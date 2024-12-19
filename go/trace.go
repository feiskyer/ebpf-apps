package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

var errNotFound = errors.New("not found")

func trace(spec *ebpf.CollectionSpec, prog *ebpf.Program, tracingName string, opts ebpf.CollectionOptions) (link.Link, error) {
	entryFn, progName, tag, err := getBpfProgInfo(prog)
	if err != nil {
		if errors.Is(err, errNotFound) {
			log.Printf("Skip tracing bpf prog %s because cannot find its entry function name", prog)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get entry function name: %w", err)
	}

	tSpec := spec.Copy()
	tSpec.Programs[tracingName].AttachTarget = prog
	tSpec.Programs[tracingName].AttachTo = entryFn
	coll, err := ebpf.NewCollectionWithOptions(tSpec, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	tracing, err := link.AttachTracing(link.TracingOptions{
		Program: coll.Programs[tracingName],
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach tracing: %w", err)
	}

	log.Printf("Tracing %s XDP prog %s (entry: %s, tag: %s)", tracingName, progName, entryFn, tag)
	return tracing, nil
}

func listBpfProgs(typ ebpf.ProgramType) ([]*ebpf.Program, error) {
	var (
		id  ebpf.ProgramID
		err error
	)

	var progs []*ebpf.Program
	for id, err = ebpf.ProgramGetNextID(id); err == nil; id, err = ebpf.ProgramGetNextID(id) {
		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			return nil, err
		}

		if prog.Type() == typ {
			progs = append(progs, prog)
		} else {
			_ = prog.Close()
		}
	}

	if !errors.Is(err, unix.ENOENT) {
		return nil, err
	}

	return progs, nil
}

func getBpfProgInfo(prog *ebpf.Program) (entryFuncName, progName, tag string, err error) {
	info, err := prog.Info()
	if err != nil {
		err = fmt.Errorf("failed to get program info: %w", err)
		return
	}

	_, ok := info.BTFID()
	if !ok {
		// FENTRY/FEXIT program can only be attached to another program
		// annotated with BTF. So if the BTF ID is not found, it means
		// the program is not annotated with BTF.
		err = errNotFound
		return
	}

	insns, err := info.Instructions()
	if err != nil {
		err = fmt.Errorf("failed to get program instructions: %w", err)
		return
	}

	for _, insn := range insns {
		sym := insn.Symbol()
		if sym != "" {
			return sym, info.Name, info.Tag, nil
		}
	}

	err = errNotFound
	return
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp_trace xdp_trace.bpf.c
func main() {
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		log.Fatalf("Failed to load BTF spec: %s", err)
	}

	bpfSpec, err := loadXdp_trace()
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %s", err)
	}
	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction

	bpfSpecFentryXdp := bpfSpec.Copy()
	bpfSpecFentryXdp.Programs = map[string]*ebpf.ProgramSpec{
		"fentry_xdp": bpfSpecFentryXdp.Programs["fentry_xdp"],
	}

	bpfSpecFexitXdp := bpfSpec.Copy()
	bpfSpecFexitXdp.Programs = map[string]*ebpf.ProgramSpec{
		"fexit_xdp": bpfSpecFexitXdp.Programs["fexit_xdp"],
	}

	progs, err := listBpfProgs(ebpf.XDP)
	if err != nil {
		log.Fatalf("failed to list XDP progs: %v", err)
	}

	var errg errgroup.Group
	var traces []link.Link
	for _, prog := range progs {
		prog := prog
		errg.Go(func() error {
			tracing, err := trace(bpfSpecFentryXdp, prog, "fentry_xdp", opts)
			if err != nil {
				return err
			}
			traces = append(traces, tracing)

			tracing, err = trace(bpfSpecFexitXdp, prog, "fexit_xdp", opts)
			if err != nil {
				return err
			}
			traces = append(traces, tracing)

			return nil
		})
	}

	if err := errg.Wait(); err != nil {
		log.Fatalf("failed to trace XDP progs: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		tracePipe, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
		if err != nil {
			log.Fatalf("failed to open trace_pipe: %v", err)
		}
		defer tracePipe.Close()

		buf := make([]byte, 4096)
		for {
			n, err := tracePipe.Read(buf)
			if err != nil {
				log.Fatalf("failed to read from trace_pipe: %v", err)
			}
			if n > 0 {
				fmt.Print(string(buf[:n]))
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			for _, tracing := range traces {
				tracing.Close()
			}
			return

		default:
		}
	}
}
