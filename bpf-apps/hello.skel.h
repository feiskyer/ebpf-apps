/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __HELLO_BPF_SKEL_H__
#define __HELLO_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct hello_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *tracepoint__syscalls__sys_enter_execve;
	} progs;
	struct {
		struct bpf_link *tracepoint__syscalls__sys_enter_execve;
	} links;

#ifdef __cplusplus
	static inline struct hello_bpf *open(const struct bpf_object_open_opts
					     *opts = nullptr);
	static inline struct hello_bpf *open_and_load();
	static inline int load(struct hello_bpf *skel);
	static inline int attach(struct hello_bpf *skel);
	static inline void detach(struct hello_bpf *skel);
	static inline void destroy(struct hello_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif				/* __cplusplus */
};

static void hello_bpf__destroy(struct hello_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int hello_bpf__create_skeleton(struct hello_bpf *obj);

static inline struct hello_bpf *hello_bpf__open_opts(const struct
						     bpf_object_open_opts *opts)
{
	struct hello_bpf *obj;
	int err;

	obj = (struct hello_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = hello_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
 err_out:
	hello_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct hello_bpf *hello_bpf__open(void)
{
	return hello_bpf__open_opts(NULL);
}

static inline int hello_bpf__load(struct hello_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct hello_bpf *hello_bpf__open_and_load(void)
{
	struct hello_bpf *obj;
	int err;

	obj = hello_bpf__open();
	if (!obj)
		return NULL;
	err = hello_bpf__load(obj);
	if (err) {
		hello_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int hello_bpf__attach(struct hello_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void hello_bpf__detach(struct hello_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *hello_bpf__elf_bytes(size_t *sz);

static inline int hello_bpf__create_skeleton(struct hello_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s) {
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "hello_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "hello_bp.rodata";
	s->maps[0].map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs =
	    (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "tracepoint__syscalls__sys_enter_execve";
	s->progs[0].prog = &obj->progs.tracepoint__syscalls__sys_enter_execve;
	s->progs[0].link = &obj->links.tracepoint__syscalls__sys_enter_execve;

	s->data = hello_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
 err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *hello_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xf0\x11\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1b\0\
\x01\0\x79\x16\x10\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xb7\x02\0\0\x11\0\0\0\xbf\x03\0\0\0\0\0\0\xbf\x64\0\0\0\0\0\0\x85\0\0\0\
\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\x42\x53\x44\
\x2f\x47\x50\x4c\0\x50\x72\x6f\x63\x65\x73\x73\x5b\x25\x64\x5d\x3a\x20\x25\x73\
\x0a\0\x26\0\0\0\x05\0\x08\0\x03\0\0\0\x0c\0\0\0\x12\0\0\0\x18\0\0\0\x04\0\x10\
\x01\x51\0\x04\x08\x50\x01\x56\0\x04\x10\x40\x01\x50\0\x01\x11\x01\x25\x25\x13\
\x05\x03\x25\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\x17\x8c\x01\x17\0\0\
\x02\x34\0\x03\x25\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x03\x01\x01\x49\
\x13\0\0\x04\x21\0\x49\x13\x37\x0b\0\0\x05\x24\0\x03\x25\x3e\x0b\x0b\x0b\0\0\
\x06\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x07\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\
\x05\0\0\x08\x26\0\x49\x13\0\0\x09\x0f\0\x49\x13\0\0\x0a\x15\0\x49\x13\x27\x19\
\0\0\x0b\x16\0\x49\x13\x03\x25\x3a\x0b\x3b\x0b\0\0\x0c\x2e\x01\x11\x1b\x12\x06\
\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x27\x19\x49\x13\x3f\x19\0\0\x0d\x34\0\
\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x02\x18\0\0\x0e\x05\0\x02\x22\x03\x25\x3a\x0b\
\x3b\x0b\x49\x13\0\0\x0f\x34\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x10\
\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\0\0\x11\x15\x01\x49\x13\x27\x19\0\0\x12\
\x05\0\x49\x13\0\0\x13\x18\0\0\0\x14\x13\x01\x03\x25\x0b\x0b\x3a\x0b\x3b\x06\0\
\0\x15\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x06\x38\x0b\0\0\x16\x13\x01\x03\x25\
\x0b\x0b\x3a\x0b\x3b\x05\0\0\x17\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x05\x38\x0b\
\0\0\0\x8b\x01\0\0\x05\0\x01\x08\0\0\0\0\x01\0\x0c\0\x01\x08\0\0\0\0\0\0\0\x02\
\x02\x50\0\0\0\x08\0\0\0\x0c\0\0\0\x02\x03\x32\0\0\0\0\x06\x02\xa1\0\x03\x3e\0\
\0\0\x04\x42\0\0\0\x0d\0\x05\x04\x06\x01\x06\x05\x08\x07\x07\x06\x4f\0\0\0\x02\
\x72\x01\x08\x54\0\0\0\x09\x59\0\0\0\x0a\x5e\0\0\0\x0b\x66\0\0\0\x08\x01\x12\
\x05\x07\x07\x08\x0c\x02\x50\0\0\0\x01\x5a\x0f\0\x09\xf9\0\0\0\x0d\x09\xa0\0\0\
\0\0\x0f\x02\xa1\x01\x0e\0\x11\0\x0a\xfd\0\0\0\x0f\x01\x1e\0\x0c\xd8\0\0\0\x0f\
\x02\x18\0\x0d\x7e\x01\0\0\0\x03\xac\0\0\0\x04\x42\0\0\0\x11\0\x08\x3e\0\0\0\
\x10\x0a\xb9\0\0\0\x02\xb1\x08\xbe\0\0\0\x09\xc3\0\0\0\x11\xd4\0\0\0\x12\xd8\0\
\0\0\x12\xdd\0\0\0\x13\0\x05\x0b\x05\x08\x09\xac\0\0\0\x0b\xe5\0\0\0\x0d\x01\
\x0e\x05\x0c\x07\x04\x03\xf5\0\0\0\x04\x42\0\0\0\x06\0\x05\x0e\x07\x08\x05\x10\
\x05\x04\x09\x02\x01\0\0\x14\x1d\x40\x01\x4d\xb3\x01\0\x15\x12\x3b\x01\0\0\x01\
\x4e\xb3\x01\0\0\x15\x1a\xd4\0\0\0\x01\x4f\xb3\x01\0\x08\x15\x1b\xe9\0\0\0\x01\
\x50\xb3\x01\0\x10\x15\x1c\x72\x01\0\0\x01\x51\xb3\x01\0\x40\0\x16\x19\x08\x01\
\x08\x17\x17\x13\x6a\x01\0\0\x01\x09\x17\0\x17\x15\x6e\x01\0\0\x01\x0a\x17\x02\
\x17\x17\x6e\x01\0\0\x01\x0b\x17\x03\x17\x18\xf9\0\0\0\x01\x0c\x17\x04\0\x05\
\x14\x07\x02\x05\x16\x08\x01\x03\x3e\0\0\0\x04\x42\0\0\0\0\0\x0b\x86\x01\0\0\
\x20\x01\x32\x0b\xf9\0\0\0\x1f\x01\x24\0\x88\0\0\0\x05\0\0\0\0\0\0\0\x27\0\0\0\
\x33\0\0\0\x4a\0\0\0\x52\0\0\0\x57\0\0\0\x6b\0\0\0\x84\0\0\0\x97\0\0\0\x9d\0\0\
\0\xa5\0\0\0\xb6\0\0\0\xbb\0\0\0\xc8\0\0\0\xce\0\0\0\xdc\0\0\0\x03\x01\0\0\x07\
\x01\0\0\x0b\x01\0\0\x0f\x01\0\0\x14\x01\0\0\x23\x01\0\0\x29\x01\0\0\x37\x01\0\
\0\x45\x01\0\0\x49\x01\0\0\x55\x01\0\0\x58\x01\0\0\x5d\x01\0\0\x64\x01\0\0\x7e\
\x01\0\0\x87\x01\0\0\x96\x01\0\0\x55\x62\x75\x6e\x74\x75\x20\x63\x6c\x61\x6e\
\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\x34\x2e\x30\x2e\x30\x2d\x31\x75\
\x62\x75\x6e\x74\x75\x31\x2e\x31\0\x68\x65\x6c\x6c\x6f\x2e\x62\x70\x66\x2e\x63\
\0\x2f\x67\x6f\x2f\x65\x62\x70\x66\x2d\x61\x70\x70\x73\x2f\x62\x70\x66\x2d\x61\
\x70\x70\x73\0\x4c\x49\x43\x45\x4e\x53\x45\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\
\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x62\x70\x66\x5f\
\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\
\x64\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\
\0\x5f\x5f\x75\x36\x34\0\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x62\x70\x66\x5f\x74\x72\
\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\x6b\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\
\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\
\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\
\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\
\x72\x5f\x65\x78\x65\x63\x76\x65\0\x69\x6e\x74\0\x63\x74\x78\0\x65\x6e\x74\0\
\x74\x79\x70\x65\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\
\x66\x6c\x61\x67\x73\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\0\
\x70\x72\x65\x65\x6d\x70\x74\x5f\x63\x6f\x75\x6e\x74\0\x70\x69\x64\0\x74\x72\
\x61\x63\x65\x5f\x65\x6e\x74\x72\x79\0\x69\x64\0\x61\x72\x67\x73\0\x5f\x5f\x64\
\x61\x74\x61\0\x74\x72\x61\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\
\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\0\x66\x69\x6c\x65\x6e\x61\x6d\x65\0\x5f\
\x5f\x6b\x65\x72\x6e\x65\x6c\x5f\x70\x69\x64\x5f\x74\0\x70\x69\x64\x5f\x74\0\
\x1c\0\0\0\x05\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\
\xeb\x01\0\x18\0\0\0\0\0\0\0\xd0\x01\0\0\xd0\x01\0\0\xf7\x01\0\0\0\0\0\0\0\0\0\
\x02\x02\0\0\0\x01\0\0\0\x04\0\0\x04\x40\0\0\0\x1b\0\0\0\x03\0\0\0\0\0\0\0\x1f\
\0\0\0\x07\0\0\0\x40\0\0\0\x22\0\0\0\x09\0\0\0\x80\0\0\0\x27\0\0\0\x0c\0\0\0\0\
\x02\0\0\x2e\0\0\0\x04\0\0\x04\x08\0\0\0\x3a\0\0\0\x04\0\0\0\0\0\0\0\x3f\0\0\0\
\x05\0\0\0\x10\0\0\0\x45\0\0\0\x05\0\0\0\x18\0\0\0\x53\0\0\0\x06\0\0\0\x20\0\0\
\0\x57\0\0\0\0\0\0\x01\x02\0\0\0\x10\0\0\0\x66\0\0\0\0\0\0\x01\x01\0\0\0\x08\0\
\0\0\x74\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\x78\0\0\0\0\0\0\x01\x08\0\0\0\
\x40\0\0\x01\x7d\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\
\x08\0\0\0\x0a\0\0\0\x06\0\0\0\x8b\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\x9f\0\0\
\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x0b\0\0\0\x0a\0\0\
\0\0\0\0\0\0\0\0\0\x01\0\0\x0d\x06\0\0\0\xa4\0\0\0\x01\0\0\0\xa8\0\0\0\x01\0\0\
\x0c\x0d\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x0b\0\0\0\x0a\0\0\0\x0d\0\0\0\xb0\x01\
\0\0\0\0\0\x0e\x0f\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x0a\x0b\0\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\0\x11\0\0\0\x0a\0\0\0\x11\0\0\0\xb8\x01\0\0\0\0\0\x0e\x12\0\0\0\0\0\
\0\0\xe7\x01\0\0\x01\0\0\x0f\0\0\0\0\x13\0\0\0\0\0\0\0\x11\0\0\0\xef\x01\0\0\
\x01\0\0\x0f\0\0\0\0\x10\0\0\0\0\0\0\0\x0d\0\0\0\0\x74\x72\x61\x63\x65\x5f\x65\
\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\0\x65\
\x6e\x74\0\x69\x64\0\x61\x72\x67\x73\0\x5f\x5f\x64\x61\x74\x61\0\x74\x72\x61\
\x63\x65\x5f\x65\x6e\x74\x72\x79\0\x74\x79\x70\x65\0\x66\x6c\x61\x67\x73\0\x70\
\x72\x65\x65\x6d\x70\x74\x5f\x63\x6f\x75\x6e\x74\0\x70\x69\x64\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x75\x6e\x73\x69\x67\x6e\x65\x64\
\x20\x63\x68\x61\x72\0\x69\x6e\x74\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\
\x65\x64\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\
\x5f\x54\x59\x50\x45\x5f\x5f\0\x63\x68\x61\x72\0\x63\x74\x78\0\x74\x72\x61\x63\
\x65\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\
\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\x63\x76\x65\0\x74\x70\x2f\x73\
\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\
\x78\x65\x63\x76\x65\0\x30\x3a\x32\x3a\x30\0\x2f\x67\x6f\x2f\x65\x62\x70\x66\
\x2d\x61\x70\x70\x73\x2f\x62\x70\x66\x2d\x61\x70\x70\x73\x2f\x68\x65\x6c\x6c\
\x6f\x2e\x62\x70\x66\x2e\x63\0\x09\x63\x6f\x6e\x73\x74\x20\x63\x68\x61\x72\x20\
\x2a\x66\x69\x6c\x65\x6e\x61\x6d\x65\x20\x3d\x20\x28\x63\x6f\x6e\x73\x74\x20\
\x63\x68\x61\x72\x20\x2a\x29\x28\x63\x74\x78\x2d\x3e\x61\x72\x67\x73\x5b\x30\
\x5d\x29\x3b\0\x09\x70\x69\x64\x5f\x74\x20\x70\x69\x64\x20\x3d\x20\x62\x70\x66\
\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\
\x69\x64\x28\x29\x3b\0\x09\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x50\
\x72\x6f\x63\x65\x73\x73\x5b\x25\x64\x5d\x3a\x20\x25\x73\x5c\x6e\x22\x2c\x20\
\x70\x69\x64\x2c\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\x29\x3b\0\x09\x72\x65\x74\
\x75\x72\x6e\x20\x30\x3b\0\x4c\x49\x43\x45\x4e\x53\x45\0\x74\x72\x61\x63\x65\
\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\
\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\x63\x76\x65\x2e\x5f\x5f\x5f\x5f\
\x66\x6d\x74\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\0\
\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x4c\0\0\0\x60\0\0\0\x1c\0\
\0\0\x08\0\0\0\xcf\0\0\0\x01\0\0\0\0\0\0\0\x0e\0\0\0\x10\0\0\0\xcf\0\0\0\x04\0\
\0\0\0\0\0\0\xf2\0\0\0\x15\x01\0\0\x28\x30\0\0\x08\0\0\0\xf2\0\0\0\x4b\x01\0\0\
\x0e\x34\0\0\x10\0\0\0\xf2\0\0\0\x74\x01\0\0\x02\x3c\0\0\x40\0\0\0\xf2\0\0\0\
\xa5\x01\0\0\x02\x40\0\0\x10\0\0\0\xcf\0\0\0\x01\0\0\0\0\0\0\0\x02\0\0\0\xec\0\
\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x91\0\0\0\x05\0\x08\0\x69\0\0\0\x08\x01\
\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\0\x01\x01\x01\x1f\x03\0\0\0\0\
\x17\0\0\0\x19\0\0\0\x03\x01\x1f\x02\x0f\x05\x1e\x03\x30\0\0\0\0\x55\x2f\x2b\
\x7f\x54\xcd\x0e\x67\x1a\xe0\xdb\x10\x27\xbe\x3b\x3b\x3c\0\0\0\x01\xe2\xf1\x38\
\x92\x39\x2c\x96\x17\xaa\x42\x64\xed\x33\xe7\xb5\x02\x46\0\0\0\x02\x65\xe4\xdc\
\x8e\x31\x21\xf9\x1a\x5c\x2c\x9e\xb8\x56\x3c\x56\x92\x04\0\0\x09\x02\0\0\0\0\0\
\0\0\0\x03\x0a\x01\x05\x28\x0a\x13\x05\x0e\x21\x05\x02\x22\x67\x02\x02\0\x01\
\x01\x2f\x67\x6f\x2f\x65\x62\x70\x66\x2d\x61\x70\x70\x73\x2f\x62\x70\x66\x2d\
\x61\x70\x70\x73\0\x2e\0\x6c\x69\x62\x62\x70\x66\x2f\x75\x73\x72\x2f\x69\x6e\
\x63\x6c\x75\x64\x65\x2f\x62\x70\x66\0\x68\x65\x6c\x6c\x6f\x2e\x62\x70\x66\x2e\
\x63\0\x76\x6d\x6c\x69\x6e\x75\x78\x2e\x68\0\x62\x70\x66\x5f\x68\x65\x6c\x70\
\x65\x72\x5f\x64\x65\x66\x73\x2e\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x32\x01\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\x01\0\x06\0\0\0\0\0\0\
\0\0\0\x11\0\0\0\0\0\0\0\0\0\0\0\x03\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x03\0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x03\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x03\0\x16\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x18\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xc1\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x50\0\0\0\0\0\0\
\0\x5f\x01\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\
\x01\0\0\0\x04\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x11\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x1f\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x23\0\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x0c\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x10\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x18\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x1c\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x20\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x24\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x28\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x30\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x34\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x38\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x3c\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x40\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x44\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x48\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x4c\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x50\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x54\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x58\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x5c\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x60\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x64\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x68\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x6c\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x70\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x74\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x78\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x7c\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x80\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x84\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x88\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x0e\0\0\0\x10\0\0\0\0\0\0\0\
\x02\0\0\0\x04\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\xc8\x01\0\0\0\0\0\0\
\x03\0\0\0\x04\0\0\0\xe0\x01\0\0\0\0\0\0\x04\0\0\0\x0e\0\0\0\x2c\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x8c\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\
\x03\0\0\0\x0a\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\
\x03\0\0\0\x0c\0\0\0\x26\0\0\0\0\0\0\0\x03\0\0\0\x0c\0\0\0\x2a\0\0\0\0\0\0\0\
\x03\0\0\0\x0c\0\0\0\x36\0\0\0\0\0\0\0\x03\0\0\0\x0c\0\0\0\x4b\0\0\0\0\0\0\0\
\x03\0\0\0\x0c\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\x0c\0\0\0\x7a\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x0d\x0e\x03\0\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\
\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\
\x74\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\
\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\x63\x76\
\x65\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x6f\x63\
\x6c\x69\x73\x74\x73\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\
\x5f\x6f\x66\x66\x73\x65\x74\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\0\
\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\x73\x74\x72\0\x2e\x72\x65\x6c\
\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\
\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\
\x67\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\
\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\x63\x76\
\x65\0\x2e\x72\x65\x6c\x74\x70\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\
\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\x63\x76\x65\0\x6c\x69\x63\x65\x6e\
\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\
\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x68\x65\x6c\x6c\
\x6f\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\
\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\
\x4c\x49\x43\x45\x4e\x53\x45\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x3e\x01\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x83\x10\0\
\0\0\0\0\0\x67\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xec\0\0\0\x01\0\
\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\0\0\0\x09\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xd0\x0c\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x1a\0\0\0\x03\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x09\x01\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x4e\x01\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x9d\0\0\0\0\0\0\0\x11\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x51\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xae\0\0\0\0\0\0\
\0\x2a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd8\0\0\0\0\0\0\0\x23\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa7\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfb\x01\0\0\0\0\0\0\x8f\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa3\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\xe0\x0c\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x1a\0\0\0\x09\0\0\0\x08\
\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x65\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x8a\x03\0\0\0\0\0\0\x8c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x61\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x0d\
\0\0\0\0\0\0\x10\x02\0\0\0\0\0\0\x1a\0\0\0\x0b\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\
\0\0\0\0\0\x78\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x16\x04\0\0\0\
\0\0\0\x9c\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\x97\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb2\x05\0\0\0\0\0\0\x20\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x93\0\0\0\x09\0\
\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x0f\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\
\x1a\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x5a\x01\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd4\x05\0\0\0\0\0\0\xdf\x03\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x56\x01\0\0\x09\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x70\x0f\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x1a\0\0\0\x10\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xb4\x09\0\0\0\0\0\0\x9c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x90\x0f\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x1a\0\0\0\x12\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x25\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\
\x0a\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x21\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\x0f\0\0\0\0\
\0\0\x20\0\0\0\0\0\0\0\x1a\0\0\0\x14\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\
\x15\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\x0a\0\0\0\0\0\0\x95\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x11\x01\0\0\
\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\x10\0\0\0\0\0\0\x70\0\0\0\0\0\
\0\0\x1a\0\0\0\x16\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x83\0\0\0\x01\0\0\
\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0d\x0b\0\0\0\0\0\0\x58\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xb3\0\0\0\x03\x4c\xff\x6f\0\0\
\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x80\x10\0\0\0\0\0\0\x03\0\0\0\0\0\0\0\x1a\0\0\0\
\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x46\x01\0\0\x02\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x68\x0b\0\0\0\0\0\0\x68\x01\0\0\0\0\0\0\x01\0\0\0\x0d\0\0\0\
\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct hello_bpf *hello_bpf::open(const struct bpf_object_open_opts *opts)
{
	return hello_bpf__open_opts(opts);
}

struct hello_bpf *hello_bpf::open_and_load()
{
	return hello_bpf__open_and_load();
}

int hello_bpf::load(struct hello_bpf *skel)
{
	return hello_bpf__load(skel);
}

int hello_bpf::attach(struct hello_bpf *skel)
{
	return hello_bpf__attach(skel);
}

void hello_bpf::detach(struct hello_bpf *skel)
{
	hello_bpf__detach(skel);
}

void hello_bpf::destroy(struct hello_bpf *skel)
{
	hello_bpf__destroy(skel);
}

const void *hello_bpf::elf_bytes(size_t *sz)
{
	return hello_bpf__elf_bytes(sz);
}
#endif				/* __cplusplus */

__attribute__((unused))
static void hello_bpf__assert(struct hello_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif				/* __HELLO_BPF_SKEL_H__ */
