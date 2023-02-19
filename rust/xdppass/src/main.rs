use std::fs::File;
use std::io::{prelude::*, BufReader};
use anyhow::{bail, Result};
use clap::Parser;

mod bpf;
use bpf::*;

const TRACING_PIPE: &str = "/sys/kernel/debug/tracing/trace_pipe";

#[derive(Debug, Parser)]
struct Command {
    /// interface to attach to
    #[clap(short = 'i', long = "interface", default_value = "eth0")]
    iface: String,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}
fn main() -> Result<()> {
    let opts = Command::parse();

    bump_memlock_rlimit()?;

    let builder = XdppassSkelBuilder::default();
    let open = builder.open()?;
    let mut skel = open.load()?;
    let ifidx = nix::net::if_::if_nametoindex(opts.iface.as_str())? as i32;
    let link = skel.progs_mut().xdp_prog_simple().attach_xdp(ifidx)?;
    skel.links = XdppassLinks {
        xdp_prog_simple: Some(link),
    };

    let file = File::open(TRACING_PIPE).unwrap();
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        match reader.read_line(&mut line) {
          Ok(read) => {
            if read == 0 {
              break;
            }
            println!("{}", line);
          }
          Err(err) => {
            println!("error reading {}: {}", TRACING_PIPE, err);
          }
        };
    }

    // ctrl-c to exit
    // XDP program will be automatically removed when the link goes out of scope.

    Ok(())
}
