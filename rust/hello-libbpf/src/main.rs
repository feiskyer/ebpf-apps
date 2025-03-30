#![allow(clippy::let_unit_value)]

/* 导入依赖库 */
use std::mem::MaybeUninit;
use std::os::unix::io::AsFd as _;

use anyhow::Context as _;
use anyhow::Result;

use clap::Parser;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore as _;
use libbpf_rs::MapFlags;
use libbpf_rs::TcHookBuilder;
use libbpf_rs::TC_EGRESS;
use libbpf_rs::TC_INGRESS;

use nix::net::if_::if_nametoindex;

/* 导入脚手架框架 */
mod tc {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/tc.skel.rs"));
}
use tc::*;

/* 定义命令行参数 */
#[derive(Debug, Parser)]
struct Command {
    /// list of ports to whitelist
    #[arg(short, long)]
    ports: Vec<u16>,

    /// attach a hook
    #[arg(short, long)]
    attach: bool,

    /// detach existing hook
    #[arg(short, long)]
    detach: bool,

    /// interface to attach to
    #[arg(short = 'i', long = "interface")]
    iface: String,
}

fn main() -> Result<()> {
    let opts = Command::parse();

    /* 变量定义 */
    let builder = TcSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object)?;
    let skel = open.load()?;
    let ifidx = if_nametoindex(opts.iface.as_str())? as i32;

    /* TC钩子定义 */
    let mut tc_builder = TcHookBuilder::new(skel.progs.handle_tc.as_fd());
    tc_builder
        .ifindex(ifidx)
        .replace(true)
        .handle(1)
        .priority(1);

    let mut egress = tc_builder.hook(TC_EGRESS);
    let mut ingress = tc_builder.hook(TC_INGRESS);

    /* 卸载TC程序 */
    if opts.detach {
        if let Err(e) = ingress.detach() {
            println!("failed to detach ingress hook {e}");
        }
        if let Err(e) = egress.detach() {
            println!("failed to detach egress hook {e}");
        }
    }

    /* 挂载TC程序 */
    if opts.attach {
        /* 更新BPF映射中的端口号 */
        for (i, port) in opts.ports.iter().enumerate() {
            let key = (i as u32).to_ne_bytes();
            let val = port.to_ne_bytes();
            let () = skel
                .maps
                .allow_ports
                .update(&key, &val, MapFlags::ANY)
                .context("Example limited to 10 ports")?;
        }

        if let Err(e) = ingress.attach() {
            println!("failed to attach ingress hook {e}");
        }

        if let Err(e) = egress.attach() {
            println!("failed to attach egress hook {e}");
        }
    }

    Ok(())
}