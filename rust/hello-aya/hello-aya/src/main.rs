/* 导入依赖库 */
use aya::maps::Array;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

/* 定义命令行参数 */
#[derive(Debug, Parser)]
struct Command {
    /// list of ports to whitelist
    #[arg(short = 'p', long = "ports", default_value = "22,443,53", value_delimiter = ',')]
    ports: Vec<u16>,

    /// interface to attach to
    #[arg(short = 'i', long = "iface", default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    /* 命令行参数解析 */
    let opts = Command::parse();
    env_logger::init();

    /* 提高 memlock rlimit */
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret: i32 = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    /* 加载eBPF程序 */
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/hello-aya"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        /* 这里说明eBPF程序不包含任何日志语句 */
        warn!("failed to initialize eBPF logger: {}", e);
    }

    /* 根据命令行参数更新BPF映射中的端口号 */
    let mut port_map: Array<_, _> = Array::try_from(ebpf.map_mut("ALLOW_PORTS").unwrap())?;
    for (i, port) in opts.ports.iter().enumerate() {
        let key = i as u32;
        let val = *port as u32;
        port_map.set(key, val, 0)?;
    }

    /* 挂载TC程序（程序退出时会自动卸载） */
    let program: &mut SchedClassifier = ebpf.program_mut("hello_aya").unwrap().try_into()?;
    program.load()?;
    let _ = tc::qdisc_add_clsact(&opts.iface);
    program.attach(&opts.iface, TcAttachType::Egress)?;
    program.attach(&opts.iface, TcAttachType::Ingress)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
