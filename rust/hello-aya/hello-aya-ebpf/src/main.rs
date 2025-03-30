/* 不使用标准库和main函数 */
#![no_std]
#![no_main]

/* 导入依赖库 */
use aya_ebpf::{
    bindings::{TC_ACT_UNSPEC, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

/* 定义BPF映射，用于用户空间配置允许的端口号 */
#[map]
static ALLOW_PORTS: Array<u32> =
    Array::<u32>::with_max_entries(10, 0);


/* TC程序主处理函数 */
#[classifier]
pub fn hello_aya(ctx: TcContext) -> i32 {
    match try_hello_aya(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_UNSPEC,
    }
}

/* 网络数据头定位函数 */
#[inline(always)]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

/* TC处理函数 */
fn try_hello_aya(ctx: TcContext) -> Result<i32, ()> {
    let mut rc: i32 = TC_ACT_SHOT;
    let mut tcphdr: *const TcpHdr = core::ptr::null();
    let mut udphdr: *const UdpHdr = core::ptr::null();
    let proto: IpProto;

    /* 获取TCP/UDP头 */
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            proto = unsafe { (*ipv4hdr).proto };
            match proto {
                IpProto::Tcp => {
                    tcphdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                }
                IpProto::Udp => {
                    udphdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                }
                _ => return Ok(TC_ACT_SHOT),
            };
        }
        EtherType::Ipv6 => {
            let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            proto = unsafe { (*ipv6hdr).next_hdr };
            match proto {
                IpProto::Tcp => {
                    tcphdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                }
                IpProto::Udp => {
                    udphdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                }
                _ => return Ok(TC_ACT_SHOT),
            };
        }
        _ => return Ok(TC_ACT_SHOT),
    }

    /* 获取源端口号和目的端口号 */
    let source_port: u16;
    let dest_port: u16;
    match proto {
        IpProto::Tcp => {
            source_port = u16::from_be(unsafe { (*tcphdr).source });
            dest_port = u16::from_be(unsafe { (*tcphdr).dest });
        }
        IpProto::Udp => {
            source_port = u16::from_be(unsafe { (*udphdr).source });
            dest_port = u16::from_be(unsafe { (*udphdr).dest });
        }
        _ => return Ok(TC_ACT_UNSPEC),
    }

    /* 检查源端口或目的端口是否被允许 */
    for i in 0..10 {
        let port = ALLOW_PORTS.get(i).unwrap_or(&0);
        if *port == source_port as u32 || *port == dest_port as u32 {
            rc = TC_ACT_UNSPEC;
            break;
        }
    }

    /* 打印日志 */
    info!(&ctx, "Packet {} -> {}", source_port,  dest_port);
    Ok(rc)
}

/* 实际上用不到，但是Rust编译必须的 */
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
