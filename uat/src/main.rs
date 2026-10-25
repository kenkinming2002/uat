#![feature(dirfd)]

mod tun;
mod libc;

use std::fs::Dir;

use anyhow::Result;
use argh::FromArgs;
use aya::programs::{CgroupAttachMode, Program};
use aya_log::EbpfLogger;
use ipnet::Ipv4Net;
use tokio::io::{Interest, unix::AsyncFd};
use uat_common::{Net, Port};

use crate::tun::Tun;

/// UAT
#[derive(FromArgs, PartialEq, Debug)]
struct Args {
    /// ipv4 network to use (default: 192.168.33.0/24)
    #[argh(option, default="\"192.168.33.0/24\".parse().unwrap()")]
    net: Ipv4Net,

    /// minimum reserved port (default: 61000)
    #[argh(option, default="61000")]
    min_port: u16,

    /// maximum reserved port (default: 65535)
    #[argh(option, default="65535")]
    max_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = argh::from_env::<Args>();

    let mut ebpf = aya::EbpfLoader::new()
        .override_global("NET", &Net(args.net), true)
        .override_global("MIN_PORT", &Port(args.min_port.to_be()), true)
        .override_global("MAX_PORT", &Port(args.max_port.to_be()), true)
        .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/uat")))?;

    let cgroup = Dir::open("/sys/fs/cgroup")?;
    let mut cgroup_sock_links = Vec::new();
    let mut cgroup_sock_addr_links = Vec::new();
    for (_, program) in ebpf.programs_mut() {
        match program {
            Program::CgroupSock(program) => {
                program.load()?;
                cgroup_sock_links.push(program.attach(&cgroup, CgroupAttachMode::Single)?);
            },
            Program::CgroupSockAddr(program) => {
                program.load()?;
                cgroup_sock_addr_links.push(program.attach(&cgroup, CgroupAttachMode::Single)?);
            },
            _ => unreachable!(),
        }
    }

    let mut _tun = Tun::new(args.net, "uat%d")?;

    let logger = EbpfLogger::init_with_logger(&mut ebpf, env_logger::builder().build()).unwrap();
    let mut logger = AsyncFd::with_interest(logger, Interest::READABLE).unwrap();
    loop {
        let mut guard = logger.readable_mut().await.unwrap();
        guard.get_inner_mut().flush();
        guard.clear_ready();
    }
}
