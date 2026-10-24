#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::{EbpfContext, Global, bindings::{BPF_F_NO_PREALLOC, BPF_NOEXIST}, helpers::generated::bpf_get_prandom_u32, macros::{cgroup_sock_addr, map}, maps::HashMap, programs::SockAddrContext};
use aya_log_ebpf::error;
use uat_common::{Ipv4Net, Net};

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"MIT\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

const MAX_ENTRIES: u32 = 1024;
const MAX_RETRIES: u32 = 1024;

#[unsafe(no_mangle)] static NET: Global<Net> = Global::new(Net(Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 1), 8)));

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
struct Uid(u32);

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
struct Port(u16);

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct MapKey {
    addr: Ipv4Addr,
    uid: Uid,
    port: Port,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct MapValue {
    mapped_port: Port,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct RMapKey {
    addr: Ipv4Addr,
    mapped_port: Port,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct RMapValue {
    port: Port,
}


#[map] static MAP: HashMap<MapKey, MapValue> = HashMap::with_max_entries(MAX_ENTRIES, BPF_F_NO_PREALLOC);
#[map] static RMAP: HashMap<RMapKey, RMapValue> = HashMap::with_max_entries(MAX_ENTRIES, BPF_F_NO_PREALLOC);

fn map(uid: Uid, addr: Ipv4Addr, port: Port) -> Result<Option<Port>, &'static str> {
    let net = NET.load();
    if net.addr() == addr || !net.contains(&addr) {
        return Ok(None)
    }

    if let Some(&MapValue { mapped_port }) = unsafe { MAP.get(MapKey { addr, uid, port }) } {
        return Ok(Some(mapped_port))
    }

    for _ in 0..MAX_RETRIES {
        let random = unsafe { bpf_get_prandom_u32() };
        let mapped_port1 = Port(((random >> 0)  & 0xFFFF) as u16);
        let mapped_port2 = Port(((random >> 16) & 0xFFFF) as u16);
        for mapped_port in [mapped_port1, mapped_port2] {
            if RMAP.get_ptr(RMapKey { addr, mapped_port }).is_none() {
                let Ok(()) = RMAP.insert(RMapKey { addr, mapped_port }, RMapValue { port }, BPF_NOEXIST as u64) else {
                    // This happens if we are extremely unlucky and the same mapped_port is
                    // concurrently allocated at random. Retry.
                    continue
                };

                let Ok(()) = MAP.insert(MapKey { addr, uid, port }, MapValue { mapped_port }, BPF_NOEXIST as u64) else {
                    // This happens if we try to allocate mapped_port for the same uid and port pair
                    // and have already succeeded concurrently. Cleanup and bail out.
                    let Ok(()) = RMAP.remove(RMapKey { addr, mapped_port }) else { return Err("BUG: inserted key missing 1") };
                    let Some(&MapValue { mapped_port }) = (unsafe { MAP.get(MapKey { addr, uid, port }) }) else { return Err("BUG: inserted key missing 2") };
                    return Ok(Some(mapped_port));
                };
            }
        }
    }

    Err("attempt exhausted")
}

fn rmap(addr: Ipv4Addr, mapped_port: Port) -> Result<Option<Port>, &'static str> {
    let net = NET.load();
    if net.addr() == addr || !net.contains(&addr) {
        return Ok(None)
    }

    let Some(&RMapValue { port }) = (unsafe { RMAP.get(RMapKey { addr, mapped_port }) }) else { return Err("BUG: failed reverse mapping") };
    Ok(Some(port))
}

fn ctx_map(ctx: &SockAddrContext) -> i32 {
    let uid = Uid(ctx.uid());
    let addr = unsafe { Ipv4Addr::from_octets(u32::to_ne_bytes((*ctx.sock_addr).user_ip4)) };
    let port = unsafe { Port((*ctx.sock_addr).user_port as u16) };
    match map(uid, addr, port) {
        Ok(mapped_port) => {
            if let Some(mapped_port) = mapped_port { unsafe { (*ctx.sock_addr).user_port = mapped_port.0 as u32 } }
            return 1
        },
        Err(err) => {
            error!(&ctx, "{}", err);
            return 0
        },
    };

}

fn ctx_rmap(ctx: &SockAddrContext) -> i32 {
    let addr = unsafe { Ipv4Addr::from_octets(u32::to_ne_bytes((*ctx.sock_addr).user_ip4)) };
    let mapped_port = unsafe { Port((*ctx.sock_addr).user_port as u16) };
    match rmap(addr, mapped_port) {
        Ok(port) => {
            if let Some(port) = port { unsafe { (*ctx.sock_addr).user_port = port.0 as u32 } }
            return 1
        },
        Err(err) => {
            error!(&ctx, "{}", err);
            return 0
        },
    };
}

/// Bail out.
///
/// Not all bpf program accept error as exit code, so we simply set an "invalid" address and pretend
/// to be successful.
fn ctx_bail(ctx: &SockAddrContext, res: i32) -> i32 {
    if res != 1 {
        let net = NET.load();
        let addr = u32::from_ne_bytes(net.addr().octets());
        unsafe { (*ctx.sock_addr).user_ip4 = addr }
    }
    return 1
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    ctx_map(&ctx)
}

#[cgroup_sock_addr(bind4)]
pub fn bind4(ctx: SockAddrContext) -> i32 {
    ctx_map(&ctx) * 3
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    ctx_map(&ctx)
}

#[cgroup_sock_addr(recvmsg4)]
pub fn recvmsg4(ctx: SockAddrContext) -> i32 {
    ctx_bail(&ctx, ctx_map(&ctx))
}
#[cgroup_sock_addr(getpeername4)]
pub fn getpeername4(ctx: SockAddrContext) -> i32 {
    ctx_bail(&ctx, ctx_rmap(&ctx))
}

#[cgroup_sock_addr(getsockname4)]
pub fn getsockname4(ctx: SockAddrContext) -> i32 {
    ctx_bail(&ctx, ctx_rmap(&ctx))
}

