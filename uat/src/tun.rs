use std::{fs::File, io, mem::{self, MaybeUninit}, net::Ipv4Addr, os::fd::{AsRawFd as _, FromRawFd as _}, ptr};

use ipnet::Ipv4Net;
use anyhow::Result;

use crate::libc;

pub struct Tun(File);

impl std::ops::Deref for Tun {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Tun {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn sockaddr_from_ipv4_addr(addr: Ipv4Addr) -> libc::sockaddr {
    let mut sockaddr = unsafe { MaybeUninit::<libc::sockaddr_in>::zeroed().assume_init() };
    sockaddr.sin_family = libc::AF_INET as _;
    sockaddr.sin_port = 0;
    sockaddr.sin_addr.s_addr = unsafe{ mem::transmute(addr) };
    unsafe { mem::transmute(sockaddr) }
}

impl Tun {
    pub fn new(net: Ipv4Net, name: &str) -> Result<Self> {
        let file = File::open("/dev/net/tun")?;
        let mut ifreq = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };

        assert!(name.len() < ifreq.ifr_name.len());
        unsafe { ptr::copy_nonoverlapping(name.as_ptr() as *const i8, ifreq.ifr_name.as_mut_ptr(), name.len()) };
        ifreq.ifr_ifru.ifru_flags = libc::IFF_TUN as _;

        let res = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &ifreq) };
        if res != 0 { Err(io::Error::last_os_error())? }

        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 { Err(io::Error::last_os_error())? }
        let sock = unsafe { File::from_raw_fd(sock) };

        ifreq.ifr_ifru.ifru_addr = sockaddr_from_ipv4_addr(net.addr());
        let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFADDR, &ifreq) };
        if res != 0 { Err(io::Error::last_os_error())? }

        ifreq.ifr_ifru.ifru_addr = sockaddr_from_ipv4_addr(net.netmask());
        let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFNETMASK, &ifreq) };
        if res != 0 { Err(io::Error::last_os_error())? }

        let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &ifreq) };
        if res != 0 { Err(io::Error::last_os_error())? }
        unsafe { ifreq.ifr_ifru.ifru_flags |= libc::IFF_UP as i16 };
        let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &ifreq) };
        if res != 0 { Err(io::Error::last_os_error())? }

        let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFINDEX, &ifreq) };
        if res != 0 { Err(io::Error::last_os_error())? }
        let ifindex = unsafe { ifreq.ifr_ifru.ifru_ifindex };

        // See https://elixir.bootlin.com/linux/v7.3/source/net/ipv4/fib_frontend.c#L1152 for
        // implementation of function fib_add_ifaddr() which is called when a network interface is
        // brought up. In particular, there is two routes which is added:
        //  - local route for the device network local address
        //  - local/unicast route the device address
        // Note that the second route is set to be local only if the IFF_LOOPBACK flag is set on the
        // device, which is what we want. This is because
        //  - we can only bind to and accept packets from address specified in a local route
        //  - traffic through address specified in a local route a routed locally and ingress/egress
        //    queue of the device
        // Unfortuately, there is no way to set the IFF_LOOPBACK flag manually, so we need to setup
        // the routes by ourself, and deal with rtnetlink(7) interface.

        #[repr(C)]
        struct Req {
            nh: libc::nlmsghdr,
            rm: libc::rtmsg,

            dst_attr: libc::rtattr,
            dst: Ipv4Addr,

            oif_attr: libc::rtattr,
            oif: u32,

            prefsrc_attr: libc::rtattr,
            prefsrc: Ipv4Addr,
        }

        #[repr(C)]
        struct Resp {
            nh: libc::nlmsghdr,
            ec: i32,
            old_nh: libc::nlmsghdr,
        }

        let netlink = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_ROUTE) };
        if netlink < 0 { Err(io::Error::last_os_error())? }

        let mut addr = unsafe { MaybeUninit::<libc::sockaddr_nl>::zeroed().assume_init() };
        addr.nl_family = libc::AF_NETLINK as _;
        if unsafe { libc::bind(netlink, &addr as *const libc::sockaddr_nl as *const _, mem::size_of_val(&addr) as _) } < 0 { Err(io::Error::last_os_error())? }

        let mut req = unsafe { MaybeUninit::<Req>::zeroed().assume_init() };
        req.nh.nlmsg_len = 52;
        req.rm.rtm_family = libc::AF_INET as _;
        req.rm.rtm_src_len = 0;
        req.rm.rtm_protocol = libc::RTPROT_KERNEL;
        req.dst_attr.rta_type = libc::RTA_DST;
        req.dst_attr.rta_len = 8;
        req.prefsrc_attr.rta_type = libc::RTA_PREFSRC;
        req.prefsrc_attr.rta_len = 8;
        req.oif_attr.rta_type = libc::RTA_OIF;
        req.oif_attr.rta_len = 8;
        req.oif = ifindex as _;
        let mut resp = unsafe { MaybeUninit::<Resp>::zeroed().assume_init() };

        // Delete default routes
        {
            req.nh.nlmsg_type = libc::RTM_DELROUTE;
            req.nh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as _;
            req.prefsrc = net.addr();

            req.rm.rtm_dst_len = 32;
            req.rm.rtm_table = libc::RT_TABLE_LOCAL;
            req.rm.rtm_scope = libc::RT_SCOPE_HOST;
            req.rm.rtm_type = libc::RTN_LOCAL;
            req.dst = net.addr();
            if mem::size_of_val(&req) != unsafe { libc::send(netlink, &req as *const Req as *const _, mem::size_of_val(&req), 0) } as _ { Err(io::Error::last_os_error())? }
            if mem::size_of_val(&resp) != unsafe { libc::recv(netlink, &mut resp as *mut Resp as *mut _, mem::size_of_val(&resp), 0) } as _ { Err(io::Error::last_os_error())? }
            if resp.ec != 0 { Err(io::Error::from_raw_os_error(-resp.ec))? }

            req.rm.rtm_dst_len = 32;
            req.rm.rtm_table = libc::RT_TABLE_LOCAL;
            req.rm.rtm_scope = libc::RT_SCOPE_LINK;
            req.rm.rtm_type = libc::RTN_BROADCAST;
            req.dst = net.broadcast();
            if mem::size_of_val(&req) != unsafe { libc::send(netlink, &req as *const Req as *const _, mem::size_of_val(&req), 0) } as _ { Err(io::Error::last_os_error())? }
            if mem::size_of_val(&resp) != unsafe { libc::recv(netlink, &mut resp as *mut Resp as *mut _, mem::size_of_val(&resp), 0) } as _ { Err(io::Error::last_os_error())? }
            if resp.ec != 0 { Err(io::Error::from_raw_os_error(-resp.ec))? }

            req.rm.rtm_dst_len = net.prefix_len();
            req.rm.rtm_table = libc::RT_TABLE_MAIN;
            req.rm.rtm_scope = libc::RT_SCOPE_LINK;
            req.rm.rtm_type = libc::RTN_UNICAST;
            req.dst = net.network();
            if mem::size_of_val(&req) != unsafe { libc::send(netlink, &req as *const Req as *const _, mem::size_of_val(&req), 0) } as _ { Err(io::Error::last_os_error())? }
            if mem::size_of_val(&resp) != unsafe { libc::recv(netlink, &mut resp as *mut Resp as *mut _, mem::size_of_val(&resp), 0) } as _ { Err(io::Error::last_os_error())? }
            if resp.ec != 0 { Err(io::Error::from_raw_os_error(-resp.ec))? }
        }

        // Add route
        {
            req.rm.rtm_dst_len = net.prefix_len();
            req.rm.rtm_table = libc::RT_TABLE_LOCAL;
            req.rm.rtm_scope = libc::RT_SCOPE_HOST;
            req.rm.rtm_type = libc::RTN_LOCAL;
            req.nh.nlmsg_type = libc::RTM_NEWROUTE;
            req.nh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as _;
            req.dst = net.network();
            req.prefsrc = Ipv4Addr::LOCALHOST;
            if mem::size_of_val(&req) != unsafe { libc::send(netlink, &req as *const Req as *const _, mem::size_of_val(&req), 0) } as _ { Err(io::Error::last_os_error())? }
            if mem::size_of_val(&resp) != unsafe { libc::recv(netlink, &mut resp as *mut Resp as *mut _, mem::size_of_val(&resp), 0) } as _ { Err(io::Error::last_os_error())? }
            if resp.ec != 0 { Err(io::Error::from_raw_os_error(-resp.ec))? }
        }

        Ok(Self(file))
    }
}
