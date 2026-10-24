#![no_std]

pub use core::net::Ipv4Addr;
pub use ipnet::Ipv4Net;

#[derive(Clone, Copy, Debug)]
pub struct Net(pub Ipv4Net);

impl core::ops::Deref for Net {
    type Target = Ipv4Net;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Addr(pub Ipv4Addr);

impl core::ops::Deref for Addr {
    type Target = Ipv4Addr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature="user")]
mod pod {
    use super::*;
    unsafe impl aya::Pod for Addr {}
    unsafe impl aya::Pod for Net {}
}
