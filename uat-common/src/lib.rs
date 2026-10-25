#![no_std]

pub use core::net::Ipv4Addr;
pub use ipnet::Ipv4Net;

macro_rules! wrapper {
    ($outer:ident, $inner:ty) => {
        #[derive(Clone, Copy, Debug)]
        #[repr(transparent)]
        pub struct $outer(pub $inner);

        impl core::ops::Deref for $outer {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl core::ops::DerefMut for $outer {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        #[cfg(feature="user")]
        unsafe impl aya::Pod for $outer {}
    };
}

wrapper!(Net, Ipv4Net);
wrapper!(Addr, Ipv4Addr);
wrapper!(Uid, u32);
wrapper!(Port, u16);
