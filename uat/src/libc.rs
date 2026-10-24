//! Wrapper around libc crates with additional types.
//!
//! Notably, include type [rtmsg].
#![allow(non_camel_case_types)]

pub use libc::*;

#[repr(C)]
pub struct rtmsg {
    pub rtm_family: c_uchar,
    pub rtm_dst_len: c_uchar,
    pub rtm_src_len: c_uchar,
    pub rtm_tos: c_uchar,
    pub rtm_table: c_uchar,

    pub rtm_protocol: c_uchar,
    pub rtm_scope: c_uchar,
    pub rtm_type: c_uchar,

    pub rtm_flags: c_uint,
}

