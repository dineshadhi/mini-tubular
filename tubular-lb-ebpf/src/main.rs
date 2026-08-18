#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_SOCKMAP},
    helpers::{bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_release},
    macros::{map, sk_lookup},
    maps::Array,
    programs::SkLookupContext,
    EbpfContext,
};
use core::ffi::c_void;
use aya_log_ebpf::info;

const MAX_SOCKETS: u32 = 64;
const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

/// Four-byte values let userspace register sockets with Aya's SockMap API.
#[no_mangle]
#[link_section = "maps"]
static mut SOCK_POOL: bpf_map_def = bpf_map_def {
    type_: BPF_MAP_TYPE_SOCKMAP,
    key_size: 4,  // sizeof(u32)
    value_size: 4, // sizeof(u32) — kernel requires 4 for SOCKMAP
    max_entries: MAX_SOCKETS,
    map_flags: 0,
    id: 0,
    pinning: 0,
};

/// STATE[0] = pool size, STATE[1] = round-robin counter.
#[map]
static STATE: Array<u64> = Array::with_max_entries(2, 0);

#[sk_lookup]
pub fn tubular_lb(ctx: SkLookupContext) -> u32 {
    match try_lb(&ctx) {
        Ok(v) => v,
        Err(_) => SK_DROP,
    }
}

#[inline(always)]
fn try_lb(ctx: &SkLookupContext) -> Result<u32, i64> {
    let local_port = unsafe { (*ctx.lookup).local_port };
    if local_port != 443 {
        return Ok(SK_PASS);
    }
    info!(ctx, "intercepting port 443");

    let size = *STATE.get(0).ok_or(0i64)?;
    if size == 0 {
        info!(ctx, "pool empty");
        return Ok(SK_DROP);
    }

    let counter_ptr = STATE.get_ptr_mut(1).ok_or(0i64)?;
    let idx = unsafe {
        let c = *counter_ptr;
        *counter_ptr = c.wrapping_add(1);
        (c % size) as u32
    };

    info!(ctx, "trying slot {}", idx);

    let ret = unsafe {
        let sk = bpf_map_lookup_elem(
            &mut SOCK_POOL as *mut _ as *mut c_void,
            &idx as *const _ as *const c_void,
        );
        if sk.is_null() {
            info!(ctx, "slot {} null", idx);
            return Ok(SK_DROP);
        }
        let r = bpf_sk_assign(ctx.as_ptr() as *mut c_void, sk, 0);
        bpf_sk_release(sk);
        r
    };

    if ret == 0 {
        info!(ctx, "assigned ok slot {}", idx);
        Ok(SK_PASS)
    } else {
        info!(ctx, "assign failed slot {} err {}", idx, ret);
        Ok(SK_DROP)
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
