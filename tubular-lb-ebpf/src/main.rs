#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    helpers::{bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_release},
    macros::{map, sk_lookup},
    maps::{Array, SockMap},
    programs::SkLookupContext,
    EbpfContext,
};
use aya_ebpf_cty::c_void;
use aya_log_ebpf::info;

const MAX_SOCKETS: u32 = 64;
const BPF_SK_LOOKUP_F_REPLACE: u64 = 1 << 0;

/// Pool of listening sockets — populated by the userspace loader.
#[map]
static mut SOCK_POOL: SockMap = SockMap::with_max_entries(MAX_SOCKETS, 0);

/// STATE[0] = pool size (number of active sockets).
/// STATE[1] = round-robin counter.
#[map]
static STATE: Array<u64> = Array::with_max_entries(2, 0);

#[sk_lookup]
pub fn tubular_lb(ctx: SkLookupContext) -> u32 {
    match try_lb(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_lb(ctx: &SkLookupContext) -> Result<u32, i64> {
    let local_port_raw = unsafe { (*ctx.lookup).local_port };

    if local_port_raw != 443 {
        return Ok(0);
    }
    info!(ctx, "intercepting port 443");

    let size = *STATE.get(0).ok_or(0i64)?;
    if size == 0 {
        info!(ctx, "pool empty");
        return Ok(0);
    }

    let counter_ptr = STATE.get_ptr_mut(1).ok_or(0i64)?;
    let idx = unsafe {
        let c = *counter_ptr;
        *counter_ptr = c.wrapping_add(1);
        (c % size) as u32
    };

    info!(ctx, "trying slot {} of {}", idx, size);

    unsafe {
        let map_ptr = SOCK_POOL.def.get() as *mut c_void;
        let sk = bpf_map_lookup_elem(map_ptr, &idx as *const _ as *const c_void);
        if sk.is_null() {
            info!(ctx, "slot {} is null in map", idx);
            return Ok(0);
        }
        info!(ctx, "slot {} found, calling bpf_sk_assign", idx);
        let ret = bpf_sk_assign(ctx.as_ptr() as *mut _, sk, BPF_SK_LOOKUP_F_REPLACE);
        bpf_sk_release(sk);
        info!(ctx, "bpf_sk_assign returned {}", ret);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
