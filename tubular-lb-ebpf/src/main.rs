#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    macros::{map, sk_lookup},
    maps::{Array, SockMap},
    programs::SkLookupContext,
};
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

    let result = unsafe { SOCK_POOL.redirect_sk_lookup(ctx, idx, BPF_SK_LOOKUP_F_REPLACE) };
    match result {
        Ok(()) => info!(ctx, "bpf_sk_assign ok for slot {}", idx),
        Err(e) => info!(ctx, "bpf_sk_assign failed slot {} err {}", idx, e),
    }

    Ok(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
