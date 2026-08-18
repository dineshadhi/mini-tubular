#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    bindings::{bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_release},
    cty::c_void,
    macros::{map, sk_lookup},
    maps::{Array, SockMap},
    programs::SkLookupContext,
    EbpfContext,
};
use aya_log_ebpf::info;

const MAX_SOCKETS: u32 = 64;

// BPF_SK_LOOKUP_F_REPLACE — override port mismatch check
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
    info!(ctx, "sk_lookup fired: port={}", local_port_raw);

    // Only intercept port 443 (host byte order).
    if local_port_raw != 443 {
        return Ok(0);
    }
    info!(ctx, "intercepting port 443");

    // Read pool size.
    let size = *STATE.get(0).ok_or(0i64)?;
    if size == 0 {
        info!(ctx, "pool empty, passing through");
        return Ok(0);
    }

    // Fetch and increment the round-robin counter.
    let counter_ptr = STATE.get_ptr_mut(1).ok_or(0i64)?;
    let idx = unsafe {
        let c = *counter_ptr;
        *counter_ptr = c.wrapping_add(1);
        (c % size) as u32
    };

    // Look up the socket directly and call bpf_sk_assign without releasing
    // the reference first — aya's redirect_sk_lookup calls bpf_sk_release
    // immediately after bpf_sk_assign which drops the ref too early.
    let ret = unsafe {
        let map_ptr = &mut SOCK_POOL.def as *mut _ as *mut c_void;
        let sk = bpf_map_lookup_elem(map_ptr, &idx as *const _ as *const c_void);
        if sk.is_null() {
            info!(ctx, "slot {} is empty", idx);
            return Ok(0);
        }
        // bpf_sk_assign with BPF_SK_LOOKUP_F_REPLACE
        let r = bpf_sk_assign(ctx.as_ptr() as *mut _, sk, BPF_SK_LOOKUP_F_REPLACE);
        // Release only after assign is done
        bpf_sk_release(sk);
        r
    };

    if ret == 0 {
        info!(ctx, "assigned connection to slot {}", idx);
    } else {
        info!(ctx, "bpf_sk_assign failed: {} for slot {}", ret, idx);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
