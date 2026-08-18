#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::sk_action::SK_PASS,
    macros::{map, sk_lookup},
    maps::{Array, SockMap},
    programs::SkLookupContext,
};
use aya_log_ebpf::info;

/// Maximum sockets in the pool — must match userspace.
const MAX_SOCKETS: u32 = 64;

/// Pool of listening sockets populated by the userspace loader.
#[map]
static SOCK_POOL: SockMap = SockMap::with_max_entries(MAX_SOCKETS, 0);

/// Single-element array: [pool_size, rr_counter].
/// Using Array<u64> so the eBPF verifier can reason about it.
/// Index 0 → number of active sockets.
/// Index 1 → round-robin counter (wraps naturally as u64).
#[map]
static STATE: Array<u64> = Array::with_max_entries(2, 0);

#[sk_lookup]
pub fn tubular_lb(ctx: SkLookupContext) -> u32 {
    match try_lb(&ctx) {
        Ok(v) => v,
        Err(_) => SK_PASS,
    }
}

#[inline(always)]
fn try_lb(ctx: &SkLookupContext) -> Result<u32, i64> {
    // Read pool size (index 0).
    let size_ptr = STATE.get_ptr_mut(0).ok_or(0i64)?;
    let size = unsafe { *size_ptr };
    if size == 0 {
        return Ok(SK_PASS);
    }

    // Atomically increment the round-robin counter (index 1).
    let counter_ptr = STATE.get_ptr_mut(1).ok_or(0i64)?;
    let idx = unsafe {
        let c = *counter_ptr;
        *counter_ptr = c.wrapping_add(1);
        c % size
    };

    // Look up the socket at that slot.
    let sk = unsafe { SOCK_POOL.get(idx as u32) }.ok_or(0i64)?;

    // Assign this socket to handle the incoming connection.
    ctx.assign(sk, 0).map_err(|e| e as i64)?;

    info!(ctx, "assigned connection -> slot {}", idx);

    Ok(SK_PASS)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
