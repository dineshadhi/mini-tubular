#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_SOCKMAP},
    helpers::{bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_release},
    macros::sk_lookup,
    programs::SkLookupContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use core::ffi::c_void;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

const IPV4_SLOT: u32 = 0;
const IPV6_SLOT: u32 = 1;

#[no_mangle]
#[link_section = "maps"]
static mut SOCK_POOL: bpf_map_def = bpf_map_def {
    type_: BPF_MAP_TYPE_SOCKMAP,
    key_size: 4,
    value_size: 4,
    max_entries: 2,
    map_flags: 0,
    id: 0,
    pinning: 0,
};

#[sk_lookup]
pub fn tubular_lb(ctx: SkLookupContext) -> u32 {
    match try_select_family(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => SK_DROP,
    }
}

#[inline(always)]
fn try_select_family(ctx: &SkLookupContext) -> Result<u32, i64> {
    let lookup = unsafe { &*ctx.lookup };

    // Leave unrelated services, including SSH, untouched.
    if lookup.local_port != 443 {
        return Ok(SK_PASS);
    }

    let slot = match lookup.family {
        AF_INET => IPV4_SLOT,
        AF_INET6 => IPV6_SLOT,
        _ => return Ok(SK_PASS),
    };

    let ret = unsafe {
        let sk = bpf_map_lookup_elem(
            &mut SOCK_POOL as *mut _ as *mut c_void,
            &slot as *const _ as *const c_void,
        );
        if sk.is_null() {
            info!(ctx, "address-family socket slot {} is empty", slot);
            return Ok(SK_DROP);
        }

        let ret = bpf_sk_assign(ctx.as_ptr() as *mut c_void, sk, 0);
        bpf_sk_release(sk);
        ret
    };

    if ret == 0 {
        info!(ctx, "assigned family {} to socket slot {}", lookup.family, slot);
        Ok(SK_PASS)
    } else {
        info!(ctx, "family assignment failed: family={} slot={} error={}", lookup.family, slot, ret);
        Ok(SK_DROP)
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
