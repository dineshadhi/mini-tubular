/// tubular-lb — userspace loader
///
/// Usage:
///   sudo tubular-lb <ebpf-obj> <fd-or-proc-path> [<fd-or-proc-path> ...]
///
/// Each argument after the eBPF object path is either:
///   - a raw fd integer (only valid if this process inherited it), or
///   - a /proc/<pid>/fd/<n> path pointing to a listening socket.
///
/// The program:
///   1. Opens each socket path to obtain a local fd.
///   2. Loads the eBPF object.
///   3. Inserts all sockets into the SOCK_POOL SockMap.
///   4. Sets STATE[0] = pool size.
///   5. Attaches the sk_lookup program to the network namespace.
///   6. Blocks until Ctrl-C, then cleans up.
use std::{
    fs,
    os::unix::io::RawFd,
    path::Path,
};

use anyhow::{bail, Context, Result};
use aya::{
    maps::{Array, SockMap},
    programs::SkLookup,
    Ebpf,
};
use aya_log::EbpfLogger;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        bail!(
            "Usage: {} <ebpf-object.o> <socket-path-or-fd> [...]",
            args[0]
        );
    }

    let obj_path = &args[1];
    let socket_args = &args[2..];

    if socket_args.len() > 64 {
        bail!("Too many sockets — maximum is 64");
    }

    // ── 1. Resolve each argument to a local fd ──────────────────────────────
    let mut fds: Vec<RawFd> = Vec::new();

    for arg in socket_args {
        let fd = resolve_socket_arg(arg)
            .with_context(|| format!("Failed to open socket: {}", arg))?;
        info!("Resolved {} -> fd {}", arg, fd);
        fds.push(fd);
    }

    // ── 2. Load the eBPF object ─────────────────────────────────────────────
    let obj_bytes = fs::read(obj_path)
        .with_context(|| format!("Failed to read eBPF object: {}", obj_path))?;

    let mut bpf = Ebpf::load(&obj_bytes)?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("eBPF logger not available: {}", e);
    }

    // ── 3. Populate SOCK_POOL ───────────────────────────────────────────────
    {
        let mut sock_pool: SockMap<_> = SockMap::try_from(
            bpf.map_mut("SOCK_POOL")
                .context("SOCK_POOL map not found")?,
        )?;
        for (i, &fd) in fds.iter().enumerate() {
            sock_pool
                .set(i as u32, &fd, 0)
                .with_context(|| format!("Failed to insert fd {} at slot {}", fd, i))?;
            info!("SOCK_POOL[{}] = fd {}", i, fd);
        }
    }

    // ── 4. Write pool size into STATE[0] ────────────────────────────────────
    {
        let mut state: Array<_, u64> = Array::try_from(
            bpf.map_mut("STATE").context("STATE map not found")?,
        )?;
        state
            .set(0, fds.len() as u64, 0)
            .context("Failed to set STATE[0] (pool_size)")?;
        info!("Pool size set to {}", fds.len());
    }

    // ── 5. Attach sk_lookup program to the current network namespace ────────
    let netns = fs::File::open("/proc/self/ns/net").context("Failed to open netns")?;

    let program: &mut SkLookup = bpf
        .program_mut("tubular_lb")
        .context("Program 'tubular_lb' not found in eBPF object")?
        .try_into()?;

    program.load()?;

    let _link = program
        .attach(netns)
        .context("Failed to attach sk_lookup program")?;

    info!(
        "tubular-lb running — round-robining {} sockets. Press Ctrl-C to stop.",
        fds.len()
    );

    // ── 6. Wait for Ctrl-C ──────────────────────────────────────────────────
    signal::ctrl_c().await?;
    info!("Shutting down.");

    Ok(())
}

/// Resolve a CLI argument to a raw fd in this process.
fn resolve_socket_arg(arg: &str) -> Result<RawFd> {
    if Path::new(arg).exists() {
        let fd = unsafe {
            libc::open(
                std::ffi::CString::new(arg.as_bytes())?.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            bail!(
                "open({}) failed: {}",
                arg,
                std::io::Error::last_os_error()
            );
        }
        validate_socket_fd(fd)?;
        return Ok(fd);
    }

    if let Ok(n) = arg.parse::<RawFd>() {
        validate_socket_fd(n)?;
        return Ok(n);
    }

    bail!("'{}' is neither a valid path nor a numeric fd", arg);
}

/// Confirm the fd is actually a socket (getsockopt SO_TYPE).
fn validate_socket_fd(fd: RawFd) -> Result<()> {
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        bail!(
            "fd {} is not a socket: {}",
            fd,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}
