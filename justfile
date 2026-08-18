message := "This is a server running in a VPS"

# Build all workspace crates (server + tubular-lb)
build:
    cargo build --release

# Build the eBPF kernel program (requires Linux with rust-src + nightly)
build-ebpf:
    cd tubular-lb-ebpf && cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core

# Run the HTTP server (port is required)
serve port msg=message:
    cargo run --release -p server -- {{port}} "{{msg}}"

# Build then run the HTTP server
run port msg=message: build
    ./target/release/server {{port}} "{{msg}}"

# Run the eBPF load balancer
# Usage: just lb <ebpf-obj> /proc/111/fd/3 /proc/222/fd/3 ...
lb ebpf_obj *sockets:
    sudo RUST_LOG=info ./target/release/tubular-lb {{ebpf_obj}} {{sockets}}

# Full workflow: build everything, then run lb
lb-run ebpf_obj *sockets: build
    sudo RUST_LOG=info ./target/release/tubular-lb {{ebpf_obj}} {{sockets}}
