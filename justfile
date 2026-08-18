message := "This is a server running in a VPS"

# Build all workspace crates (server + tubular-lb)
build:
    cargo build --release

# Build the eBPF kernel program (requires Linux with rust-src + nightly)
build-ebpf:
    cd tubular-lb-ebpf && cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core

# Build the IPv4/IPv6 family selector eBPF program
build-family-ebpf:
    cd tubular-family-ebpf && cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core

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

# Build and run the eBPF load balancer with the standard object path
# Usage: just run-ebpf /proc/111/fd/3 /proc/222/fd/3
run-ebpf *sockets: build build-ebpf
    sudo RUST_LOG=info ./target/release/tubular-lb tubular-lb-ebpf/target/bpfel-unknown-none/release/tubular-lb-ebpf {{sockets}}

# Route IPv4 to the first socket and IPv6 to the second socket
# Usage: just run-family-ebpf /proc/<v4-pid>/fd/3 /proc/<v6-pid>/fd/3
run-family-ebpf ipv4_socket ipv6_socket: build build-family-ebpf
    sudo RUST_LOG=info ./target/release/tubular-lb tubular-family-ebpf/target/bpfel-unknown-none/release/tubular-family-ebpf {{ipv4_socket}} {{ipv6_socket}}
