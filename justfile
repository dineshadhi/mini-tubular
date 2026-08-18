message := "This is a server running in a VPS"

# Build all workspace crates (server + tubular-lb)
build:
    cargo build --release

# Build the eBPF kernel program (requires Linux with rust-src + nightly)
build-ebpf:
    cd tubular-lb-ebpf && cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core

# Run the server with SO_REUSEPORT — multiple instances can share the same port.
# The kernel round-robins connections across all instances automatically.
# Usage: just serve 443 "Server A"  (in terminal 1)
#        just serve 443 "Server B"  (in terminal 2)
serve port msg=message:
    cargo run --release -p server -- {{port}} "{{msg}}"

# Build then run
run port msg=message: build
    ./target/release/server {{port}} "{{msg}}"
