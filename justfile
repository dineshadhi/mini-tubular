message := "This is a server running in a VPS"

# Build the release binary
build:
    cargo build --release

# Run the server (port is required)
serve port msg=message:
    cargo run --release -- {{port}} "{{msg}}"

# Build then run
run port msg=message: build
    ./target/release/mini-tubular {{port}} "{{msg}}"
