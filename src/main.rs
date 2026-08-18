use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;

fn handle_client(mut stream: TcpStream, port: u16, message: &str, listener_fd: i32) {
    let conn_fd = stream.as_raw_fd();
    println!("Accepted connection — fd: {}", conn_fd);

    let mut buffer = [0u8; 1024];
    if stream.read(&mut buffer).is_err() {
        return;
    }

    let pid = std::process::id();
    let fd_path = format!("/proc/{}/fd/{}", pid, listener_fd);

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>mini-tubular</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0f0f0f;
      font-family: 'Segoe UI', system-ui, sans-serif;
      color: #e0e0e0;
    }}
    .card {{
      text-align: center;
      padding: 3rem 4rem;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      background: #1a1a1a;
      box-shadow: 0 8px 32px rgba(0,0,0,0.5);
      max-width: 560px;
      width: 90%;
    }}
    .label {{
      font-size: 0.75rem;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: #666;
      margin-bottom: 0.5rem;
    }}
    .port {{
      font-size: 3.5rem;
      font-weight: 700;
      color: #7c6af7;
      letter-spacing: -0.02em;
      margin-bottom: 0.5rem;
    }}
    .fd {{
      font-size: 0.8rem;
      color: #4caf7d;
      font-family: 'Courier New', monospace;
      margin-bottom: 1.75rem;
      word-break: break-all;
    }}
    .divider {{
      width: 40px;
      height: 2px;
      background: #2a2a2a;
      margin: 0 auto 1.75rem;
    }}
    .message {{
      font-size: 1.1rem;
      line-height: 1.6;
      color: #b0b0b0;
    }}
  </style>
</head>
<body>
  <div class="card">
    <p class="label">Listening on port</p>
    <p class="port">{port}</p>
    <p class="fd">{fd_path}</p>
    <div class="divider"></div>
    <p class="message">{message}</p>
  </div>
</body>
</html>"#,
        port = port,
        fd_path = fd_path,
        message = message
    );

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );

    let _ = stream.write_all(response.as_bytes());
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <port> <message>", args[0]);
        std::process::exit(1);
    }

    let port: u16 = args[1].parse().unwrap_or_else(|_| {
        eprintln!("Invalid port: {}", args[1]);
        std::process::exit(1);
    });

    let message = args[2..].join(" ");

    let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
        eprintln!("Failed to bind to port {}: {}", port, e);
        std::process::exit(1);
    });

    let listener_fd = listener.as_raw_fd();
    let pid = std::process::id();
    let fd_path = format!("/proc/{}/fd/{}", pid, listener_fd);

    println!("Listening on port {} — listener fd: {}", port, listener_fd);
    println!("Socket path (for eBPF loader): {}", fd_path);
    println!("Message: {}", message);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_client(stream, port, &message, listener_fd),
            Err(e) => eprintln!("Connection error: {}", e),
        }
    }
}
