use std::env;
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConnection;

// ── TLS certificate loading ────────────────────────────────────────────────

/// Try to find a certificate in /etc/letsencrypt/live/<domain>/ for every
/// domain present in that directory.  Returns (cert_chain, private_key) on
/// success.
fn load_acme_certs() -> Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let live = Path::new("/etc/letsencrypt/live");
    if !live.is_dir() {
        return None;
    }

    for entry in fs::read_dir(live).ok()? {
        let entry = entry.ok()?;
        let domain_dir = entry.path();
        let fullchain = domain_dir.join("fullchain.pem");
        let privkey = domain_dir.join("privkey.pem");

        if !fullchain.exists() || !privkey.exists() {
            continue;
        }

        let cert_pem = fs::read(&fullchain).ok()?;
        let key_pem = fs::read(&privkey).ok()?;

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_pem.as_slice())
                .filter_map(|r| r.ok())
                .map(|c| c.into_owned())
                .collect();

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .ok()
            .flatten()?
            .clone_key();

        if !certs.is_empty() {
            println!(
                "TLS: loaded ACME certificate from {}",
                domain_dir.display()
            );
            return Some((certs, key));
        }
    }

    None
}

/// Generate a self-signed certificate for localhost / 127.0.0.1.
fn self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(subject_alt_names).expect("rcgen failed");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .expect("invalid key der");

    println!("TLS: no ACME certs found — using self-signed certificate");
    (vec![cert_der], key_der)
}

/// Build a rustls ServerConfig from whichever cert source is available.
fn build_tls_config() -> Arc<ServerConfig> {
    let (certs, key) = load_acme_certs().unwrap_or_else(self_signed_cert);

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("invalid TLS certificate or key");

    Arc::new(config)
}

// ── Request handling ───────────────────────────────────────────────────────

fn build_html(port: u16, fd_path: &str, message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>mini-tubular</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html {{ font-size: 20px; }}
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
      padding: 5rem 6rem;
      border: 1px solid #2a2a2a;
      border-radius: 20px;
      background: #1a1a1a;
      box-shadow: 0 16px 64px rgba(0,0,0,0.6);
      max-width: 860px;
      width: 92%;
    }}
    .label {{
      font-size: 1rem;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: #555;
      margin-bottom: 0.75rem;
    }}
    .port {{
      font-size: 7rem;
      font-weight: 800;
      color: #7c6af7;
      letter-spacing: -0.03em;
      line-height: 1;
      margin-bottom: 1rem;
    }}
    .fd {{
      font-size: 1.1rem;
      color: #4caf7d;
      font-family: 'Courier New', monospace;
      margin-bottom: 3rem;
      word-break: break-all;
    }}
    .divider {{
      width: 60px;
      height: 3px;
      background: #2a2a2a;
      margin: 0 auto 3rem;
    }}
    .message {{
      font-size: 1.6rem;
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
        message = message,
    )
}

fn handle_client(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    port: u16,
    message: &str,
    listener_fd: i32,
) {
    let conn_fd = stream.as_raw_fd();
    println!("Accepted connection — fd: {}", conn_fd);

    let mut tls = match ServerConnection::new(tls_config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("TLS init error: {}", e);
            return;
        }
    };

    // Complete TLS handshake, then serve HTTP over the encrypted stream.
    let mut binding = &stream;
    let mut tls_stream = rustls::Stream::new(&mut tls, &mut binding);

    // Read the HTTP request (we just need to drain it; we always respond 200).
    let mut buf = [0u8; 4096];
    match tls_stream.read(&mut buf) {
        Ok(0) | Err(_) => return,
        Ok(_) => {}
    }

    let pid = std::process::id();
    let fd_path = format!("/proc/{}/fd/{}", pid, listener_fd);
    let html = build_html(port, &fd_path, message);

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html,
    );

    let mut writer = BufWriter::new(&mut tls_stream);
    if let Err(e) = writer.write_all(response.as_bytes()) {
        eprintln!("Write error: {}", e);
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

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

    let tls_config = build_tls_config();

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
            Ok(stream) => handle_client(stream, Arc::clone(&tls_config), port, &message, listener_fd),
            Err(e) => eprintln!("Connection error: {}", e),
        }
    }
}
