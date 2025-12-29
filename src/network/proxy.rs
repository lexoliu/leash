//! Network proxy for filtering sandboxed process network access
//!
//! This module implements a local HTTP/HTTPS proxy that intercepts network
//! requests from sandboxed processes and applies NetworkPolicy filtering.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crate::error::{SandboxError, SandboxResult};
use crate::network::{ConnectionDirection, DomainRequest, NetworkPolicy};

/// A network proxy that filters requests based on a NetworkPolicy
pub struct NetworkProxy<N: NetworkPolicy> {
    policy: Arc<N>,
    listener: TcpListener,
    addr: SocketAddr,
    running: Arc<AtomicBool>,
}

impl<N: NetworkPolicy + 'static> NetworkProxy<N> {
    /// Create a new network proxy with the given policy
    pub fn new(policy: N) -> SandboxResult<Self> {
        // Bind to a random available port on localhost
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        tracing::debug!(addr = %addr, "network proxy: bound to address");

        Ok(Self {
            policy: Arc::new(policy),
            listener,
            addr,
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Get the proxy address (for setting HTTP_PROXY/HTTPS_PROXY)
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get the proxy URL for environment variables
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Start the proxy server in a background thread
    pub fn start(&self) -> SandboxResult<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(()); // Already running
        }

        let listener = self.listener.try_clone()?;
        let policy = Arc::clone(&self.policy);
        let running = Arc::clone(&self.running);

        thread::spawn(move || {
            tracing::debug!("network proxy: started");

            while running.load(Ordering::SeqCst) {
                // Set a timeout so we can check the running flag periodically
                listener
                    .set_nonblocking(true)
                    .expect("Failed to set non-blocking");

                match listener.accept() {
                    Ok((stream, peer_addr)) => {
                        let policy = Arc::clone(&policy);
                        thread::spawn(move || {
                            if let Err(e) = handle_connection(stream, peer_addr, &*policy) {
                                tracing::warn!(error = %e, "network proxy: connection error");
                            }
                        });
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // No connection available, sleep briefly
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => {
                        if running.load(Ordering::SeqCst) {
                            tracing::error!(error = %e, "network proxy: accept error");
                        }
                        break;
                    }
                }
            }

            tracing::debug!("network proxy: stopped");
        });

        Ok(())
    }

    /// Stop the proxy server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl<N: NetworkPolicy> Drop for NetworkProxy<N> {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Handle a single proxy connection
fn handle_connection<N: NetworkPolicy>(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    policy: &N,
) -> SandboxResult<()> {
    client.set_nonblocking(false)?;

    let mut reader = BufReader::new(client.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(SandboxError::ProxyError("Invalid request line".to_string()));
    }

    let method = parts[0];
    let target = parts[1];

    tracing::debug!(method = %method, target = %target, peer = %peer_addr, "network proxy: request");

    if method == "CONNECT" {
        // HTTPS tunnel request
        handle_connect(&mut client, reader, target, policy)
    } else {
        // Regular HTTP request
        handle_http(&mut client, reader, &request_line, target, policy)
    }
}

/// Handle CONNECT method for HTTPS tunneling
fn handle_connect<N: NetworkPolicy>(
    client: &mut TcpStream,
    mut reader: BufReader<TcpStream>,
    target: &str,
    policy: &N,
) -> SandboxResult<()> {
    // Parse host:port from target
    let (host, port) = parse_host_port(target, 443)?;

    // Read and discard headers until empty line
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Check policy
    let request = DomainRequest::new(host.clone(), port, ConnectionDirection::Outbound, 0);

    // Use blocking check - in a real async implementation, this would be async
    let allowed = futures_lite::future::block_on(policy.check(&request));

    if !allowed {
        tracing::info!(host = %host, port = port, "network proxy: connection denied by policy");
        client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by sandbox policy\r\n")?;
        return Ok(());
    }

    tracing::debug!(host = %host, port = port, "network proxy: connection allowed");

    // Connect to the target
    let target_addr = format!("{}:{}", host, port);
    let mut target_stream = match TcpStream::connect(&target_addr) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target = %target_addr, error = %e, "network proxy: failed to connect");
            client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")?;
            return Ok(());
        }
    };

    // Send 200 Connection Established
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

    // Tunnel data between client and target
    tunnel(client, &mut target_stream)?;

    Ok(())
}

/// Handle regular HTTP request
fn handle_http<N: NetworkPolicy>(
    client: &mut TcpStream,
    mut reader: BufReader<TcpStream>,
    request_line: &str,
    target: &str,
    policy: &N,
) -> SandboxResult<()> {
    // Parse URL to get host
    let (host, port, path) = parse_http_url(target)?;

    // Read headers
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
        headers.push(line);
    }

    // Check policy
    let request = DomainRequest::new(host.clone(), port, ConnectionDirection::Outbound, 0);
    let allowed = futures_lite::future::block_on(policy.check(&request));

    if !allowed {
        tracing::info!(host = %host, port = port, "network proxy: HTTP request denied by policy");
        client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by sandbox policy\r\n")?;
        return Ok(());
    }

    tracing::debug!(host = %host, port = port, path = %path, "network proxy: HTTP request allowed");

    // Connect to target
    let target_addr = format!("{}:{}", host, port);
    let mut target_stream = match TcpStream::connect(&target_addr) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target = %target_addr, error = %e, "network proxy: failed to connect");
            client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")?;
            return Ok(());
        }
    };

    // Forward the request with modified path (remove scheme and host)
    let method = request_line.split_whitespace().next().unwrap_or("GET");
    let version = request_line
        .split_whitespace()
        .last()
        .unwrap_or("HTTP/1.1");
    let new_request_line = format!("{} {} {}\r\n", method, path, version);
    target_stream.write_all(new_request_line.as_bytes())?;

    // Forward headers
    for header in &headers {
        target_stream.write_all(header.as_bytes())?;
    }
    target_stream.write_all(b"\r\n")?;

    // Forward response back to client
    let mut response = Vec::new();
    std::io::copy(&mut target_stream, &mut response)?;
    client.write_all(&response)?;

    Ok(())
}

/// Parse host:port from CONNECT target
fn parse_host_port(target: &str, default_port: u16) -> SandboxResult<(String, u16)> {
    if let Some(colon_pos) = target.rfind(':') {
        let host = target[..colon_pos].to_string();
        let port: u16 = target[colon_pos + 1..]
            .parse()
            .map_err(|_| SandboxError::ProxyError(format!("Invalid port in: {}", target)))?;
        Ok((host, port))
    } else {
        Ok((target.to_string(), default_port))
    }
}

/// Parse HTTP URL to extract host, port, and path
fn parse_http_url(url: &str) -> SandboxResult<(String, u16, String)> {
    // Handle absolute URLs (http://host:port/path)
    let url = if let Some(stripped) = url.strip_prefix("http://") {
        stripped
    } else if let Some(stripped) = url.strip_prefix("https://") {
        stripped
    } else {
        url
    };

    // Split host:port and path
    let (host_port, path) = if let Some(slash_pos) = url.find('/') {
        (&url[..slash_pos], &url[slash_pos..])
    } else {
        (url, "/")
    };

    // Parse host and port
    let (host, port) = parse_host_port(host_port, 80)?;

    Ok((host, port, path.to_string()))
}

/// Tunnel data bidirectionally between two streams
fn tunnel(client: &mut TcpStream, target: &mut TcpStream) -> SandboxResult<()> {
    // Clone streams for bidirectional transfer
    let mut client_read = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut target_read = target.try_clone()?;
    let mut target_write = target.try_clone()?;

    client_read.set_nonblocking(true)?;
    target_read.set_nonblocking(true)?;

    // Client -> Target
    let handle1 = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 8192];
        loop {
            match client_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if target_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
        let _ = target_write.shutdown(Shutdown::Write);
        Ok(())
    });

    // Target -> Client
    let handle2 = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 8192];
        loop {
            match target_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
        let _ = client_write.shutdown(Shutdown::Write);
        Ok(())
    });

    let _ = handle1.join();
    let _ = handle2.join();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port() {
        let (host, port) = parse_host_port("example.com:443", 80).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);

        let (host, port) = parse_host_port("example.com", 80).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_http_url() {
        let (host, port, path) = parse_http_url("http://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");

        let (host, port, path) = parse_http_url("http://example.com:8080/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/path");
    }
}
