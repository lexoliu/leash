//! Test network proxy filtering with AllowList policy

use native_sandbox::{AllowList, NetworkProxy, SandboxResult};

#[tokio::main]
async fn main() -> SandboxResult<()> {
    tracing_subscriber::fmt::init();

    // Create an AllowList policy that only allows httpbin.org
    let policy = AllowList::new(["httpbin.org", "*.httpbin.org"]);

    // Create and start the proxy
    let proxy = NetworkProxy::new(policy)?;
    println!("Proxy started at: {}", proxy.proxy_url());

    proxy.start()?;

    // Test with curl using the proxy
    println!("\n--- Testing allowed domain (httpbin.org) ---");
    let status = std::process::Command::new("curl")
        .env("http_proxy", proxy.proxy_url())
        .env("https_proxy", proxy.proxy_url())
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "http://httpbin.org/get"])
        .status()?;
    println!("httpbin.org result: exit={}", status);

    println!("\n--- Testing blocked domain (example.com) ---");
    let status = std::process::Command::new("curl")
        .env("http_proxy", proxy.proxy_url())
        .env("https_proxy", proxy.proxy_url())
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "http://example.com"])
        .status()?;
    println!("example.com result: exit={}", status);

    println!("\n--- Testing HTTPS to allowed domain ---");
    let output = std::process::Command::new("curl")
        .env("http_proxy", proxy.proxy_url())
        .env("https_proxy", proxy.proxy_url())
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "https://httpbin.org/get"])
        .output()?;
    println!(
        "HTTPS httpbin.org: exit={}, response={}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );

    println!("\n--- Testing HTTPS to blocked domain ---");
    let output = std::process::Command::new("curl")
        .env("http_proxy", proxy.proxy_url())
        .env("https_proxy", proxy.proxy_url())
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com"])
        .output()?;
    println!(
        "HTTPS example.com: exit={}, response={}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );

    proxy.stop();
    println!("\nProxy stopped");

    Ok(())
}
