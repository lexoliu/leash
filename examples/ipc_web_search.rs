//! IPC example with WebSearch command
//!
//! This example demonstrates how to:
//! 1. Define an IPC command (WebSearch)
//! 2. Register it with IpcRouter
//! 3. Create a sandbox with IPC enabled
//! 4. Call the command from within the sandbox
//!
//! Run with: cargo run --example ipc_web_search

use leash::{IpcCommand, IpcRouter, Sandbox, SandboxConfig};
use serde::{Deserialize, Serialize};

/// WebSearch command - sent from sandbox to host
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WebSearch {
    query: String,
}

/// WebSearch response - returned from host to sandbox
#[derive(Debug, Serialize, Deserialize)]
struct WebSearchResult {
    items: Vec<SearchItem>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SearchItem {
    title: String,
    url: String,
}

impl IpcCommand for WebSearch {
    type Response = WebSearchResult;

    fn name(&self) -> String {
        "web_search".to_string()
    }

    fn apply_args(&mut self, params: &[u8]) -> Result<(), leash::rmp_serde::decode::Error> {
        *self = leash::rmp_serde::from_slice(params)?;
        Ok(())
    }

    async fn handle(&mut self) -> WebSearchResult {
        println!("[Host] Received web_search: {:?}", self.query);

        // Mock results (real implementation would call a search API)
        WebSearchResult {
            items: vec![
                SearchItem {
                    title: format!("Result 1 for '{}'", self.query),
                    url: "https://example.com/1".to_string(),
                },
                SearchItem {
                    title: format!("Result 2 for '{}'", self.query),
                    url: "https://example.com/2".to_string(),
                },
            ],
        }
    }
}

#[tokio::main]
async fn main() -> leash::Result<()> {
    tracing_subscriber::fmt::init();

    // Create router and register WebSearch command
    let router = IpcRouter::new().register(WebSearch::default());

    // Path to leash-ipc binary
    let leash_ipc = std::env::current_dir()?.join("target/debug/leash-ipc");

    // Create sandbox with IPC enabled, using tokio executor
    let config = SandboxConfig::builder()
        .ipc(router)
        .executable_path(&leash_ipc)
        .build()?;
    let sandbox =
        Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal).await?;

    println!("Sandbox: {}", sandbox.working_dir().display());

    // Call web_search from sandbox via leash-ipc
    let output = sandbox
        .command(leash_ipc.to_string_lossy())
        .arg("web_search")
        .arg("--query")
        .arg("rust async programming")
        .output()
        .await?;

    println!("\nExit: {:?}", output.status);
    println!("stdout:\n{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}
