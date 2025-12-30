//! CLI tool for IPC communication with leash sandbox
//!
//! Usage:
//!   leash-ipc <command> [--json <PAYLOAD>] [--key value]...
//!   leash-ipc search --query "rust async"
//!   leash-ipc search --json '{"query": "rust async"}'

use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use clap::Parser;

/// CLI tool for IPC communication with leash sandbox
#[derive(Parser)]
#[command(name = "leash-ipc")]
#[command(about = "Send IPC commands to leash sandbox")]
struct Cli {
    /// Command name to invoke
    command: String,

    /// JSON payload (mutually exclusive with key-value pairs)
    #[arg(long)]
    json: Option<String>,

    /// Key-value pairs for building the payload
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Get socket path from environment
    let socket_path = match env::var("LEASH_IPC_SOCKET") {
        Ok(path) => path,
        Err(_) => {
            eprintln!("error: LEASH_IPC_SOCKET environment variable not set");
            return ExitCode::FAILURE;
        }
    };

    // Build the payload
    let payload = match build_payload(&cli) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Connect and send request
    match send_request(&socket_path, &cli.command, &payload) {
        Ok(response) => {
            println!("{response}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn build_payload(cli: &Cli) -> Result<Vec<u8>, String> {
    if let Some(json_str) = &cli.json {
        // Parse JSON and convert to MessagePack
        let value: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| format!("invalid JSON: {e}"))?;
        rmp_serde::to_vec(&value).map_err(|e| format!("serialization failed: {e}"))
    } else if !cli.args.is_empty() {
        // Parse key-value pairs from trailing args
        let mut map: HashMap<String, serde_json::Value> = HashMap::new();
        let mut i = 0;

        while i < cli.args.len() {
            let arg = &cli.args[i];
            if arg.starts_with("--") {
                let key = arg.trim_start_matches("--");
                if i + 1 < cli.args.len() && !cli.args[i + 1].starts_with("--") {
                    let value = &cli.args[i + 1];
                    // Try to parse as number or boolean, otherwise use string
                    let json_value = if let Ok(n) = value.parse::<i64>() {
                        serde_json::Value::Number(n.into())
                    } else if let Ok(n) = value.parse::<f64>() {
                        serde_json::json!(n)
                    } else if value == "true" {
                        serde_json::Value::Bool(true)
                    } else if value == "false" {
                        serde_json::Value::Bool(false)
                    } else {
                        serde_json::Value::String(value.clone())
                    };
                    map.insert(key.to_string(), json_value);
                    i += 2;
                } else {
                    // Flag without value, treat as boolean true
                    map.insert(key.to_string(), serde_json::Value::Bool(true));
                    i += 1;
                }
            } else {
                return Err(format!("unexpected argument: {arg}"));
            }
        }

        rmp_serde::to_vec(&map).map_err(|e| format!("serialization failed: {e}"))
    } else {
        // Empty payload
        rmp_serde::to_vec(&serde_json::json!({})).map_err(|e| format!("serialization failed: {e}"))
    }
}

fn send_request(socket_path: &str, method: &str, params: &[u8]) -> Result<String, String> {
    // Connect to the socket
    let mut stream =
        UnixStream::connect(socket_path).map_err(|e| format!("failed to connect: {e}"))?;

    // Build the request:
    // [4 bytes: total length (u32 BE)]
    // [1 byte: method length (u8)]
    // [method bytes (UTF-8)]
    // [params bytes (MessagePack)]
    let method_bytes = method.as_bytes();
    if method_bytes.len() > 255 {
        return Err("method name too long (max 255 bytes)".to_string());
    }

    let body_len = 1 + method_bytes.len() + params.len();
    let mut request = Vec::with_capacity(4 + body_len);
    request.extend_from_slice(&(body_len as u32).to_be_bytes());
    request.push(method_bytes.len() as u8);
    request.extend_from_slice(method_bytes);
    request.extend_from_slice(params);

    // Send the request
    stream
        .write_all(&request)
        .map_err(|e| format!("failed to send request: {e}"))?;

    // Read the response length
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("failed to read response length: {e}"))?;
    let response_len = u32::from_be_bytes(len_buf) as usize;

    if response_len == 0 || response_len > 16 * 1024 * 1024 {
        return Err(format!("invalid response length: {response_len}"));
    }

    // Read the response body
    let mut body = vec![0u8; response_len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("failed to read response: {e}"))?;

    // Parse the response:
    // [1 byte: success flag (0 or 1)]
    // [payload bytes (MessagePack result or error string)]
    if body.is_empty() {
        return Err("empty response".to_string());
    }

    let success = body[0] != 0;
    let payload = &body[1..];

    if success {
        // Deserialize MessagePack to JSON value
        let value: serde_json::Value =
            rmp_serde::from_slice(payload).map_err(|e| format!("failed to decode response: {e}"))?;
        // Output as pretty JSON
        serde_json::to_string_pretty(&value).map_err(|e| format!("JSON encoding failed: {e}"))
    } else {
        // Error message is in payload
        let error: String = rmp_serde::from_slice(payload)
            .unwrap_or_else(|_| String::from_utf8_lossy(payload).to_string());
        Err(error)
    }
}
