//! IPC server implementation
//!
//! Unix domain socket server for handling IPC requests from sandboxed processes.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_net::unix::UnixListener;
use executor_core::{Executor, Task};
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

use crate::ipc::protocol::{IpcError, IpcRequest, IpcResponse};
use crate::ipc::router::IpcRouter;

/// IPC server that listens on a Unix domain socket
pub struct IpcServer {
    router: Arc<IpcRouter>,
    socket_path: PathBuf,
    running: Arc<AtomicBool>,
}

impl IpcServer {
    /// Create and start a new IPC server
    ///
    /// # Arguments
    /// * `router` - The router to dispatch incoming requests
    /// * `socket_path` - Path for the Unix domain socket
    /// * `executor` - Executor to spawn the server task on
    pub async fn new<E: Executor + Clone + 'static>(
        router: IpcRouter,
        socket_path: impl AsRef<Path>,
        executor: E,
    ) -> Result<Self, IpcError> {
        let socket_path = socket_path.as_ref().to_path_buf();
        let router = Arc::new(router);
        let running = Arc::new(AtomicBool::new(true));

        // Remove existing socket file if present
        let _ = std::fs::remove_file(&socket_path);

        // Create parent directory if needed
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Bind the listener
        let listener = UnixListener::bind(&socket_path)?;

        tracing::info!(path = %socket_path.display(), "IPC server started");

        // Spawn the accept loop
        let server = Self {
            router: Arc::clone(&router),
            socket_path: socket_path.clone(),
            running: Arc::clone(&running),
        };

        let router_clone = Arc::clone(&router);
        let running_clone = Arc::clone(&running);
        executor
            .spawn(run_server(listener, router_clone, running_clone, executor.clone()))
            .detach();

        Ok(server)
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Stop the server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        tracing::debug!(path = %self.socket_path.display(), "IPC server stopping");
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop();
        // Remove the socket file only - directory cleanup is Sandbox's responsibility
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Main server accept loop
async fn run_server<E: Executor + Clone + 'static>(
    listener: UnixListener,
    router: Arc<IpcRouter>,
    running: Arc<AtomicBool>,
    executor: E,
) {
    while running.load(Ordering::SeqCst) {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let router = Arc::clone(&router);
                executor.spawn(handle_connection(stream, router)).detach();
            }
            Err(e) => {
                if running.load(Ordering::SeqCst) {
                    tracing::warn!(error = %e, "failed to accept IPC connection");
                }
            }
        }
    }
}

/// Handle a single connection
async fn handle_connection(mut stream: async_net::unix::UnixStream, router: Arc<IpcRouter>) {
    loop {
        // Read the length prefix (4 bytes, u32 BE)
        let mut len_buf = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut len_buf).await {
            if e.kind() != std::io::ErrorKind::UnexpectedEof {
                tracing::debug!(error = %e, "failed to read request length");
            }
            break;
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 16 * 1024 * 1024 {
            // Max 16MB
            tracing::warn!(len, "invalid request length");
            break;
        }

        // Read the request body
        let mut body = vec![0u8; len];
        if let Err(e) = stream.read_exact(&mut body).await {
            tracing::debug!(error = %e, "failed to read request body");
            break;
        }

        // Parse and handle the request
        let response = match IpcRequest::from_bytes(&body) {
            Ok(request) => {
                tracing::debug!(method = %request.method, "handling IPC request");
                match router.handle(&request.method, &request.params).await {
                    Ok(result) => IpcResponse {
                        success: true,
                        payload: result,
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "IPC handler error");
                        IpcResponse::error(&e.to_string()).unwrap_or_else(|_| IpcResponse {
                            success: false,
                            payload: vec![],
                        })
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse IPC request");
                IpcResponse::error(&e.to_string()).unwrap_or_else(|_| IpcResponse {
                    success: false,
                    payload: vec![],
                })
            }
        };

        // Send the response
        let response_bytes = response.to_bytes();
        if let Err(e) = stream.write_all(&response_bytes).await {
            tracing::debug!(error = %e, "failed to write response");
            break;
        }
    }
}
