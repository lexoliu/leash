//! IPC router for dispatching commands

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::ipc::command::IpcCommand;
use crate::ipc::protocol::IpcError;

/// Type-erased handler function
type ErasedHandler = Box<
    dyn Fn(&[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, IpcError>> + Send>> + Send + Sync,
>;

/// Metadata about a registered command
pub struct CommandMeta {
    /// Positional argument names in order (e.g., ["query"] or ["subagent", "prompt"])
    pub positional_args: Vec<String>,
    /// Stdin argument name for piped input
    pub stdin_arg: Option<String>,
}

/// Router that dispatches IPC requests to registered command handlers
///
/// The router stores type-erased handlers internally, but registration is type-safe
/// via the `IpcCommand` trait.
pub struct IpcRouter {
    handlers: HashMap<String, ErasedHandler>,
    metadata: HashMap<String, CommandMeta>,
}

impl IpcRouter {
    /// Create a new empty router
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Register a command instance.
    ///
    /// The command is cloned for each request, preserving any stateful data
    /// (like registries, connections, etc.) while applying request arguments.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let router = IpcRouter::new()
    ///     .register(SearchCommand::new(api_key))
    ///     .register(TasksCommand::new(registry));
    /// ```
    pub fn register<C: IpcCommand + Clone + Sync>(mut self, cmd: C) -> Self {
        let name = cmd.name();
        let positional_args = cmd.positional_args();
        let stdin_arg = cmd.stdin_arg();
        let method_name = name.clone();

        // Clone the command for each request, preserving state
        let handler: ErasedHandler = Box::new(move |params: &[u8]| {
            let mut cmd = cmd.clone();
            let params = params.to_vec();
            let method_name = method_name.clone();
            Box::pin(async move {
                cmd.apply_args(&params)?;
                cmd.set_method_name(&method_name);
                let response = cmd.handle().await;
                let bytes = rmp_serde::to_vec(&response)?;
                Ok(bytes)
            })
        });

        self.metadata.insert(
            name.clone(),
            CommandMeta {
                positional_args: positional_args.iter().map(|c| c.to_string()).collect(),
                stdin_arg: stdin_arg.map(|c| c.into_owned()),
            },
        );
        self.handlers.insert(name, handler);
        self
    }

    /// Handle an incoming request
    ///
    /// This is called internally by the IPC server.
    pub(crate) async fn handle(&self, method: &str, params: &[u8]) -> Result<Vec<u8>, IpcError> {
        let handler = self
            .handlers
            .get(method)
            .ok_or_else(|| IpcError::UnknownMethod(method.to_string()))?;

        handler(params).await
    }

    /// Get the list of registered method names with their metadata
    pub fn methods(&self) -> impl Iterator<Item = (&str, &CommandMeta)> {
        self.metadata.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl Default for IpcRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestCommand {
        value: i32,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestResponse {
        doubled: i32,
    }

    impl IpcCommand for TestCommand {
        type Response = TestResponse;

        fn name(&self) -> String {
            "test".to_string()
        }

        fn apply_args(&mut self, params: &[u8]) -> Result<(), rmp_serde::decode::Error> {
            *self = rmp_serde::from_slice(params)?;
            Ok(())
        }

        async fn handle(&mut self) -> TestResponse {
            TestResponse {
                doubled: self.value * 2,
            }
        }
    }

    #[tokio::test]
    async fn test_router_dispatch() {
        let router = IpcRouter::new().register(TestCommand { value: 0 });

        let cmd = TestCommand { value: 21 };
        let params = rmp_serde::to_vec(&cmd).unwrap();

        let response_bytes = router.handle("test", &params).await.unwrap();
        let response: TestResponse = rmp_serde::from_slice(&response_bytes).unwrap();

        assert_eq!(response, TestResponse { doubled: 42 });
    }

    #[tokio::test]
    async fn test_router_unknown_method() {
        let router = IpcRouter::new();

        let result = router.handle("unknown", &[]).await;
        assert!(matches!(result, Err(IpcError::UnknownMethod(_))));
    }
}
