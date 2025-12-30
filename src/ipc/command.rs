//! IPC command trait definition

use std::future::Future;

use serde::{Serialize, de::DeserializeOwned};

/// A type-safe IPC command with its handler
///
/// Users implement this trait to define commands that can be called from sandboxed processes.
/// The command struct contains the request data, and the `handle` method processes it.
///
/// # Example
///
/// ```rust,ignore
/// use serde::{Serialize, Deserialize};
/// use leash::ipc::IpcCommand;
///
/// #[derive(Serialize, Deserialize)]
/// struct SearchCommand {
///     query: String,
/// }
///
/// #[derive(Serialize, Deserialize)]
/// struct SearchResult {
///     items: Vec<String>,
/// }
///
/// impl IpcCommand for SearchCommand {
///     type Response = SearchResult;
///
///     fn name(&self) -> String {
///         "search".to_string()
///     }
///
///     async fn handle(&mut self) -> SearchResult {
///         let results = do_search(&self.query).await;
///         SearchResult { items: results }
///     }
/// }
/// ```
pub trait IpcCommand: Serialize + DeserializeOwned + Send + 'static {
    /// The response type returned by this command
    type Response: Serialize + DeserializeOwned + Send;

    /// Command name for wire protocol dispatch
    ///
    /// This name is used to route incoming requests to the correct handler.
    fn name(&self) -> String;

    /// Handle this command and produce a response
    ///
    /// The handler has mutable access to the command data, allowing it to
    /// modify state if needed during processing.
    fn handle(&mut self) -> impl Future<Output = Self::Response> + Send;
}
