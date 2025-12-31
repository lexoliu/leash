use napi_derive::napi;

/// IPC router for handling commands from sandboxed processes
///
/// Note: IPC support in the Node.js binding is currently limited.
/// For full IPC functionality, use the Rust library directly.
#[napi]
pub struct IpcRouterJs {
    methods: Vec<String>,
}

#[napi]
impl IpcRouterJs {
    /// Create a new empty IPC router
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            methods: Vec::new(),
        }
    }

    /// Get the list of registered method names
    #[napi]
    pub fn methods(&self) -> Vec<String> {
        self.methods.clone()
    }
}

impl Default for IpcRouterJs {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to create an IPC router (factory function for cleaner API)
#[napi]
pub fn create_ipc_router() -> IpcRouterJs {
    IpcRouterJs::new()
}
