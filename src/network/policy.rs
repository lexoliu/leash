use std::collections::HashSet;
use std::future::Future;
use std::marker::PhantomData;

/// Direction of a network connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

/// Information about a network access request
#[derive(Debug, Clone)]
pub struct DomainRequest {
    target: String,
    port: u16,
    direction: ConnectionDirection,
    pid: u32,
}

impl DomainRequest {
    /// Create a new domain request (internal use)
    pub(crate) fn new(target: String, port: u16, direction: ConnectionDirection, pid: u32) -> Self {
        Self {
            target,
            port,
            direction,
            pid,
        }
    }

    /// The domain or IP being accessed
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The port number
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The direction of the connection
    pub fn direction(&self) -> ConnectionDirection {
        self.direction
    }

    /// The process ID making the request
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

/// Async network policy trait - determines if a connection is allowed
pub trait NetworkPolicy: Send + Sync + 'static {
    /// Check if a network request should be allowed
    fn check(&self, request: &DomainRequest) -> impl Future<Output = bool> + Send;
}

/// Deny all network access (default policy)
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl NetworkPolicy for DenyAll {
    async fn check(&self, _request: &DomainRequest) -> bool {
        false
    }
}

/// Allow all network access
#[derive(Debug, Clone, Copy)]
pub struct AllowAll;

impl NetworkPolicy for AllowAll {
    async fn check(&self, _request: &DomainRequest) -> bool {
        true
    }
}

/// Allow access to specific domains only
pub struct AllowList {
    allowed: HashSet<String>,
}

impl AllowList {
    /// Create a new allow list from an iterator of domains
    pub fn new(domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowed: domains.into_iter().map(Into::into).collect(),
        }
    }

    /// Check if a domain matches the allow list
    fn matches(&self, target: &str) -> bool {
        // Exact match
        if self.allowed.contains(target) {
            return true;
        }

        // Subdomain match (e.g., "api.example.com" matches "*.example.com")
        for allowed in &self.allowed {
            if allowed.starts_with("*.") {
                let suffix = &allowed[1..]; // ".example.com"
                if target.ends_with(suffix) {
                    return true;
                }
            }
        }

        false
    }
}

impl NetworkPolicy for AllowList {
    async fn check(&self, request: &DomainRequest) -> bool {
        self.matches(request.target())
    }
}

/// Custom async policy with user-provided handler function
pub struct CustomPolicy<F, Fut>
where
    F: Fn(&DomainRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + Sync + 'static,
{
    handler: F,
    _marker: PhantomData<fn() -> Fut>,
}

impl<F, Fut> CustomPolicy<F, Fut>
where
    F: Fn(&DomainRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + Sync + 'static,
{
    /// Create a new custom policy with the given handler function
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            _marker: PhantomData,
        }
    }
}

impl<F, Fut> NetworkPolicy for CustomPolicy<F, Fut>
where
    F: Fn(&DomainRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + Sync + 'static,
{
    async fn check(&self, request: &DomainRequest) -> bool {
        (self.handler)(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deny_all() {
        let policy = DenyAll;
        let request = DomainRequest::new(
            "example.com".to_string(),
            443,
            ConnectionDirection::Outbound,
            1234,
        );

        assert!(!policy.check(&request).await);
    }

    #[tokio::test]
    async fn test_allow_all() {
        let policy = AllowAll;
        let request = DomainRequest::new(
            "example.com".to_string(),
            443,
            ConnectionDirection::Outbound,
            1234,
        );

        assert!(policy.check(&request).await);
    }

    #[test]
    fn test_allow_list_exact() {
        let policy = AllowList::new(["example.com", "api.test.com"]);

        assert!(policy.matches("example.com"));
        assert!(policy.matches("api.test.com"));
        assert!(!policy.matches("other.com"));
        assert!(!policy.matches("sub.example.com"));
    }

    #[test]
    fn test_allow_list_wildcard() {
        let policy = AllowList::new(["*.example.com"]);

        assert!(policy.matches("api.example.com"));
        assert!(policy.matches("sub.api.example.com"));
        assert!(!policy.matches("example.com")); // Exact domain not matched by wildcard
        assert!(!policy.matches("other.com"));
    }
}
