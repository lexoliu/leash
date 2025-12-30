//! Wire protocol types for IPC
//!
//! Wire format:
//! ```text
//! Request:
//!   [4 bytes: total length (u32 BE)]
//!   [1 byte: method length (u8)]
//!   [method bytes (UTF-8)]
//!   [params bytes (MessagePack)]
//!
//! Response:
//!   [4 bytes: total length (u32 BE)]
//!   [1 byte: success flag (0 or 1)]
//!   [payload bytes (MessagePack result or error string)]
//! ```

use std::io;

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Errors that can occur during IPC operations
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("IPC not enabled")]
    NotEnabled,

    #[error("unknown method: {0}")]
    UnknownMethod(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] rmp_serde::encode::Error),

    #[error("deserialization error: {0}")]
    Deserialization(#[from] rmp_serde::decode::Error),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),

    #[error("handler error: {0}")]
    Handler(String),
}

/// Request parsed from wire format
#[derive(Debug)]
pub struct IpcRequest {
    /// Method name
    pub method: String,
    /// Raw MessagePack params (not yet deserialized)
    pub params: Vec<u8>,
}

impl IpcRequest {
    /// Parse a request from raw bytes
    ///
    /// Format: [method_len: u8][method: bytes][params: bytes]
    pub fn from_bytes(data: &[u8]) -> Result<Self, IpcError> {
        if data.is_empty() {
            return Err(IpcError::InvalidProtocol("empty request".to_string()));
        }

        let method_len = data[0] as usize;
        if data.len() < 1 + method_len {
            return Err(IpcError::InvalidProtocol("truncated method".to_string()));
        }

        let method = String::from_utf8(data[1..1 + method_len].to_vec())
            .map_err(|e| IpcError::InvalidProtocol(format!("invalid method UTF-8: {e}")))?;

        let params = data[1 + method_len..].to_vec();

        Ok(Self { method, params })
    }

    /// Serialize a request to wire format
    pub fn to_bytes<T: Serialize>(method: &str, params: &T) -> Result<Vec<u8>, IpcError> {
        let method_bytes = method.as_bytes();
        if method_bytes.len() > 255 {
            return Err(IpcError::InvalidProtocol("method name too long".to_string()));
        }

        let params_bytes = rmp_serde::to_vec(params)?;

        let total_len = 1 + method_bytes.len() + params_bytes.len();
        let mut buf = Vec::with_capacity(4 + total_len);

        // Total length (u32 BE)
        buf.extend_from_slice(&(total_len as u32).to_be_bytes());
        // Method length (u8)
        buf.push(method_bytes.len() as u8);
        // Method
        buf.extend_from_slice(method_bytes);
        // Params
        buf.extend_from_slice(&params_bytes);

        Ok(buf)
    }

    /// Deserialize params into a typed command
    pub fn deserialize_params<T: DeserializeOwned>(&self) -> Result<T, IpcError> {
        rmp_serde::from_slice(&self.params).map_err(IpcError::from)
    }
}

/// Response to be sent over wire
#[derive(Debug)]
pub struct IpcResponse {
    /// Whether the request succeeded
    pub success: bool,
    /// Raw MessagePack payload (result or error)
    pub payload: Vec<u8>,
}

impl IpcResponse {
    /// Create a success response with the given result
    pub fn success<T: Serialize>(result: &T) -> Result<Self, IpcError> {
        Ok(Self {
            success: true,
            payload: rmp_serde::to_vec(result)?,
        })
    }

    /// Create an error response
    pub fn error(message: &str) -> Result<Self, IpcError> {
        Ok(Self {
            success: false,
            payload: rmp_serde::to_vec(&message)?,
        })
    }

    /// Serialize to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_len = 1 + self.payload.len();
        let mut buf = Vec::with_capacity(4 + total_len);

        // Total length (u32 BE)
        buf.extend_from_slice(&(total_len as u32).to_be_bytes());
        // Success flag
        buf.push(if self.success { 1 } else { 0 });
        // Payload
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Parse a response from raw bytes (after length prefix)
    pub fn from_bytes(data: &[u8]) -> Result<Self, IpcError> {
        if data.is_empty() {
            return Err(IpcError::InvalidProtocol("empty response".to_string()));
        }

        let success = data[0] == 1;
        let payload = data[1..].to_vec();

        Ok(Self { success, payload })
    }

    /// Deserialize the payload as the given type
    pub fn deserialize_payload<T: DeserializeOwned>(&self) -> Result<T, IpcError> {
        rmp_serde::from_slice(&self.payload).map_err(IpcError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestParams {
        query: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestResult {
        items: Vec<String>,
    }

    #[test]
    fn test_request_roundtrip() {
        let params = TestParams {
            query: "hello".to_string(),
        };

        let bytes = IpcRequest::to_bytes("search", &params).unwrap();
        // Skip the 4-byte length prefix
        let request = IpcRequest::from_bytes(&bytes[4..]).unwrap();

        assert_eq!(request.method, "search");
        let decoded: TestParams = request.deserialize_params().unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn test_response_success_roundtrip() {
        let result = TestResult {
            items: vec!["a".to_string(), "b".to_string()],
        };

        let response = IpcResponse::success(&result).unwrap();
        let bytes = response.to_bytes();
        // Skip the 4-byte length prefix
        let parsed = IpcResponse::from_bytes(&bytes[4..]).unwrap();

        assert!(parsed.success);
        let decoded: TestResult = parsed.deserialize_payload().unwrap();
        assert_eq!(decoded, result);
    }

    #[test]
    fn test_response_error_roundtrip() {
        let response = IpcResponse::error("something went wrong").unwrap();
        let bytes = response.to_bytes();
        // Skip the 4-byte length prefix
        let parsed = IpcResponse::from_bytes(&bytes[4..]).unwrap();

        assert!(!parsed.success);
        let message: String = parsed.deserialize_payload().unwrap();
        assert_eq!(message, "something went wrong");
    }
}
