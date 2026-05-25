use ethers::providers::{HttpClientError, HttpRateLimitRetryPolicy, RetryPolicy};
use reqwest::StatusCode;
use std::time::Duration;

/// Retry policy that broadens ethers' built-in `HttpRateLimitRetryPolicy` to
/// cover the transient errors that are most common when talking to a chain
/// RPC through a reverse proxy:
///
/// - reqwest connection / timeout errors
/// - any HTTP 5xx (502 / 503 / 504 are routinely emitted by openresty/nginx
///   when the upstream node restarts or briefly stalls)
/// - SerdeJson deserialization failures whose body is HTML — i.e. a proxy
///   returned an error page instead of a JSON-RPC envelope
///
/// Everything narrower (specifically: HTTP 429, the rate-limit JSON-RPC
/// error codes, and JsonRpcError envelopes hidden inside a SerdeJson body)
/// is delegated to `HttpRateLimitRetryPolicy` so we don't drop existing
/// behaviour on the floor.
#[derive(Debug)]
pub struct TransientRpcRetryPolicy;

impl RetryPolicy<HttpClientError> for TransientRpcRetryPolicy {
    fn should_retry(&self, error: &HttpClientError) -> bool {
        match error {
            HttpClientError::ReqwestError(err) => {
                if err.is_timeout() || err.is_connect() {
                    return true;
                }
                if let Some(status) = err.status() {
                    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
                        return true;
                    }
                }
            }
            HttpClientError::SerdeJson { text, .. } => {
                // HTML body = a proxy returned its own error page (e.g.
                // "<html>...502 Bad Gateway...openresty..."). Always
                // transient.
                if text.trim_start().starts_with('<') {
                    return true;
                }
            }
            _ => {}
        }
        // Fall through to the narrow rate-limit policy for the cases we
        // haven't broadened (HTTP 429, JSON-RPC rate-limit codes, etc.).
        HttpRateLimitRetryPolicy.should_retry(error)
    }

    fn backoff_hint(&self, error: &HttpClientError) -> Option<Duration> {
        HttpRateLimitRetryPolicy.backoff_hint(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::providers::JsonRpcError;

    /// Build a `SerdeJson` variant with an arbitrary `text` body. The error
    /// itself is produced by deliberately failing to parse the text as
    /// `()` — which only accepts `null`, so any other input yields a real
    /// `serde_json::Error`. The text we put into the variant is decoupled
    /// from the parse attempt, so it can be anything.
    fn serde_json_error(text: &str) -> HttpClientError {
        let err = serde_json::from_str::<()>("invalid").expect_err("must not parse");
        HttpClientError::SerdeJson {
            err,
            text: text.to_string(),
        }
    }

    #[test]
    fn retries_on_html_body() {
        let err = serde_json_error("<html><head><title>502 Bad Gateway</title></head></html>");
        assert!(TransientRpcRetryPolicy.should_retry(&err));
    }

    #[test]
    fn retries_on_html_body_with_leading_whitespace() {
        let err = serde_json_error("   \n<html>oops</html>");
        assert!(TransientRpcRetryPolicy.should_retry(&err));
    }

    #[test]
    fn does_not_retry_on_genuinely_malformed_json() {
        // Body parses as nothing useful but isn't an HTML page either —
        // probably a real bug, don't retry.
        let err = serde_json_error("not json, not html, just garbage");
        assert!(!TransientRpcRetryPolicy.should_retry(&err));
    }

    #[test]
    fn delegates_to_inner_for_jsonrpc_envelope_in_serdejson_text() {
        // Even though the body fails strict JSON-RPC parsing, the inner
        // policy recognises the embedded JsonRpcError with a known
        // rate-limit message and retries.
        let body = r#"{"error":{"code":-32005,"message":"limit"}}"#;
        let err = serde_json_error(body);
        assert!(TransientRpcRetryPolicy.should_retry(&err));
    }

    #[test]
    fn retries_on_rate_limit_jsonrpc_code() {
        let err = HttpClientError::JsonRpcError(JsonRpcError {
            code: -32005,
            message: "project rate limit".into(),
            data: None,
        });
        assert!(TransientRpcRetryPolicy.should_retry(&err));
    }

    #[test]
    fn does_not_retry_on_unknown_jsonrpc_error() {
        let err = HttpClientError::JsonRpcError(JsonRpcError {
            code: -32000,
            message: "execution reverted".into(),
            data: None,
        });
        assert!(!TransientRpcRetryPolicy.should_retry(&err));
    }
}
