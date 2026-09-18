//! Best-effort, bounded extraction of provider-reported usage from SSE.
//! Only metadata is retained in the log; response bytes are never rewritten.

use crate::errors::Dialect;

const MAX_EVENT_BYTES: usize = 64 * 1024;

pub(crate) fn counter(value: Option<&serde_json::Value>) -> Option<i64> {
    value.and_then(serde_json::Value::as_i64).filter(|n| *n >= 0)
}

pub(crate) fn buffered(bytes: &[u8], dialect: Dialect) -> (Option<String>, Option<i64>, Option<i64>) {
    // `finish` already caps the buffered body; this is a second cap on JSON
    // parsing and never changes the body returned to the client.
    if bytes.len() > 25 * 1024 * 1024 {
        return (None, None, None);
    }
    let Ok(serde_json::Value::Object(obj)) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return (None, None, None);
    };
    let model = obj.get("model").and_then(serde_json::Value::as_str).map(str::to_owned);
    let usage = obj.get("usage");
    let (in_key, out_key) = match dialect {
        Dialect::OpenAi => ("prompt_tokens", "completion_tokens"),
        Dialect::Anthropic => ("input_tokens", "output_tokens"),
    };
    (model, counter(usage.and_then(|u| u.get(in_key))), counter(usage.and_then(|u| u.get(out_key))))
}

pub(crate) struct SseUsage {
    dialect: Dialect,
    line: Vec<u8>,
    event: Vec<u8>,
    discarding: bool,
    pub(crate) tokens_in: Option<i64>,
    pub(crate) tokens_out: Option<i64>,
}

impl SseUsage {
    pub(crate) fn new(dialect: Dialect) -> Self {
        Self { dialect, line: Vec::new(), event: Vec::new(), discarding: false, tokens_in: None, tokens_out: None }
    }

    pub(crate) fn observe(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                let line = std::mem::take(&mut self.line);
                let line = line.strip_suffix(b"\r").unwrap_or(&line);
                if line.is_empty() {
                    if !self.discarding {
                        self.parse_event();
                    }
                    self.event.clear();
                    self.discarding = false;
                } else if !self.discarding {
                    if self.event.len() + line.len() < MAX_EVENT_BYTES {
                        self.event.extend_from_slice(line);
                        self.event.push(b'\n');
                    } else {
                        self.event.clear();
                        self.discarding = true;
                    }
                }
            } else if self.line.len() < MAX_EVENT_BYTES {
                self.line.push(byte);
            } else {
                self.line.clear();
                self.event.clear();
                self.discarding = true;
            }
        }
    }

    fn parse_event(&mut self) {
        let mut event_name = None;
        let mut data = Vec::new();
        for line in self.event.split(|b| *b == b'\n') {
            if let Some(value) = line.strip_prefix(b"event:") {
                event_name = std::str::from_utf8(value.trim_ascii()).ok();
            } else if let Some(value) = line.strip_prefix(b"data:") {
                if !data.is_empty() { data.push(b'\n'); }
                data.extend_from_slice(value.trim_ascii_start());
            }
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&data) else { return; };
        let usage = match self.dialect {
            Dialect::OpenAi => value.get("usage"),
            Dialect::Anthropic if event_name == Some("message_start") => value.get("message").and_then(|m| m.get("usage")),
            Dialect::Anthropic if event_name == Some("message_delta") => value.get("usage"),
            Dialect::Anthropic => None,
        };
        let (in_key, out_key) = match self.dialect {
            Dialect::OpenAi => ("prompt_tokens", "completion_tokens"),
            Dialect::Anthropic => ("input_tokens", "output_tokens"),
        };
        if let Some(n) = counter(usage.and_then(|u| u.get(in_key))) { self.tokens_in = Some(n); }
        if let Some(n) = counter(usage.and_then(|u| u.get(out_key))) { self.tokens_out = Some(n); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffered_usage_is_dialect_specific_and_zero_is_reported() {
        let openai = br#"{"model":"m","usage":{"prompt_tokens":7,"completion_tokens":0}}"#;
        assert_eq!(buffered(openai, Dialect::OpenAi), (Some("m".into()), Some(7), Some(0)));
        assert_eq!(buffered(openai, Dialect::Anthropic), (Some("m".into()), None, None));
        let anthropic = br#"{"model":"m","usage":{"input_tokens":4,"output_tokens":2}}"#;
        assert_eq!(buffered(anthropic, Dialect::Anthropic), (Some("m".into()), Some(4), Some(2)));
        assert_eq!(buffered(br#"{"model":"m"}"#, Dialect::OpenAi), (Some("m".into()), None, None));
        assert_eq!(buffered(br#"{"usage":{"prompt_tokens":-1}}"#, Dialect::OpenAi), (None, None, None));
    }

    #[test]
    fn openai_sse_usage_survives_one_byte_chunks_and_missing_usage() {
        let mut parser = SseUsage::new(Dialect::OpenAi);
        for byte in b"data: {\"choices\":[{\"delta\":{\"content\":\"secret\"}}]}\r\n\r\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":0}}\r\n\r\ndata: [DONE]\n\n" {
            parser.observe(std::slice::from_ref(byte));
        }
        assert_eq!((parser.tokens_in, parser.tokens_out), (Some(7), Some(0)));
        let mut missing = SseUsage::new(Dialect::OpenAi);
        missing.observe(b"data: {\"choices\":[]}\n\ndata: [DONE]\n\n");
        assert_eq!((missing.tokens_in, missing.tokens_out), (None, None));
    }

    #[test]
    fn anthropic_sse_merges_start_and_delta_counters() {
        let mut parser = SseUsage::new(Dialect::Anthropic);
        parser.observe(b"event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n");
        parser.observe(b"event: message_delta\ndata: {\"usage\":{\"output_tokens\":2}}\n\n");
        assert_eq!((parser.tokens_in, parser.tokens_out), (Some(4), Some(2)));
    }

    #[test]
    fn oversized_event_is_discarded_without_poisoning_next_event() {
        let mut parser = SseUsage::new(Dialect::OpenAi);
        let mut oversized = b"data: ".to_vec();
        oversized.extend(vec![b'x'; MAX_EVENT_BYTES]);
        oversized.extend_from_slice(b"\n\ndata: {\"usage\":{\"prompt_tokens\":3}}\n\n");
        parser.observe(&oversized);
        assert_eq!((parser.tokens_in, parser.tokens_out), (Some(3), None));
    }
}
