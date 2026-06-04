use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex};

// ── Query types ──────────────────────────────────────────────────────────────
// Defined here (not in audit.rs) so that journal is a leaf dependency — audit
// imports journal, but journal does not import audit.

/// A single audit event row returned from a journal query.
#[derive(Debug, Clone)]
pub struct AuditEventRow {
    pub occurred_at: String,
    pub event_type: String,
    pub subject: Option<String>,
    pub principal: Option<String>,
    pub outcome: String,
    pub detail: Option<String>,
}

/// Parameters for audit journal queries.
pub struct AuditQuery {
    pub event_type: Option<String>,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub until: Option<String>,
    pub outcome: Option<String>,
    pub limit: u32,
    pub offset: u32,
}

/// A received journal entry stored by the built-in daemon.
#[derive(Debug, Clone)]
struct JournalEntry {
    occurred_at: String,
    fields: HashMap<String, String>,
}

const DAEMON_STORE_CAP: usize = 100_000;

/// Writer for the systemd journal native datagram protocol.
///
/// Connects to a journal namespace socket at
/// `/run/systemd/journal.{namespace}/socket`.  When the socket is unavailable
/// (development, CI, non-systemd hosts), [`Self::with_daemon`] spawns a lightweight
/// in-process listener that stores entries in memory and supports filtered
/// queries without requiring `journalctl`.
#[derive(Debug)]
pub struct JournalWriter {
    socket: Option<UnixDatagram>,
    namespace: String,
    store: Option<Arc<Mutex<Vec<JournalEntry>>>>,
    _tmpdir: Option<tempfile::TempDir>,
}

impl JournalWriter {
    /// Connect to the journal namespace socket.  Falls back to tracing if the
    /// socket does not exist.
    pub fn new(namespace: &str) -> Self {
        let path = format!("/run/systemd/journal.{namespace}/socket");
        let socket = UnixDatagram::unbound()
            .and_then(|s| {
                s.connect(&path)?;
                Ok(s)
            })
            .ok();

        if socket.is_none() {
            tracing::warn!(
                namespace,
                path,
                "journal namespace socket not found — audit events will use tracing fallback",
            );
        } else {
            tracing::info!(namespace, path, "connected to journal namespace socket");
        }

        Self {
            socket,
            namespace: namespace.to_owned(),
            store: None,
            _tmpdir: None,
        }
    }

    /// Create a writer with a built-in in-process journal daemon.
    ///
    /// Spawns a background thread that receives datagrams on a temporary Unix
    /// socket and stores them in memory.  The entries are queryable via
    /// [`Self::query`].  Use this in tests and development environments where
    /// systemd-journald is not available.
    pub fn with_daemon() -> Self {
        let tmpdir = tempfile::tempdir().expect("failed to create temp dir for journal daemon");
        let socket_path = tmpdir.path().join("socket");

        let server =
            UnixDatagram::bind(&socket_path).expect("failed to bind journal daemon socket");

        let store = Arc::new(Mutex::new(Vec::<JournalEntry>::new()));
        let store_clone = Arc::clone(&store);

        std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            while let Ok(n) = server.recv(&mut buf) {
                let fields = parse_journal_datagram(&buf[..n]);
                let occurred_at = crate::util::rfc3339_now();
                let mut entries = store_clone.lock().unwrap_or_else(|e| {
                    tracing::error!("journal daemon store mutex poisoned");
                    e.into_inner()
                });
                if entries.len() >= DAEMON_STORE_CAP {
                    let drain_n = DAEMON_STORE_CAP / 10;
                    entries.drain(..drain_n);
                }
                entries.push(JournalEntry {
                    occurred_at,
                    fields,
                });
            }
        });

        let client = UnixDatagram::unbound().expect("failed to create client socket");
        client
            .connect(&socket_path)
            .expect("failed to connect to journal daemon socket");

        Self {
            socket: Some(client),
            namespace: String::new(),
            store: Some(store),
            _tmpdir: Some(tmpdir),
        }
    }

    /// Create a disconnected writer (for unit tests that only need the
    /// fallback path and do not query stored entries).
    pub fn disconnected() -> Self {
        Self {
            socket: None,
            namespace: String::new(),
            store: None,
            _tmpdir: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.socket.is_some()
    }

    /// Returns `true` when entries are stored in memory and queryable via
    /// [`Self::query`] (i.e., the built-in daemon is active).
    pub fn has_store(&self) -> bool {
        self.store.is_some()
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Send a structured journal entry as `KEY=VALUE` pairs.
    ///
    /// Values containing newlines use the binary length-prefix encoding
    /// required by the journal native protocol.
    pub fn send(&self, fields: &[(&str, &str)]) -> io::Result<()> {
        let Some(ref sock) = self.socket else {
            self.fallback(fields);
            return Ok(());
        };

        let mut buf = Vec::with_capacity(512);
        for &(key, value) in fields {
            if value.contains('\n') {
                buf.extend_from_slice(key.as_bytes());
                buf.push(b'\n');
                buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
                buf.extend_from_slice(value.as_bytes());
                buf.push(b'\n');
            } else {
                buf.extend_from_slice(key.as_bytes());
                buf.push(b'=');
                buf.extend_from_slice(value.as_bytes());
                buf.push(b'\n');
            }
        }

        sock.send(&buf)?;
        Ok(())
    }

    /// Query the in-memory store for audit events matching the given filters.
    ///
    /// Returns an empty vec if the built-in daemon is not active (`has_store()`
    /// is false).
    pub fn query(&self, q: &AuditQuery) -> Vec<AuditEventRow> {
        let Some(ref store) = self.store else {
            return Vec::new();
        };
        let entries = store.lock().unwrap_or_else(|e| {
            tracing::error!("journal store mutex poisoned — returning recovered state");
            e.into_inner()
        });

        entries
            .iter()
            .rev()
            .filter(|e| {
                if let Some(ref t) = q.event_type {
                    if e.fields.get("AKAMU_EVENT_TYPE").map(|v| v.as_str()) != Some(t.as_str()) {
                        return false;
                    }
                }
                if let Some(ref s) = q.subject {
                    if e.fields.get("AKAMU_SUBJECT").map(|v| v.as_str()) != Some(s.as_str()) {
                        return false;
                    }
                }
                if let Some(ref o) = q.outcome {
                    if e.fields.get("AKAMU_OUTCOME").map(|v| v.as_str()) != Some(o.as_str()) {
                        return false;
                    }
                }
                if let Some(ref from) = q.from {
                    if e.occurred_at.as_str() < from.as_str() {
                        return false;
                    }
                }
                if let Some(ref until) = q.until {
                    if e.occurred_at.as_str() > until.as_str() {
                        return false;
                    }
                }
                true
            })
            .skip(q.offset as usize)
            .take(q.limit as usize)
            .map(|e| AuditEventRow {
                occurred_at: e.occurred_at.clone(),
                event_type: e
                    .fields
                    .get("AKAMU_EVENT_TYPE")
                    .cloned()
                    .unwrap_or_default(),
                subject: e.fields.get("AKAMU_SUBJECT").cloned(),
                principal: e.fields.get("AKAMU_PRINCIPAL").cloned(),
                outcome: e.fields.get("AKAMU_OUTCOME").cloned().unwrap_or_default(),
                detail: e.fields.get("AKAMU_DETAIL").cloned(),
            })
            .collect()
    }

    fn fallback(&self, fields: &[(&str, &str)]) {
        let mut event_type = "";
        let mut outcome = "";
        let mut subject = "";
        let mut principal = "";
        let mut detail = "";

        for &(k, v) in fields {
            match k {
                "AKAMU_EVENT_TYPE" => event_type = v,
                "AKAMU_OUTCOME" => outcome = v,
                "AKAMU_SUBJECT" => subject = v,
                "AKAMU_PRINCIPAL" => principal = v,
                "AKAMU_DETAIL" => detail = v,
                _ => {}
            }
        }

        tracing::info!(
            target: "akamu_audit",
            event_type,
            outcome,
            subject,
            principal,
            detail,
            "audit event (journal fallback)",
        );
    }
}

/// Parse a journal native datagram into key-value pairs.
///
/// Handles both the simple `KEY=VALUE\n` format and the binary encoding
/// `KEY\n<8-byte LE length><value>\n` for values containing newlines.
fn parse_journal_datagram(data: &[u8]) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let mut pos = 0;

    while pos < data.len() {
        let key_end = data[pos..]
            .iter()
            .position(|&b| b == b'=' || b == b'\n')
            .map(|i| pos + i)
            .unwrap_or(data.len());

        if key_end >= data.len() {
            break;
        }

        let key = String::from_utf8_lossy(&data[pos..key_end]).into_owned();

        if data[key_end] == b'=' {
            let val_start = key_end + 1;
            let val_end = data[val_start..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|i| val_start + i)
                .unwrap_or(data.len());
            let value = String::from_utf8_lossy(&data[val_start..val_end]).into_owned();
            fields.insert(key, value);
            pos = val_end + 1;
        } else {
            // Binary encoding: KEY\n<8-byte LE length><value>\n
            let len_start = key_end + 1;
            if len_start + 8 > data.len() {
                break;
            }
            let raw_len = u64::from_le_bytes(data[len_start..len_start + 8].try_into().unwrap());
            let Some(value_len) = usize::try_from(raw_len).ok() else {
                break;
            };
            let val_start = len_start + 8;
            let val_end = val_start + value_len;
            if val_end > data.len() {
                break;
            }
            let value = String::from_utf8_lossy(&data[val_start..val_end]).into_owned();
            fields.insert(key, value);
            pos = if val_end < data.len() && data[val_end] == b'\n' {
                val_end + 1
            } else {
                val_end
            };
        }
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_send_does_not_panic() {
        let w = JournalWriter::disconnected();
        assert!(!w.is_connected());
        assert!(!w.has_store());
        w.send(&[
            ("AKAMU_EVENT_TYPE", "cert.issue"),
            ("AKAMU_OUTCOME", "success"),
        ])
        .unwrap();
    }

    #[test]
    fn daemon_write_and_query_round_trip() {
        let w = JournalWriter::with_daemon();
        assert!(w.is_connected());
        assert!(w.has_store());

        w.send(&[
            ("SYSLOG_IDENTIFIER", "akamu-audit"),
            ("AKAMU_EVENT_TYPE", "cert.issue"),
            ("AKAMU_OUTCOME", "success"),
            ("AKAMU_SUBJECT", "serial-abc"),
            ("AKAMU_PRINCIPAL", "acme:thumb"),
        ])
        .unwrap();

        w.send(&[
            ("SYSLOG_IDENTIFIER", "akamu-audit"),
            ("AKAMU_EVENT_TYPE", "auth.jws.fail"),
            ("AKAMU_OUTCOME", "failure"),
        ])
        .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        let all = w.query(&AuditQuery {
            event_type: None,
            subject: None,
            from: None,
            until: None,
            outcome: None,
            limit: 100,
            offset: 0,
        });
        assert_eq!(all.len(), 2, "expected 2 entries, got {}", all.len());

        let certs = w.query(&AuditQuery {
            event_type: Some("cert.issue".to_owned()),
            subject: None,
            from: None,
            until: None,
            outcome: None,
            limit: 100,
            offset: 0,
        });
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].event_type, "cert.issue");
        assert_eq!(certs[0].subject.as_deref(), Some("serial-abc"));
        assert_eq!(certs[0].principal.as_deref(), Some("acme:thumb"));

        let failures = w.query(&AuditQuery {
            event_type: None,
            subject: None,
            from: None,
            until: None,
            outcome: Some("failure".to_owned()),
            limit: 100,
            offset: 0,
        });
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].event_type, "auth.jws.fail");
    }

    #[test]
    fn daemon_handles_binary_encoded_values() {
        let w = JournalWriter::with_daemon();

        w.send(&[
            ("AKAMU_EVENT_TYPE", "admin.action"),
            ("AKAMU_OUTCOME", "success"),
            ("AKAMU_DETAIL", "line1\nline2"),
        ])
        .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        let rows = w.query(&AuditQuery {
            event_type: Some("admin.action".to_owned()),
            subject: None,
            from: None,
            until: None,
            outcome: None,
            limit: 100,
            offset: 0,
        });
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].detail.as_deref(), Some("line1\nline2"));
    }

    #[test]
    fn parse_simple_datagram() {
        let data = b"KEY=val\nOTHER=x\n";
        let fields = parse_journal_datagram(data);
        assert_eq!(fields.get("KEY").unwrap(), "val");
        assert_eq!(fields.get("OTHER").unwrap(), "x");
    }

    #[test]
    fn parse_binary_datagram() {
        let value = "line1\nline2";
        let mut data = Vec::new();
        data.extend_from_slice(b"DETAIL");
        data.push(b'\n');
        data.extend_from_slice(&(value.len() as u64).to_le_bytes());
        data.extend_from_slice(value.as_bytes());
        data.push(b'\n');
        data.extend_from_slice(b"OTHER=ok\n");

        let fields = parse_journal_datagram(&data);
        assert_eq!(fields.get("DETAIL").unwrap(), "line1\nline2");
        assert_eq!(fields.get("OTHER").unwrap(), "ok");
    }
}
