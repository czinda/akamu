use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufWriter, Write};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
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

/// Writer for the systemd journal native datagram protocol, with optional
/// file-based JSONL backend for non-journald environments.
///
/// Connects to a journal namespace socket at
/// `/run/systemd/journal.{namespace}/socket`.  When the socket is unavailable
/// (development, CI, non-systemd hosts), [`Self::with_daemon`] spawns a lightweight
/// in-process listener, or [`Self::with_file`] writes append-only JSONL to a file.
#[derive(Debug)]
pub struct JournalWriter {
    socket: Option<UnixDatagram>,
    namespace: String,
    store: Option<Arc<Mutex<Vec<JournalEntry>>>>,
    log_file: Option<Mutex<BufWriter<File>>>,
    log_file_path: Option<PathBuf>,
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
            log_file: None,
            log_file_path: None,
            _tmpdir: None,
        }
    }

    /// Create a writer that appends audit events as JSON Lines to a file.
    ///
    /// Each event is a single-line JSON object flushed immediately after write
    /// (FAU_STG.1 — durable on each event).  The file is opened in append mode
    /// and created if it does not exist.
    pub fn with_file(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        tracing::info!(path, "opened audit log file (JSONL append mode)");
        Ok(Self {
            socket: None,
            namespace: String::new(),
            store: None,
            log_file: Some(Mutex::new(BufWriter::new(file))),
            log_file_path: Some(PathBuf::from(path)),
            _tmpdir: None,
        })
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
            log_file: None,
            log_file_path: None,
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
            log_file: None,
            log_file_path: None,
            _tmpdir: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.socket.is_some() || self.log_file.is_some()
    }

    /// Returns `true` when entries are queryable in-process (daemon store or
    /// file backend).
    pub fn has_store(&self) -> bool {
        self.store.is_some() || self.log_file_path.is_some()
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Send a structured journal entry as `KEY=VALUE` pairs.
    ///
    /// Dispatches to the appropriate backend: journal socket, JSONL file, or
    /// tracing fallback.
    pub fn send(&self, fields: &[(&str, &str)]) -> io::Result<()> {
        if let Some(ref sock) = self.socket {
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
            return Ok(());
        }

        if let Some(ref log_file) = self.log_file {
            return self.write_jsonl(log_file, fields);
        }

        self.fallback(fields);
        Ok(())
    }

    fn write_jsonl(
        &self,
        log_file: &Mutex<BufWriter<File>>,
        fields: &[(&str, &str)],
    ) -> io::Result<()> {
        let occurred_at = crate::util::rfc3339_now();
        let mut obj = serde_json::Map::new();
        obj.insert(
            "occurred_at".to_owned(),
            serde_json::Value::String(occurred_at),
        );
        for &(key, value) in fields {
            obj.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));
        }

        let line =
            serde_json::to_string(&serde_json::Value::Object(obj)).map_err(io::Error::other)?;

        let mut writer = log_file.lock().unwrap_or_else(|e| {
            tracing::error!("audit log file mutex poisoned");
            e.into_inner()
        });
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }

    /// Query for audit events.  Dispatches to the in-memory daemon store or
    /// the JSONL file backend depending on which is active.
    pub fn query(&self, q: &AuditQuery) -> Vec<AuditEventRow> {
        if self.store.is_some() {
            return self.query_store(q);
        }
        if let Some(ref path) = self.log_file_path {
            return self.query_file(path, q);
        }
        Vec::new()
    }

    fn query_store(&self, q: &AuditQuery) -> Vec<AuditEventRow> {
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
            .filter(|e| filter_entry(&e.occurred_at, &e.fields, q))
            .skip(q.offset as usize)
            .take(q.limit as usize)
            .map(|e| entry_to_row(&e.occurred_at, &e.fields))
            .collect()
    }

    fn query_file(&self, path: &Path, q: &AuditQuery) -> Vec<AuditEventRow> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "failed to open audit log for reading");
                return Vec::new();
            }
        };
        let reader = io::BufReader::new(file);
        let mut all: Vec<AuditEventRow> = reader
            .lines()
            .filter_map(|line| {
                let line = line.ok()?;
                let obj: serde_json::Value = serde_json::from_str(&line).ok()?;
                let map = obj.as_object()?;
                let occurred_at = map
                    .get("occurred_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned();
                let fields: HashMap<String, String> = map
                    .iter()
                    .filter(|(k, _)| k.as_str() != "occurred_at")
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                    .collect();
                if !filter_entry(&occurred_at, &fields, q) {
                    return None;
                }
                Some(entry_to_row(&occurred_at, &fields))
            })
            .collect();

        all.reverse();
        all.into_iter()
            .skip(q.offset as usize)
            .take(q.limit as usize)
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

fn filter_entry(occurred_at: &str, fields: &HashMap<String, String>, q: &AuditQuery) -> bool {
    if let Some(ref t) = q.event_type {
        if fields.get("AKAMU_EVENT_TYPE").map(|v| v.as_str()) != Some(t.as_str()) {
            return false;
        }
    }
    if let Some(ref s) = q.subject {
        if fields.get("AKAMU_SUBJECT").map(|v| v.as_str()) != Some(s.as_str()) {
            return false;
        }
    }
    if let Some(ref o) = q.outcome {
        if fields.get("AKAMU_OUTCOME").map(|v| v.as_str()) != Some(o.as_str()) {
            return false;
        }
    }
    if let Some(ref from) = q.from {
        if occurred_at < from.as_str() {
            return false;
        }
    }
    if let Some(ref until) = q.until {
        if occurred_at > until.as_str() {
            return false;
        }
    }
    true
}

fn entry_to_row(occurred_at: &str, fields: &HashMap<String, String>) -> AuditEventRow {
    AuditEventRow {
        occurred_at: occurred_at.to_owned(),
        event_type: fields.get("AKAMU_EVENT_TYPE").cloned().unwrap_or_default(),
        subject: fields.get("AKAMU_SUBJECT").cloned(),
        principal: fields.get("AKAMU_PRINCIPAL").cloned(),
        outcome: fields.get("AKAMU_OUTCOME").cloned().unwrap_or_default(),
        detail: fields.get("AKAMU_DETAIL").cloned(),
    }
}

/// Parse a journal native datagram into key-value pairs.
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
    fn file_backend_write_and_query_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let w = JournalWriter::with_file(path.to_str().unwrap()).unwrap();
        assert!(w.is_connected());
        assert!(w.has_store());

        w.send(&[
            ("AKAMU_EVENT_TYPE", "cert.issue"),
            ("AKAMU_OUTCOME", "success"),
            ("AKAMU_SUBJECT", "serial-123"),
            ("AKAMU_PRINCIPAL", "acme:test"),
        ])
        .unwrap();

        w.send(&[
            ("AKAMU_EVENT_TYPE", "auth.jws.fail"),
            ("AKAMU_OUTCOME", "failure"),
            ("AKAMU_SUBJECT", "thumb-xyz"),
        ])
        .unwrap();

        w.send(&[
            ("AKAMU_EVENT_TYPE", "cert.revoke"),
            ("AKAMU_OUTCOME", "success"),
            ("AKAMU_SUBJECT", "serial-456"),
        ])
        .unwrap();

        let all = w.query(&AuditQuery {
            event_type: None,
            subject: None,
            from: None,
            until: None,
            outcome: None,
            limit: 100,
            offset: 0,
        });
        assert_eq!(all.len(), 3);
        // newest first
        assert_eq!(all[0].event_type, "cert.revoke");
        assert_eq!(all[2].event_type, "cert.issue");

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
        assert_eq!(certs[0].subject.as_deref(), Some("serial-123"));

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

        // Verify file contains 3 JSONL lines
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 3);
        for line in content.lines() {
            let obj: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(obj.get("occurred_at").is_some());
            assert!(obj.get("AKAMU_EVENT_TYPE").is_some());
        }
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
