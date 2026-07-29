use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufWriter, Write};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
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
#[derive(Debug)]
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

/// Maximum number of JSONL lines scanned per file query to prevent unbounded
/// reads on a file that has not been rotated.
const MAX_QUERY_LINES: usize = 500_000;

enum FileCmd {
    Write {
        occurred_at: String,
        fields: Vec<(String, String)>,
    },
    Flush {
        ack: mpsc::Sender<()>,
    },
}

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
    store: Option<Arc<Mutex<VecDeque<JournalEntry>>>>,
    file_tx: Option<mpsc::Sender<FileCmd>>,
    log_file_path: Option<PathBuf>,
    /// Held to keep the temporary directory alive for the daemon socket.
    /// Requires `tempfile` as a non-dev dependency because `TempDir` is a
    /// struct field, not just used in tests.
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
            tracing::info!(
                namespace,
                path,
                "journal namespace socket not found — audit events will be logged via tracing",
            );
        } else {
            tracing::info!(namespace, path, "connected to journal namespace socket");
        }

        Self {
            socket,
            namespace: namespace.to_owned(),
            store: None,
            file_tx: None,
            log_file_path: None,
            _tmpdir: None,
        }
    }

    /// Create a writer that appends audit events as JSON Lines to a file.
    ///
    /// A background thread receives events via an unbounded channel and writes
    /// them sequentially, flushing after each event (FAU_STG.1 — durable on
    /// each event).  `send()` returns as soon as the event is enqueued, so
    /// audit I/O does not block the request path.
    ///
    /// The file is opened in append mode and created if it does not exist.
    /// The file grows without bound; external log rotation (e.g. `logrotate(8)`
    /// with `copytruncate`) is expected for long-running deployments.  Queries
    /// scan at most 500 000 lines from the file to bound read cost.
    pub fn with_file(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        tracing::info!(path, "opened audit log file (JSONL append mode)");

        let (tx, rx) = mpsc::channel::<FileCmd>();
        std::thread::spawn(move || {
            file_writer_loop(rx, file);
        });

        Ok(Self {
            socket: None,
            namespace: String::new(),
            store: None,
            file_tx: Some(tx),
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

        let store = Arc::new(Mutex::new(VecDeque::<JournalEntry>::new()));
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
                    tracing::warn!(
                        evicted = drain_n,
                        cap = DAEMON_STORE_CAP,
                        "daemon store full — evicting oldest entries"
                    );
                    entries.drain(..drain_n);
                }
                entries.push_back(JournalEntry {
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
            file_tx: None,
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
            file_tx: None,
            log_file_path: None,
            _tmpdir: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn broken() -> Self {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let socket_path = tmpdir.path().join("socket");
        let server = UnixDatagram::bind(&socket_path).expect("bind");
        let client = UnixDatagram::unbound().expect("client");
        client.connect(&socket_path).expect("connect");
        drop(server);
        std::fs::remove_file(&socket_path).expect("remove");
        // Give the kernel time to process the peer close so that subsequent
        // sends reliably return ECONNREFUSED instead of buffering.
        std::thread::sleep(std::time::Duration::from_millis(10));
        Self {
            socket: Some(client),
            namespace: String::new(),
            store: None,
            file_tx: None,
            log_file_path: None,
            _tmpdir: Some(tmpdir),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.socket.is_some() || self.file_tx.is_some()
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
    ///
    /// Uses synchronous I/O intentionally: local Unix datagram sends and file
    /// writes are sub-microsecond on local filesystems and do not warrant the
    /// overhead of `spawn_blocking` or async I/O.
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

        if let Some(ref tx) = self.file_tx {
            let occurred_at = crate::util::rfc3339_now();
            let owned: Vec<(String, String)> = fields
                .iter()
                .map(|&(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
            tx.send(FileCmd::Write {
                occurred_at,
                fields: owned,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "audit writer thread gone"))?;
            return Ok(());
        }

        self.fallback(fields);
        Ok(())
    }

    /// Query for audit events.  Dispatches to the in-memory daemon store or
    /// the JSONL file backend depending on which is active.
    pub fn query(&self, q: &AuditQuery) -> Result<Vec<AuditEventRow>, io::Error> {
        if self.store.is_some() {
            return Ok(self.query_store(q));
        }
        if let Some(ref path) = self.log_file_path {
            return self.query_file(path, q);
        }
        Ok(Vec::new())
    }

    fn query_store(&self, q: &AuditQuery) -> Vec<AuditEventRow> {
        let Some(ref store) = self.store else {
            return Vec::new();
        };
        let entries = store.lock().unwrap_or_else(|e| {
            tracing::error!("journal daemon store mutex poisoned");
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

    fn query_file(&self, path: &Path, q: &AuditQuery) -> Result<Vec<AuditEventRow>, io::Error> {
        // Drain the background writer before reading to avoid partial-line races.
        if let Some(ref tx) = self.file_tx {
            let (ack_tx, ack_rx) = mpsc::channel();
            tx.send(FileCmd::Flush { ack: ack_tx }).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "audit writer thread gone")
            })?;
            ack_rx.recv().map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "audit writer thread gone")
            })?;
        }

        let file = File::open(path)?;
        let reader = io::BufReader::new(file);
        let mut skipped: usize = 0;
        let mut all: Vec<AuditEventRow> = reader
            .lines()
            .take(MAX_QUERY_LINES)
            .enumerate()
            .filter_map(|(line_no, line)| {
                let line = match line {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::warn!(line = line_no + 1, error = %e, "skipping unreadable JSONL line");
                        skipped += 1;
                        return None;
                    }
                };
                if line.is_empty() {
                    return None;
                }
                let obj: serde_json::Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(line = line_no + 1, error = %e, "skipping malformed JSONL line");
                        skipped += 1;
                        return None;
                    }
                };
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

        if skipped > 0 {
            tracing::warn!(skipped, "JSONL query skipped malformed/unreadable lines");
        }

        all.reverse();
        Ok(all
            .into_iter()
            .skip(q.offset as usize)
            .take(q.limit as usize)
            .collect())
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
            "audit event",
        );
    }
}

fn file_writer_loop(rx: mpsc::Receiver<FileCmd>, file: File) {
    let mut writer = BufWriter::new(file);
    while let Ok(cmd) = rx.recv() {
        match cmd {
            FileCmd::Write {
                occurred_at,
                fields,
            } => {
                let mut obj = serde_json::Map::new();
                obj.insert(
                    "occurred_at".to_owned(),
                    serde_json::Value::String(occurred_at),
                );
                for (key, value) in fields {
                    obj.insert(key, serde_json::Value::String(value));
                }
                match serde_json::to_string(&serde_json::Value::Object(obj)) {
                    Ok(line) => {
                        if let Err(e) = writer
                            .write_all(line.as_bytes())
                            .and_then(|()| writer.write_all(b"\n"))
                            .and_then(|()| writer.flush())
                        {
                            tracing::error!(error = %e, "audit file write failed — event may be lost");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "audit event JSON serialization failed — event lost");
                    }
                }
            }
            FileCmd::Flush { ack } => {
                if let Err(e) = writer.flush() {
                    tracing::error!(error = %e, "audit file flush failed");
                }
                let _ = ack.send(());
            }
        }
    }
    if let Err(e) = writer.flush() {
        tracing::error!(error = %e, "audit file final flush failed");
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

        let all = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert_eq!(all.len(), 2, "expected 2 entries, got {}", all.len());

        let certs = w
            .query(&AuditQuery {
                event_type: Some("cert.issue".to_owned()),
                subject: None,
                from: None,
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].event_type, "cert.issue");
        assert_eq!(certs[0].subject.as_deref(), Some("serial-abc"));
        assert_eq!(certs[0].principal.as_deref(), Some("acme:thumb"));

        let failures = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: None,
                outcome: Some("failure".to_owned()),
                limit: 100,
                offset: 0,
            })
            .unwrap();
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

        let rows = w
            .query(&AuditQuery {
                event_type: Some("admin.action".to_owned()),
                subject: None,
                from: None,
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
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

        let all = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert_eq!(all.len(), 3);
        // newest first
        assert_eq!(all[0].event_type, "cert.revoke");
        assert_eq!(all[2].event_type, "cert.issue");

        let certs = w
            .query(&AuditQuery {
                event_type: Some("cert.issue".to_owned()),
                subject: None,
                from: None,
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject.as_deref(), Some("serial-123"));

        let failures = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: None,
                outcome: Some("failure".to_owned()),
                limit: 100,
                offset: 0,
            })
            .unwrap();
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
    fn new_falls_back_when_no_socket() {
        let w = JournalWriter::new("nonexistent-test-namespace-12345");
        assert!(!w.is_connected());
        assert!(!w.has_store());
        assert_eq!(w.namespace(), "nonexistent-test-namespace-12345");
        // send should use tracing fallback, not error
        w.send(&[
            ("AKAMU_EVENT_TYPE", "ca.start"),
            ("AKAMU_OUTCOME", "success"),
        ])
        .unwrap();
    }

    #[test]
    fn query_on_disconnected_returns_empty() {
        let w = JournalWriter::disconnected();
        let rows = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn file_backend_offset_and_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let w = JournalWriter::with_file(path.to_str().unwrap()).unwrap();

        for i in 0..5 {
            w.send(&[
                ("AKAMU_EVENT_TYPE", "cert.issue"),
                ("AKAMU_OUTCOME", "success"),
                ("AKAMU_SUBJECT", &format!("serial-{i}")),
            ])
            .unwrap();
        }

        let page = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: None,
                outcome: None,
                limit: 2,
                offset: 1,
            })
            .unwrap();
        assert_eq!(page.len(), 2);
        // newest first, skip 1 → serial-3, serial-2
        assert_eq!(page[0].subject.as_deref(), Some("serial-3"));
        assert_eq!(page[1].subject.as_deref(), Some("serial-2"));
    }

    #[test]
    fn daemon_query_by_subject() {
        let w = JournalWriter::with_daemon();
        w.send(&[
            ("AKAMU_EVENT_TYPE", "cert.issue"),
            ("AKAMU_OUTCOME", "success"),
            ("AKAMU_SUBJECT", "serial-a"),
        ])
        .unwrap();
        w.send(&[
            ("AKAMU_EVENT_TYPE", "cert.issue"),
            ("AKAMU_OUTCOME", "success"),
            ("AKAMU_SUBJECT", "serial-b"),
        ])
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        let rows = w
            .query(&AuditQuery {
                event_type: None,
                subject: Some("serial-a".to_owned()),
                from: None,
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].subject.as_deref(), Some("serial-a"));
    }

    #[test]
    fn file_query_by_subject_and_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let w = JournalWriter::with_file(path.to_str().unwrap()).unwrap();
        w.send(&[
            ("AKAMU_EVENT_TYPE", "cert.issue"),
            ("AKAMU_OUTCOME", "success"),
            ("AKAMU_SUBJECT", "serial-a"),
        ])
        .unwrap();
        w.send(&[
            ("AKAMU_EVENT_TYPE", "cert.revoke"),
            ("AKAMU_OUTCOME", "failure"),
            ("AKAMU_SUBJECT", "serial-b"),
        ])
        .unwrap();

        let by_subject = w
            .query(&AuditQuery {
                event_type: None,
                subject: Some("serial-b".to_owned()),
                from: None,
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert_eq!(by_subject.len(), 1);
        assert_eq!(by_subject[0].event_type, "cert.revoke");

        let by_outcome = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: None,
                outcome: Some("failure".to_owned()),
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert_eq!(by_outcome.len(), 1);
    }

    #[test]
    fn file_query_by_time_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Write entries with explicit timestamps by writing raw JSONL
        let content = r#"{"occurred_at":"2026-01-01T00:00:00Z","AKAMU_EVENT_TYPE":"cert.issue","AKAMU_OUTCOME":"success"}
{"occurred_at":"2026-06-15T12:00:00Z","AKAMU_EVENT_TYPE":"cert.revoke","AKAMU_OUTCOME":"success"}
{"occurred_at":"2026-12-31T23:59:59Z","AKAMU_EVENT_TYPE":"admin.login","AKAMU_OUTCOME":"success"}
"#;
        std::fs::write(&path, content).unwrap();
        let w = JournalWriter::with_file(path.to_str().unwrap()).unwrap();

        let rows = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: Some("2026-06-01T00:00:00Z".to_owned()),
                until: Some("2026-07-01T00:00:00Z".to_owned()),
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "cert.revoke");
    }

    #[test]
    fn daemon_query_by_time_range() {
        let w = JournalWriter::with_daemon();
        w.send(&[
            ("AKAMU_EVENT_TYPE", "cert.issue"),
            ("AKAMU_OUTCOME", "success"),
        ])
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        let now_ish = crate::util::rfc3339_now();
        let rows = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: Some(now_ish),
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert_eq!(rows.len(), 1);

        // future from filter should exclude the event
        let rows = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: Some("2099-01-01T00:00:00Z".to_owned()),
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn file_query_empty_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.jsonl");
        let w = JournalWriter::with_file(path.to_str().unwrap()).unwrap();
        let rows = w
            .query(&AuditQuery {
                event_type: None,
                subject: None,
                from: None,
                until: None,
                outcome: None,
                limit: 100,
                offset: 0,
            })
            .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn file_query_deleted_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let w = JournalWriter::with_file(path.to_str().unwrap()).unwrap();
        w.send(&[
            ("AKAMU_EVENT_TYPE", "cert.issue"),
            ("AKAMU_OUTCOME", "success"),
        ])
        .unwrap();
        // Delete the file to trigger the open-error path in query_file
        std::fs::remove_file(&path).unwrap();
        let result = w.query(&AuditQuery {
            event_type: None,
            subject: None,
            from: None,
            until: None,
            outcome: None,
            limit: 100,
            offset: 0,
        });
        assert!(result.is_err());
    }

    #[test]
    fn parse_binary_value_without_trailing_newline() {
        let value = "hello";
        let mut data = Vec::new();
        data.extend_from_slice(b"KEY");
        data.push(b'\n');
        data.extend_from_slice(&(value.len() as u64).to_le_bytes());
        data.extend_from_slice(value.as_bytes());
        // no trailing \n — parser should still work
        let fields = parse_journal_datagram(&data);
        assert_eq!(fields.get("KEY").unwrap(), "hello");
    }

    #[test]
    fn parse_empty_datagram() {
        let fields = parse_journal_datagram(b"");
        assert!(fields.is_empty());
    }

    #[test]
    fn parse_key_only_no_separator() {
        let fields = parse_journal_datagram(b"KEYONLY");
        assert!(fields.is_empty());
    }

    #[test]
    fn parse_truncated_binary_header() {
        // Binary field with insufficient bytes for length header
        let mut data = Vec::new();
        data.extend_from_slice(b"KEY");
        data.push(b'\n');
        data.extend_from_slice(&[0u8; 4]); // only 4 bytes, need 8
        let fields = parse_journal_datagram(&data);
        assert!(fields.is_empty());
    }

    #[test]
    fn parse_truncated_binary_value() {
        // Binary field where length exceeds available data
        let mut data = Vec::new();
        data.extend_from_slice(b"KEY");
        data.push(b'\n');
        data.extend_from_slice(&100u64.to_le_bytes()); // claims 100 bytes
        data.extend_from_slice(b"short"); // only 5 bytes
        let fields = parse_journal_datagram(&data);
        assert!(fields.is_empty());
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
