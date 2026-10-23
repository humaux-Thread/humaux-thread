//! `adapters::email::sink` — the non-sending [`super::EmailProvider`]: writes each message to a `.eml` file.
//! Depends-on: crates=[async-trait]; services=[]; env=[]; modules=[adapters::email]
//! Called-by: []
//! Invariants: [opens no network connection; the file name is derived from the deterministic Message-ID, so a replayed
//!   send overwrites the same file instead of adding a second one; a header value carrying CR or LF is rejected]
//! Spec: Baseline §74.6
//!
//! M02 D10: this is the default mode of every profile. The rehearsal and CI read the files; live
//! delivery needs the owner to select `EmailMode::Smtp` explicitly.
//! ponytail: only the text part is written; an HTML alternative is dropped until a template
//! card needs to inspect it, then add a multipart body here.

use std::path::PathBuf;

use async_trait::async_trait;

use super::{EmailError, EmailProvider, OutboundEmail, ProviderMessageId};

/// Writes `<sanitised message id>.eml` under `dir`.
#[derive(Debug, Clone)]
pub struct SinkEmailProvider {
    dir: PathBuf,
}

impl SinkEmailProvider {
    /// `dir` is created on first send.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Path the message with this `Message-ID` is written to.
    pub fn path_for(&self, message_id: &str) -> PathBuf {
        let stem: String = message_id
            .trim_matches(|c| c == '<' || c == '>')
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{stem}.eml"))
    }
}

fn header_value_is_safe(v: &str) -> bool {
    !v.contains('\r') && !v.contains('\n')
}

#[async_trait]
impl EmailProvider for SinkEmailProvider {
    fn name(&self) -> &str {
        "sink"
    }

    async fn send(&self, mail: OutboundEmail) -> Result<ProviderMessageId, EmailError> {
        for v in [&mail.to, &mail.from, &mail.subject, &mail.message_id] {
            if !header_value_is_safe(v) {
                return Err(EmailError::Rejected(
                    "header value contains a line break".to_string(),
                ));
            }
        }
        let text = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nMessage-ID: {}\r\nX-Humaux-Stream: {}\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\r\n{}",
            mail.from,
            mail.to,
            mail.subject,
            mail.message_id,
            mail.stream.as_db_str(),
            mail.body_text
        );
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| EmailError::Transport(format!("sink dir: {e}")))?;
        std::fs::write(self.path_for(&mail.message_id), text)
            .map_err(|e| EmailError::Transport(format!("sink write: {e}")))?;
        Ok(ProviderMessageId(mail.message_id))
    }
}
