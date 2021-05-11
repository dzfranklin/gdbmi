use std::{collections::HashMap, fmt, process::Stdio, time::Duration};

use camino::{Utf8Path, Utf8PathBuf};
use rand::Rng;
use tokio::{io, process};
use tracing::{debug, error};

mod inner;
pub mod parser;
pub mod raw;
mod string_stream;
pub mod symbol;

use inner::Inner;

use crate::symbol::Symbol;

#[cfg(test)]
mod test_common;

#[derive(Debug, Clone, thiserror::Error, Eq, PartialEq)]
pub enum ResponseError {
    #[error(transparent)]
    Gdb(#[from] GdbError),

    #[error("Expected result response")]
    ExpectedResultResponse,

    #[error("Expected a different payload from gdb")]
    /// Parsed, but inconsistent with what sort of payload we expected
    ExpectedDifferentPayload,

    #[error("Expected response to have a payload")]
    ExpectedPayload,

    #[error("Failed to parse payload value as u32, got: {0}")]
    ParseU32(#[from] std::num::ParseIntError),

    #[error("Expected response to have message {expected}, got {actual}")]
    UnexpectedResponseMessage { expected: String, actual: String },

    #[error("Timeout waiting for response")]
    Timeout,
}

#[derive(Debug, Clone, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
/// Received error {code} from gdb: {msg}
pub struct GdbError {
    code: String,
    msg: String,
}

pub struct Gdb {
    inner: Inner,
    timeout: Duration,
}

impl Gdb {
    /// Spawn a gdb process to communicate with.
    ///
    /// The timeout applies to all requests sent to gdb.
    ///
    /// We provide the arguments "--interpreter=mi3" and "--quiet" to the command.
    ///
    /// If you are connecting to the gdbserver in [rr][rr] start it with the
    /// argument `--mark-stdio` so we can distinguish the process output.
    pub fn spawn(executable: impl AsRef<Utf8Path>, timeout: Duration) -> io::Result<Self> {
        let executable = executable.as_ref().as_str();
        debug!(?timeout, "Spawning {}", executable);

        let cmd = process::Command::new("gdb")
            .arg("--interpreter=mi3")
            .arg("--quiet")
            .arg(executable)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        Self::new(cmd, timeout)
    }

    /// Communicate with the provided process.
    ///
    /// You are responsible for configuring the process to speak version 3 of
    /// GDB/MI (provide --interpreter=mi3 to gdb).await
    ///
    /// See [`Self::spawn`] for an explanation of `timeout`.
    pub fn new(cmd: process::Child, timeout: Duration) -> io::Result<Self> {
        let inner = Inner::new(cmd);
        Ok(Self { inner, timeout })
    }

    pub async fn run(&self) -> Result<(), ResponseError> {
        self.execute_raw("-exec-run")
            .await?
            .expect_result()?
            .expect_msg_is("running")
    }

    pub async fn symbol_info_functions(
        &self,
    ) -> Result<HashMap<Utf8PathBuf, Vec<Symbol>>, ResponseError> {
        let payload = self
            .execute_raw("-symbol-info-functions")
            .await?
            .expect_result()?
            .expect_payload()?;
        symbol::from_symbol_info_functions_payload(payload)
    }

    /// Execute a command for a response.
    ///
    /// Your command will be prefixed with a token and suffixed with a newline.
    pub async fn execute_raw(
        &self,
        msg: impl Into<String>,
    ) -> Result<raw::Response, ResponseError> {
        self.inner.execute(msg.into(), self.timeout).await
    }

    /// Waits until gdb is responsive to commands.
    ///
    /// You do not need to call this before sending commands yourself.
    pub async fn await_ready(&self) -> Result<(), ResponseError> {
        self.execute_raw("-list-target-features").await?;
        Ok(())
    }

    /// Pop any messages gdb has sent that weren't addressed to any specific
    /// request off the buffer and return them.
    pub async fn pop_general(&self) -> Vec<raw::GeneralMessage> {
        self.inner.pop_general().await
    }
}

impl fmt::Debug for Gdb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gdb").finish() // TODO: Use finish_non_exhaustive
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Token(pub u32);

impl Token {
    fn generate() -> Self {
        Self(rand::thread_rng().gen())
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        format!("{}", self.0).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use insta::assert_debug_snapshot;
    use test_common::{build_hello_world, init, Result, TIMEOUT};

    fn fixture() -> eyre::Result<Gdb> {
        init();
        let bin = build_hello_world()?;
        Ok(Gdb::spawn(bin, TIMEOUT)?)
    }

    #[tokio::test]
    async fn test_run() -> Result {
        let subject = fixture()?;
        subject.run().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_symbol_info_function() -> Result {
        let subject = fixture()?;
        // Convert to BTreeMap so it has stable order
        let symbols: BTreeMap<_, _> = subject.symbol_info_functions().await?.into_iter().collect();
        assert_debug_snapshot!(symbols);
        Ok(())
    }

    #[tokio::test]
    async fn test_await_ready() -> Result {
        let subject = fixture()?;
        subject.await_ready().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_pop_general() -> Result {
        let subject = fixture()?;
        subject.execute_raw("-gdb-version").await?;
        let general = subject.pop_general().await;
        assert!(!general.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_command() -> Result {
        let subject = fixture()?;

        let err = subject.execute_raw("-invalid-command").await.unwrap_err();

        assert_eq!(
            ResponseError::Gdb(GdbError {
                code: "undefined-command".into(),
                msg: "Undefined MI command: invalid-command".into(),
            }),
            err
        );

        Ok(())
    }
}
