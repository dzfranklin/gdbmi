use std::{collections::HashMap, fmt, process::Stdio, time::Duration};

use breakpoint::{Breakpoint, LineSpec};
use camino::{Utf8Path, Utf8PathBuf};
use rand::Rng;
use tokio::{io, process};
use tracing::{debug, error};

pub mod breakpoint;
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
pub enum Error {
    #[error(transparent)]
    Gdb(#[from] GdbError),

    #[error("Expected result response")]
    ExpectedResultResponse,

    #[error("Expected a different payload from gdb")]
    /// Parsed, but inconsistent with what sort of payload we expected
    ExpectedDifferentPayload,

    #[error("Expected response to have a payload")]
    ExpectedPayload,

    #[error("Failed to parse payload value as u32")]
    ParseU32(#[from] std::num::ParseIntError),

    #[error("Failed to parse payload value as hex")]
    ParseHex(#[from] ParseHexError),

    #[error("Expected response to have message {expected}, got {actual}")]
    UnexpectedResponseMessage { expected: String, actual: String },

    #[error(transparent)]
    Timeout(#[from] TimeoutError),
}

#[derive(Debug, Clone, thiserror::Error, Eq, PartialEq)]
/// Timed out waiting for a message
///
/// This indicates that either gdb or the actor responsible for communicating
/// with it is busy.
///
/// The actor divides its time fairly between reading messages from gdb and
/// handling requests you send to it. It may be overwhelmed if the program being
/// debugger sends too much to stdout or stderr.
#[error("Timed out waiting for a message")]
pub struct TimeoutError;

#[derive(Debug, Clone, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
/// Received error from gdb. Code: {code:?}, msg: {msg:?}
pub struct GdbError {
    code: Option<String>,
    msg: Option<String>,
}

#[derive(Debug, Clone, thiserror::Error, Eq, PartialEq)]
pub enum ParseHexError {
    #[error("Expected to start with 0x")]
    InvalidPrefix,
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
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

    pub async fn exec_run(&self) -> Result<(), Error> {
        self.execute_raw("-exec-run")
            .await?
            .expect_result()?
            .expect_msg_is("running")
    }

    pub async fn exec_continue(&self) -> Result<(), Error> {
        self.execute_raw("-exec-continue")
            .await?
            .expect_result()?
            .expect_msg_is("running")
    }

    pub async fn exec_continue_reverse(&self) -> Result<(), Error> {
        self.execute_raw("-exec-continue --reverse")
            .await?
            .expect_result()?
            .expect_msg_is("running")
    }

    pub async fn break_insert(&self, at: LineSpec) -> Result<Breakpoint, Error> {
        let raw = self
            .execute_raw(format!("-break-insert {}", at.serialize()))
            .await?
            .expect_result()?
            .expect_payload()?
            .remove_expect("bkpt")?
            .expect_dict()?;

        Breakpoint::from_raw(raw)
    }

    pub async fn break_disable<'a, I>(&self, breakpoints: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = &'a Breakpoint>,
    {
        let mut raw = String::new();
        for bp in breakpoints {
            raw.push_str(&format!("{} ", bp.number));
        }

        self.execute_raw(format!("-break-disable {}", raw))
            .await?
            .expect_result()?
            .expect_msg_is("done")
    }

    pub async fn break_delete<'a, I>(&self, breakpoints: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = &'a Breakpoint>,
    {
        let mut raw = String::new();
        for bp in breakpoints {
            raw.push_str(&format!("{} ", bp.number));
        }

        self.execute_raw(format!("-break-delete {}", raw))
            .await?
            .expect_result()?
            .expect_msg_is("done")
    }

    pub async fn symbol_info_functions(&self) -> Result<HashMap<Utf8PathBuf, Vec<Symbol>>, Error> {
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
    pub async fn execute_raw(&self, msg: impl Into<String>) -> Result<raw::Response, Error> {
        self.inner.execute(msg.into(), self.timeout).await
    }

    /// Waits until gdb is responsive to commands.
    ///
    /// You do not need to call this before sending commands yourself.
    pub async fn await_ready(&self) -> Result<(), Error> {
        self.execute_raw("-list-target-features").await?;
        Ok(())
    }

    /// Pop any messages gdb has sent that weren't addressed to any specific
    /// request off the buffer and return them.
    pub async fn pop_general(&self) -> Vec<raw::GeneralMessage> {
        self.inner.pop_general().await
    }

    /// Change the timeout used for all async operations
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
}

impl fmt::Debug for Gdb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gdb").finish() // TODO: Use finish_non_exhaustive
    }
}

// TODO: Move to inner
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Token(pub u32);

impl Token {
    fn generate() -> Self {
        Self(rand::thread_rng().gen())
    }

    pub(crate) fn serialize(&self) -> String {
        format!("{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, iter};

    use super::*;
    use insta::assert_debug_snapshot;
    use pretty_assertions::assert_eq;
    use test_common::{build_hello_world, init, Result, TIMEOUT};

    fn fixture() -> eyre::Result<Gdb> {
        init();
        let bin = build_hello_world();
        Ok(Gdb::spawn(bin, TIMEOUT)?)
    }

    #[tokio::test]
    async fn test_break() -> Result {
        let subject = fixture()?;

        let bp = subject
            .break_insert(LineSpec::line("samples/hello_world/src/main.rs", 13))
            .await?;
        assert_eq!(1, bp.number);
        assert!(bp
            .file
            .as_ref()
            .unwrap()
            .ends_with("samples/hello_world/src/main.rs"));
        assert_eq!(17, bp.line.unwrap());
        assert_eq!(0, bp.times);

        subject.break_disable(iter::once(&bp)).await?;
        subject.break_delete(iter::once(&bp)).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_exec_continue() -> Result {
        let subject = fixture()?;
        subject.break_insert(LineSpec::function("main")).await?;
        subject.exec_run().await?;
        subject.exec_continue().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_exec_continue_not_running() -> Result {
        let subject = fixture()?;
        let error = match subject.exec_continue().await {
            Err(Error::Gdb(error)) => error,
            got => panic!("Expected Error::Gdb, got {:?}", got),
        };
        assert_eq!(error.msg.unwrap(), "The program is not being run.");
        Ok(())
    }

    #[tokio::test]
    async fn test_exec_run() -> Result {
        let subject = fixture()?;
        subject.exec_run().await?;
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
            Error::Gdb(GdbError {
                code: Some("undefined-command".into()),
                msg: Some("Undefined MI command: invalid-command".into()),
            }),
            err
        );

        Ok(())
    }
}
