use std::{fmt, process::Stdio};

use parser::parse_response;
use tokio::{
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
    process, select,
    sync::{mpsc, oneshot},
};
use tracing::debug;

pub mod parser;
mod string_stream;

pub use parser::Response;

#[cfg(test)]
mod test_common;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Failed to parse response
pub enum ReceiveError {
    /// IO
    Io(#[from] tokio::io::Error),
    /// Failed to parse response
    ParseResponse(#[from] parser::Error),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Failed to send command
pub struct SendError(#[from] pub io::Error);

pub struct Gdb {
    cmd: process::Child,
    stdin: BufWriter<process::ChildStdin>,
    stdout: BufReader<process::ChildStdout>,
    stderr: BufReader<process::ChildStderr>,
    buf: String,
}

impl Gdb {
    pub fn spawn_default() -> io::Result<Self> {
        let mut cmd = process::Command::new("gdb");
        cmd.args(&["--nx", "--quiet"]);
        Self::spawn(cmd)
    }

    /// Spawn a command and use its stdin, stdout, and stderr to communicate.
    ///
    /// You should not provide the argument `interpreter` or specify the
    /// stdin/stdout/stderr of the [`std::process::Command`].
    pub fn spawn(mut cmd: process::Command) -> io::Result<Self> {
        let mut cmd = cmd
            .arg("--interpreter=mi3")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let stdin = cmd.stdin.take().expect("Stdin captured");
        let stdout = cmd.stdout.take().expect("Stdout captured");
        let stderr = cmd.stderr.take().expect("Stderr captured");

        Ok(Self {
            cmd,
            stdin: BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
            stderr: BufReader::new(stderr),
            buf: String::new(),
        })
    }

    pub async fn receive(&mut self) -> Result<Vec<Response>, ReceiveError> {
        let mut responses = Vec::new();
        loop {
            let bytes_read = self.stdout.read_line(&mut self.buf).await?;
            if bytes_read == 0 && !responses.is_empty() {
                break;
            }
            let received = &self.buf[..bytes_read];
            debug!("Received {}", received);
            let response = parse_response(received)?;
            responses.push(response);
        }
        Ok(responses)
    }

    /// Cmd not should be terminated with a newline
    pub async fn send_raw(&mut self, cmd: &str) -> Result<(), SendError> {
        self.stdin.write_all(cmd.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }
}

impl fmt::Debug for Gdb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gdb").field("cmd", &self.cmd).finish() // TODO: Use finish_non_exhaustive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_common::{init, Result};
}
