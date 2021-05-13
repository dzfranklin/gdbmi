use std::{collections::HashMap, io, num::NonZeroUsize};

use crate::{
    parser::{self, parse_message},
    raw::{self, GeneralMessage, Response},
    status::Status,
    Token,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process, select,
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

type MsgOut = mpsc::Sender<Result<Response, crate::Error>>;
type StatusOut = mpsc::Sender<Status>;
type StatusAwaiterPred = Box<dyn Fn(&Status) -> bool + Send + Sync>;

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub(super) enum Msg {
    Cmd {
        token: Token,
        msg: String,
        out: MsgOut,
    },
    ConsoleCmd {
        token: Token,
        msg: String,
        out: mpsc::Sender<Result<(Response, Vec<String>), crate::Error>>,
        capture_lines: NonZeroUsize,
    },
    PopGeneral(mpsc::Sender<Vec<GeneralMessage>>),
    Status(mpsc::Sender<Status>),
    NextStatus {
        current: Status,
        out: StatusOut,
    },
    AwaitStatus {
        #[derivative(Debug = "ignore")]
        pred: StatusAwaiterPred,
        out: StatusOut,
    },
}

pub(super) fn spawn(cmd: process::Child) -> mpsc::UnboundedSender<Msg> {
    let (tx, rx) = mpsc::unbounded_channel::<Msg>();
    tokio::spawn(async move { mainloop(cmd, rx).await });
    tx
}

#[derive(Debug)]
struct PendingConsole {
    token: Token,
    response: Option<Response>,
    lines: Vec<String>,
    target: NonZeroUsize,
    out: mpsc::Sender<Result<(Response, Vec<String>), crate::Error>>,
}

#[derive(derivative::Derivative)]
#[derivative(Debug)]
struct State {
    stdin: process::ChildStdin,
    stdout: BufReader<process::ChildStdout>,
    stderr: BufReader<process::ChildStderr>,
    stdout_buf: String,
    stderr_buf: String,
    status: Status,
    #[derivative(Debug = "ignore")]
    notify_next_status: Vec<StatusOut>,
    #[derivative(Debug = "ignore")]
    status_awaiters: Vec<(StatusAwaiterPred, StatusOut)>,
    pending: HashMap<Token, MsgOut>,
    pending_general: Vec<GeneralMessage>,
    pending_console: Option<PendingConsole>,
}

async fn mainloop(mut cmd: process::Child, mut rx: mpsc::UnboundedReceiver<Msg>) {
    let stdin = cmd
        .stdin
        .take()
        .expect("Stdin not captured. See docs of Gdb::new");
    let stdout = BufReader::new(
        cmd.stdout
            .take()
            .expect("Stdout not captured. See docs of Gdb::new"),
    );
    let stderr = BufReader::new(
        cmd.stderr
            .take()
            .expect("Stderr not captured. See docs of Gdb::new"),
    );

    let mut state = State {
        stdin,
        stdout,
        stderr,
        stdout_buf: String::new(),
        stderr_buf: String::new(),
        status: Status::Unstarted,
        notify_next_status: Vec::new(),
        status_awaiters: Vec::new(),
        pending: HashMap::new(),
        pending_general: Vec::new(),
        pending_console: None,
    };

    loop {
        select! {
            // Don't pull any new command while we're waiting for console output
            msg = rx.recv(), if &state.pending_console.is_none() => {
                if let Err(err) = process_msg(msg, &mut state).await {
                    if log_and_check_fatal(&state, err) {
                        break
                    }
                }
            }

            result = state.stdout.read_line(&mut state.stdout_buf) => {
                if let Err(err) = process_stdout(result, &mut state).await {
                    if log_and_check_fatal(&state, err) {
                        break
                    }
                }
            }

            result = state.stderr.read_line(&mut state.stderr_buf) => {
                if let Err(err) = process_stderr(result, &mut state).await {
                    if log_and_check_fatal(&state, err) {
                        break
                    }
                }
            }
        }
    }
}

fn log_and_check_fatal(state: &State, error: Error) -> bool {
    debug!(?state, "State after error");
    match error {
        Error::Transient(err) => {
            error!("Transient error in worker: {}", err);
            false
        }
        Error::Fatal(err) => {
            error!("Fatal error in worker: {}", err);
            true
        }
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum Error {
    /// Fatal error in worker
    Fatal(#[from] FatalError),
    /// Transient error in worker
    Transient(#[from] TransientError),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum FatalError {
    /// Failed to write to stdin
    Stdin(#[source] io::Error),
    /// Request channel closed
    RequestChanClosed,
    /// Failed to read stdout
    Stdout(#[source] io::Error),
    /// Failed to send to out chan
    Send,
    /// Failed to parse response
    Parse(#[from] parser::Error),
    /// Failed to read stderr
    Stderr(#[source] io::Error),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum TransientError {
    /// Failed to send to out chan
    Send,
    /// Failed to parse response
    Parse(#[from] parser::Error),
}

impl<T> From<mpsc::error::SendError<T>> for FatalError {
    fn from(_: mpsc::error::SendError<T>) -> Self {
        Self::Send
    }
}

async fn process_msg(msg: Option<Msg>, state: &mut State) -> Result<(), Error> {
    let msg = msg.ok_or(FatalError::RequestChanClosed)?;

    match msg {
        Msg::Cmd { token, msg, out } => {
            write_stdin(&mut state.stdin, token, &msg).await?;
            state.pending.insert(token, out);
        }

        Msg::ConsoleCmd {
            token,
            msg,
            out,
            capture_lines,
        } => {
            state.pending_console = Some(PendingConsole {
                token,
                response: None,
                lines: Vec::with_capacity(capture_lines.get()),
                target: capture_lines,
                out,
            });
            write_stdin(&mut state.stdin, token, &msg).await?;
        }

        Msg::PopGeneral(out) => {
            send(&out, state.pending_general.clone()).await?;
            state.pending_general.clear();
        }

        Msg::Status(out) => {
            send(&out, state.status.clone()).await?;
        }

        Msg::NextStatus {
            current: current_belief,
            out,
        } => {
            if current_belief == state.status {
                state.notify_next_status.push(out);
            } else {
                debug!(?current_belief, actual = ?state.status, "Caller's current_belief incorrect, sending current status");
                send(&out, state.status.clone()).await?;
            }
        }

        Msg::AwaitStatus { pred, out } => {
            state.status_awaiters.push((pred, out));
        }
    }

    Ok(())
}

async fn write_stdin(
    stdin: &mut process::ChildStdin,
    token: Token,
    msg: &str,
) -> Result<(), FatalError> {
    let mut input = token.serialize();
    input.push_str(&msg);
    input.push('\n');

    info!("Sending to gdb {}", input);
    stdin
        .write_all(&input.as_bytes())
        .await
        .map_err(FatalError::Stdin)?;

    Ok(())
}

async fn process_stdout(result: io::Result<usize>, state: &mut State) -> Result<(), Error> {
    result.map_err(FatalError::Stdout)?;

    let line = &state.stdout_buf[..state.stdout_buf.len() - 1]; // strip the newline
    debug!("Got stdout: {}", line);
    let response = parse_message(&line).map_err(TransientError::from)?;
    state.stdout_buf.clear();

    match response {
        parser::Message::Response(response) => process_parsed_response(state, response).await?,
        parser::Message::General(general) => process_parsed_general(state, general).await?,
    }
    Ok(())
}

async fn process_parsed_response(
    state: &mut State,
    response: parser::Response,
) -> Result<(), Error> {
    let token = if let Some(token) = response.token() {
        token
    } else {
        match response {
            parser::Response::Notify {
                message, payload, ..
            } => {
                process_response_notify(state, message, payload).await?;
            }
            result @ parser::Response::Result { .. } => {
                warn!("Ignoring result without token: {:?}", result);
            }
        }
        return Ok(());
    };

    if let Some(pending_token) = state.pending_console.as_ref().map(|p| p.token) {
        if token == pending_token {
            match Response::from_parsed(response) {
                Ok(response) => {
                    let mut pending = state.pending_console.as_mut().unwrap();
                    pending.response = Some(response);

                    if pending.lines.len() != pending.target.get() {
                        return Ok(());
                    }

                    send(
                        &pending.out,
                        Ok((pending.response.clone().unwrap(), pending.lines.clone())),
                    )
                    .await?;

                    state.pending_console = None;
                }
                Err(err) => {
                    send(&state.pending_console.as_ref().unwrap().out, Err(err)).await?;
                }
            }
            return Ok(());
        }
    }

    let out = if let Some(out) = state.pending.remove(&token) {
        out
    } else {
        warn!(
            "Got unexpected token {:?}, so ignoring: {:?}",
            token, response
        );
        return Ok(());
    };

    let response = Response::from_parsed(response);
    info!("Sending response: {:?}", response);
    send(&out, response).await?;

    Ok(())
}

async fn process_response_notify(
    state: &mut State,
    message: String,
    payload: raw::Dict,
) -> Result<(), Error> {
    if let Some(new_status) = Status::from_notification(&message, payload) {
        state.status = new_status;

        info!("New status {:?}", state.status);

        let to_notify = &mut state.notify_next_status;
        debug!("Notifying {} watchers of status", to_notify.len());
        for out in to_notify.drain(..) {
            send(&out, state.status.clone()).await?;
        }

        let mut to_remove = Vec::new();
        for (idx, (pred, out)) in state.status_awaiters.iter().enumerate() {
            if pred(&state.status) {
                send(out, state.status.clone()).await?;
                to_remove.push(idx);
            }
        }
        debug!(
            "{} were awaiting this status, {} remain",
            to_remove.len(),
            state.status_awaiters.len() - to_remove.len()
        );
        for idx in to_remove {
            drop(state.status_awaiters.remove(idx));
        }
    }

    Ok(())
}

async fn process_parsed_general(
    state: &mut State,
    general: raw::GeneralMessage,
) -> Result<(), Error> {
    if let Some(pending) = state.pending_console.as_mut() {
        if let GeneralMessage::Console(line) = general {
            debug!(?pending, "Received console line for command: {}", line);

            if pending.lines.len() < pending.target.get() {
                pending.lines.push(line);
            }

            if pending.lines.len() != pending.target.get() || pending.response.is_none() {
                return Ok(());
            }

            send(
                &pending.out,
                Ok((pending.response.clone().unwrap(), pending.lines.clone())),
            )
            .await?;

            state.pending_console = None;

            return Ok(());
        }
    }

    if general == GeneralMessage::Done {
        // Suppress these, as they come after every command
        debug!("Ignoring done");
        return Ok(());
    }

    info!("Got general message: {:?}", general);
    state.pending_general.push(general);

    Ok(())
}

async fn process_stderr(result: io::Result<usize>, state: &mut State) -> Result<(), Error> {
    result.map_err(FatalError::Stderr)?;

    let line = &state.stderr_buf[..state.stderr_buf.len() - 1]; // strip the newline
    debug!("Got stderr: {}", line);
    let message = GeneralMessage::InferiorStderr(line.into());
    state.pending_general.push(message);
    state.stderr_buf.clear();

    Ok(())
}

async fn send<T>(chan: &mpsc::Sender<T>, val: T) -> Result<(), Error> {
    chan.send(val)
        .await
        .map_err(|_| Error::Transient(TransientError::Send))
}
