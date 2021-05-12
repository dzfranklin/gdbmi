use std::{collections::HashMap, num::NonZeroUsize};

use crate::{
    parser::{self, parse_message},
    raw::{GeneralMessage, Response},
    status::Status,
    Error, Token,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process, select,
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub(super) enum Msg {
    Cmd {
        token: Token,
        msg: String,
        out: mpsc::Sender<Result<Response, Error>>,
    },
    ConsoleCmd {
        token: Token,
        msg: String,
        out: mpsc::Sender<Result<(Response, Vec<String>), Error>>,
        capture_lines: NonZeroUsize,
    },
    PopGeneral(mpsc::Sender<Vec<GeneralMessage>>),
    Status(mpsc::Sender<Status>),
    NextStatus {
        current: Status,
        out: mpsc::Sender<Status>,
    },
    AwaitStatus {
        #[derivative(Debug = "ignore")]
        pred: Box<dyn Fn(&Status) -> bool + Send + Sync>,
        out: mpsc::Sender<Status>,
    },
}

pub(super) fn spawn(cmd: process::Child) -> mpsc::UnboundedSender<Msg> {
    let (tx, rx) = mpsc::unbounded_channel::<Msg>();
    tokio::spawn(async move { mainloop(cmd, rx).await });
    tx
}

#[derive(Debug, Clone)]
struct PendingConsole {
    token: Token,
    response: Option<Response>,
    lines: Vec<String>,
    target: NonZeroUsize,
    out: mpsc::Sender<Result<(Response, Vec<String>), Error>>,
}

async fn mainloop(mut cmd: process::Child, mut rx: mpsc::UnboundedReceiver<Msg>) {
    let mut stdin = cmd
        .stdin
        .take()
        .expect("Stdin not captured. See docs of Gdb::new");
    let mut stdout = BufReader::new(
        cmd.stdout
            .take()
            .expect("Stdout not captured. See docs of Gdb::new"),
    );
    let mut stderr = BufReader::new(
        cmd.stderr
            .take()
            .expect("Stderr not captured. See docs of Gdb::new"),
    );

    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();

    let mut status = Status::Unstarted;
    let mut notify_next_status = Vec::new();
    let mut status_awaiters = Vec::new();
    let mut pending = HashMap::new();
    let mut pending_general = Vec::new();
    let mut pending_console: Option<PendingConsole> = None;

    loop {
        select! {
            msg = rx.recv(), if &pending_console.is_none() => {
                // Don't pull any new command while we're waiting for console output

                let msg = if let Some(msg) = msg {
                    msg
                } else {
                    info!("Exiting mainloop as request_rx closed");
                    break;
                };

                match msg {
                    Msg::Cmd { token, msg, out } => {
                        let mut input = token.serialize();
                        input.push_str(&msg);
                        input.push('\n');

                        info!("Sending to gdb {}", input);
                        if let Err(err) = stdin.write_all(&input.as_bytes()).await {
                            error!("Failed to write, stopping: {}", err);
                            break;
                        }

                        pending.insert(token, out);
                    }

                    Msg::ConsoleCmd {token, msg, out, capture_lines } => {
                        pending_console = Some(PendingConsole {
                            token,
                            response: None,
                            lines: Vec::with_capacity(capture_lines.get()),
                            target: capture_lines,
                            out,
                        });

                        let mut input = token.serialize();
                        input.push_str(&msg);
                        input.push('\n');

                        debug!("Sending {}", input);
                        if let Err(err) = stdin.write_all(&input.as_bytes()).await {
                            error!("Failed to write, stopping: {}", err);
                            break;
                        }
                    }

                    Msg::PopGeneral(out) => {
                        if let Err(err) = out.send(pending_general.clone()).await {
                            error!("Failed to send general messages to out chan: {}", err);
                        }

                        pending_general.clear();
                    }

                    Msg::Status(out) => {
                        if let Err(err) = out.send(status.clone()).await {
                            error!("Failed to send status to out chan: {}", err);
                        }
                    }

                    Msg::NextStatus { current: current_belief, out } => {
                        if current_belief != status {
                            warn!(
                                ?current_belief,
                                actual = ?status,
                                "Caller's believed current status incorrect, sending them the current status"
                            );
                            if let Err(err) = out.send(status.clone()).await {
                                error!("Failed to send status to out chan: {}", err);
                            }
                        } else {
                            notify_next_status.push(out);
                        }
                    }

                    Msg::AwaitStatus { pred, out } => {
                        status_awaiters.push((pred, out));
                    }
                }
            }

            result = stdout.read_line(&mut stdout_buf) => {
                if let Err(err) = result {
                    error!("Failed to read, stopping: {}", err);
                    break;
                }

                let line = &stdout_buf[..stdout_buf.len() - 1]; // strip the newline
                debug!("Got stdout: {}", line);
                let response = match parse_message(&line) {
                    Ok(response) => {
                        response
                    },
                    Err(err) => {
                        error!("Failed to parse response, stopping: {}", err);
                        break;
                    }
                };
                stdout_buf.clear();

                match response {
                    parser::Message::Response(response) => {
                        let token = if let Some(token) = response.token() {
                            token
                        } else {
                            match response {
                                parser::Response::Notify { message, payload, .. } => {
                                    if let Some(new_status) = Status::from_notification(&message, payload) {
                                        status = new_status;

                                        info!("New status {:?}", status);

                                        debug!("Notifying {} watchers of status", notify_next_status.len());
                                        for out in notify_next_status.drain(..) {
                                            if let Err(err) = out.send(status.clone()).await {
                                                error!("Failed to notify next status to out chan: {}", err);
                                            }
                                        }

                                        let mut to_remove = Vec::new();
                                        for (idx, (pred, out)) in status_awaiters.iter().enumerate() {
                                            if pred(&status) {
                                                if let Err(err) = out.send(status.clone()).await {
                                                    error!("Failed to notify awaited status to out chan: {}", err);
                                                }
                                                to_remove.push(idx);
                                            }
                                        }
                                        debug!("{} status awaiters were awaiting this status, {} remain", to_remove.len(), status_awaiters.len() - to_remove.len());
                                        for idx in to_remove {
                                            let _ = status_awaiters.remove(idx);
                                        }
                                    }
                                }
                                result @ parser::Response::Result { .. } => {
                                    warn!("Ignoring result without token: {:?}", result);
                                }
                            }
                            continue;
                        };

                        if let Some(pending_token) = pending_console.as_ref().map(|p| p.token) {
                            if token == pending_token {
                                match Response::from_parsed(response) {
                                    Ok(response) => {
                                        let mut pending = pending_console.as_mut().unwrap();
                                        pending.response = Some(response);

                                        if pending.lines.len() != pending.target.get() {
                                            continue;
                                        }

                                        if let Err(err) = pending.out.send(Ok((pending.response.clone().unwrap(), pending.lines.clone()))).await {
                                            error!("Failed to send to pending console out: {}", err);
                                        }
                                        pending_console = None;
                                    }
                                    Err(err) => {
                                        if let Err(err) = pending_console.as_ref().unwrap().out.send(Err(err)).await {
                                            error!("Failed to error to pending console out: {}", err);
                                        }
                                    }
                                }
                                continue;
                            }
                        }

                        let out = if let Some(out) = pending.remove(&token) {
                            out
                        } else {
                            warn!("Did not expect token {:?}. Ignoring response: {:?}", token, response);
                            continue;
                        };

                        let response = Response::from_parsed(response);
                        info!("Sending response: {:?}", response);
                        if let Err(err) = out.send(response).await {
                            error!("Failed to send response to out chan: {}", err);
                        }
                    }
                    parser::Message::General(general) => {
                        if let Some(pending) = pending_console.as_mut() {
                            if let GeneralMessage::Console(line) = general {
                                debug!(?pending, "Received console line for command: {}", line);

                                if pending.lines.len() < pending.target.get() {
                                    pending.lines.push(line);
                                }

                                if pending.lines.len() != pending.target.get() || pending.response.is_none() {
                                    continue;
                                }

                                if let Err(err) = pending.out.send(Ok((pending.response.clone().unwrap(), pending.lines.clone()))).await {
                                    error!("Failed to send to pending console out: {}", err);
                                }
                                pending_console = None;

                                continue;
                            }
                        }

                        if general == GeneralMessage::Done {
                            // Suppress these, as they come after every command
                            debug!("Ignoring done");
                            continue;
                        }

                        info!("Got general message: {:?}", general);
                        pending_general.push(general);
                    }
                }
            }

            result = stderr.read_line(&mut stderr_buf) => {
                if let Err(err) = result {
                    error!("Failed to read, stopping: {}", err);
                    break;
                }

                let line = &stderr_buf[..stderr_buf.len() - 1]; // strip the newline
                debug!("Got stderr: {}", line);
                let message = GeneralMessage::InferiorStderr(line.into());
                pending_general.push(message);
                stderr_buf.clear();
            }
        }
    }
}
