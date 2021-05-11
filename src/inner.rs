use std::{collections::HashMap, time::Duration};

use crate::{
    parser::{self, parse_message},
    raw::{GeneralMessage, Response},
    status::Status,
    Error, TimeoutError, Token,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{self},
    select,
    sync::mpsc,
    time,
};
use tracing::{debug, error, info, warn};

pub(super) struct Inner {
    tx: mpsc::UnboundedSender<Msg>,
}

impl Inner {
    pub(super) fn new(cmd: process::Child) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<Msg>();

        tokio::spawn(async move { mainloop(cmd, rx).await });
        Self { tx }
    }

    pub(super) async fn execute(&self, line: String, timeout: Duration) -> Result<Response, Error> {
        let token = Token::generate();
        let (out_tx, out_rx) = mpsc::channel(1);
        self.send(Msg::Cmd {
            token,
            line,
            out: out_tx,
        });
        Self::receive(out_rx, timeout).await?
    }

    pub(super) async fn pop_general(
        &self,
        timeout: Duration,
    ) -> Result<Vec<GeneralMessage>, TimeoutError> {
        let (out_tx, out_rx) = mpsc::channel(1);
        self.send(Msg::PopGeneral(out_tx));
        Self::receive(out_rx, timeout).await
    }

    pub(super) async fn status(&self, timeout: Duration) -> Result<Status, TimeoutError> {
        let (out_tx, out_rx) = mpsc::channel(1);
        self.send(Msg::Status(out_tx));
        Self::receive(out_rx, timeout).await
    }

    pub(super) async fn next_status(
        &self,
        current: Status,
        timeout: Duration,
    ) -> Result<Status, TimeoutError> {
        let (out_tx, out_rx) = mpsc::channel(1);
        self.send(Msg::NextStatus {
            current,
            out: out_tx,
        });
        Self::receive(out_rx, timeout).await
    }

    fn send(&self, msg: Msg) {
        self.tx.send(msg).expect("Can send to mainloop");
    }

    async fn receive<O: std::fmt::Debug>(
        mut rx: mpsc::Receiver<O>,
        timeout: Duration,
    ) -> Result<O, TimeoutError> {
        time::timeout(timeout, rx.recv())
            .await
            .map(|o| o.expect("out chan not closed"))
            .map_err(|_| TimeoutError)
    }
}

#[derive(Debug)]
enum Msg {
    Cmd {
        token: Token,
        line: String,
        out: mpsc::Sender<Result<Response, Error>>,
    },
    PopGeneral(mpsc::Sender<Vec<GeneralMessage>>),
    Status(mpsc::Sender<Status>),
    NextStatus {
        current: Status,
        out: mpsc::Sender<Status>,
    },
}

async fn mainloop(mut cmd: process::Child, mut rx: mpsc::UnboundedReceiver<Msg>) {
    let mut stdin = cmd.stdin.take().expect("Stdin captured");
    let mut stdout = BufReader::new(cmd.stdout.take().expect("Stdout captured"));
    let mut stderr = BufReader::new(cmd.stderr.take().expect("Stderr captured"));

    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();

    let mut status = Status::Unstarted;
    let mut notify_next_status = Vec::new();
    let mut pending = HashMap::new();
    let mut pending_general = Vec::new();

    loop {
        select! {
            msg = rx.recv() => {
                let msg = if let Some(msg) = msg {
                    msg
                } else {
                    info!("Exiting mainloop as request_rx closed");
                    break;
                };

                match msg {
                    Msg::Cmd { token, line, out } => {
                        let mut input = token.serialize();
                        input.push_str(&line);
                        input.push('\n');

                        debug!("Sending {}", input);
                        if let Err(err) = stdin.write_all(&input.as_bytes()).await {
                            error!("Failed to write, stopping: {}", err);
                            break;
                        }

                        pending.insert(token, out);
                    }

                    Msg::PopGeneral(out) => {
                        if let Err(err) = out.send(pending_general.clone()).await {
                            error!("Failed to send general messages to out chan: {}", err);
                        }

                        pending_general.clear();
                    }

                    Msg::Status(out) => {
                        if let Err(err) = out.send(status).await {
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
                            if let Err(err) = out.send(status).await {
                                error!("Failed to send status to out chan: {}", err);
                            }
                        } else {
                            notify_next_status.push(out);
                        }
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
                                        info!("New status {:?}, notifying {} watchers", status, notify_next_status.len());
                                        for out in notify_next_status.drain(..) {
                                            if let Err(err) = out.send(status).await {
                                                error!("Failed to notify next status to out chan: {}", err);
                                            }
                                        }
                                    }
                                }
                                result @ parser::Response::Result { .. } => {
                                    warn!("Ignoring result without token: {:?}", result);
                                }
                            }
                            continue;
                        };

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
                        info!("Got general message: {:?}", general);
                        if general == GeneralMessage::Done {
                            // Suppress these, as they come after every command
                            debug!("Ignoring done");
                            continue;
                        } else {
                            pending_general.push(general);
                        }
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
