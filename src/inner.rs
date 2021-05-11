use std::{collections::HashMap, time::Duration};

use crate::{
    parser::{self, parse_message},
    raw::{GeneralMessage, Response},
    ResponseError, Token,
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
    request_tx: mpsc::UnboundedSender<Request>,
    general_tx: mpsc::UnboundedSender<GeneralRequest>,
}

type GeneralRequest = mpsc::Sender<Vec<GeneralMessage>>;

impl Inner {
    pub(super) fn new(cmd: process::Child) -> Self {
        let (request_tx, request_rx) = mpsc::unbounded_channel::<Request>();
        let (general_tx, general_rx) = mpsc::unbounded_channel::<GeneralRequest>();

        tokio::spawn(async move { mainloop(cmd, request_rx, general_rx).await });
        Self {
            request_tx,
            general_tx,
        }
    }

    pub(super) async fn execute(
        &self,
        msg: String,
        timeout: Duration,
    ) -> Result<Response, ResponseError> {
        let token = Token::generate();
        let (out_tx, mut out_rx) = mpsc::channel(1);

        self.request_tx
            .send((token, msg, out_tx))
            .expect("Can send to mainloop");

        time::timeout(timeout, out_rx.recv())
            .await
            .map_err(|_| ResponseError::Timeout)?
            .expect("out chan not closed")
    }

    pub(super) async fn pop_general(&self) -> Vec<GeneralMessage> {
        let (out_tx, mut out_rx) = mpsc::channel(1);
        self.general_tx.send(out_tx).expect("Can send to mainloop");
        out_rx.recv().await.expect("out chan not closed")
    }
}

type Request = (Token, String, mpsc::Sender<Result<Response, ResponseError>>);

async fn mainloop(
    mut cmd: process::Child,
    mut request_rx: mpsc::UnboundedReceiver<Request>,
    mut general_rx: mpsc::UnboundedReceiver<GeneralRequest>,
) {
    let mut stdin = cmd.stdin.take().expect("Stdin captured");
    let mut stdout = BufReader::new(cmd.stdout.take().expect("Stdout captured"));
    let mut stderr = BufReader::new(cmd.stderr.take().expect("Stderr captured"));

    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();

    let mut pending = HashMap::new();
    let mut pending_general = Vec::new();

    loop {
        select! {
            request = request_rx.recv() => {
                let (token, msg, out) = if let Some(request) = request {
                    request
                } else {
                    info!("Exiting mainloop as request_rx closed");
                    break;
                };

                let mut input = token.serialize();
                input.extend_from_slice(msg.as_bytes());
                input.push(b'\n');

                if let Err(err) = stdin.write_all(&input).await {
                    error!("Failed to write, stopping: {}", err);
                    break;
                }

                pending.insert(token, out);
            }

            result = stdout.read_line(&mut stdout_buf) => {
                if let Err(err) = result {
                    error!("Failed to read, stopping: {}", err);
                    break;
                }

                let line = &stdout_buf[..stdout_buf.len() - 1]; // strip the newline
                debug!("Got stdin: {}", line);
                let response = match parse_message(&line) {
                    Ok(response) => {
                        debug!("Parsed response: {:?}", response);
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
                            warn!("Ignoring response without token: {:?}", response);
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

            request = general_rx.recv() => {
                let out = if let Some(request) = request {
                    request
                } else {
                    info!("Exiting mainloop as general_rx closed");
                    break;
                };

                if let Err(err) = out.send(pending_general.clone()).await {
                    error!("Failed to send general messages to out chan: {}", err);
                }

                pending_general.clear();
            }
        }
    }
}
