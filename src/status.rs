use camino::Utf8PathBuf;
use tracing::error;

use crate::{address::Address, raw, Error};

#[derive(Debug, Clone, Eq, PartialEq)]
/// Note: If the program stops because of a signal like SIGKILL you will get a
/// [`Status::Stopped`].
pub enum Status {
    Unstarted,
    Running,
    Stopped(Stopped),
    Exited(ExitReason),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Stopped {
    pub reason: Option<StopReason>,
    pub address: Address,
    pub function: Option<String>,
    pub file: Option<Utf8PathBuf>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StopReason {
    /// A breakpoint was reached
    Breakpoint { number: u32 },
    /// A watchpoint was triggered
    Watchpoint,
    /// A read watchpoint was triggered
    ReadWatchpoint,
    /// An access watchpoint was triggered
    AccessWatchpoint,
    /// An -exec-finish or similar CLI command was accomplished
    FunctionFinished,
    /// An -exec-until or similar CLI command was accomplished
    LocationReached,
    /// A watchpoint has gone out of scope
    WatchpointScope,
    /// An -exec-next, -exec-next-instruction, -exec-step,
    /// -exec-step-instruction or similar CLI command was accomplished
    EndSteppingRange,
    /// A signal was received by the inferior
    SignalReceived,
    /// The inferior has stopped due to a library being loaded or unloaded.
    ///
    /// This can happen when stop-on-solib-events is set or when a catch load or
    /// catch unload catchpoint is in use (see Set Catchpoints).
    SolibEvent,
    /// The inferior has forked
    ///
    /// This is reported when catch fork has been used.
    Fork,
    /// The inferior has vforked
    ///
    /// This is reported in when catch vfork has been used.
    VFork,
    /// The inferior entered a system call
    ///
    /// This is reported when catch syscall has been used.
    SyscallEntry,
    /// The inferior returned from a system call.
    ///
    /// This is reported when catch syscall has been used.
    SyscallReturn,
    /// The inferior called exec.
    ///
    /// This is reported when catch exec has been used.
    Exec,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExitReason {
    /// The inferior exited because of a signal
    Signal,
    /// The inferior exited normally
    Normal,
    /// No information available besides that the inferior exited
    Other,
}

impl Status {
    pub(crate) fn from_notification(message: &str, payload: raw::Dict) -> Option<Self> {
        match message {
            "running" => Some(Status::Running),
            "stopped" => {
                match Self::parse_msg_stopped(payload) {
                    Ok(status) => Some(status),
                    Err(err) => {
                        error!("Got a notification that looks like a status, but failed to process: {}", err);
                        None
                    }
                }
            }
            _ => None,
        }
    }

    fn parse_msg_stopped(mut payload: raw::Dict) -> Result<Self, Error> {
        let reason = if let Some(reason) = payload
            .remove("reason")
            .map(raw::Value::expect_string)
            .transpose()?
        {
            reason
        } else {
            return Self::stopped_from_payload(None, payload);
        };

        match reason.as_str() {
            "breakpoint-hit" => {
                let number = payload.remove_expect("bkptno")?.expect_number()?;
                Self::stopped_from_payload(Some(StopReason::Breakpoint { number }), payload)
            }
            "watchpoint-trigger" => {
                Self::stopped_from_payload(Some(StopReason::Watchpoint), payload)
            }
            "read-watchpoint-trigger" => {
                Self::stopped_from_payload(Some(StopReason::ReadWatchpoint), payload)
            }
            "access-watchpoint-trigger" => {
                Self::stopped_from_payload(Some(StopReason::AccessWatchpoint), payload)
            }
            "function-finished" => {
                Self::stopped_from_payload(Some(StopReason::FunctionFinished), payload)
            }
            "location-reached" => {
                Self::stopped_from_payload(Some(StopReason::LocationReached), payload)
            }
            "watchpoint-scope" => {
                Self::stopped_from_payload(Some(StopReason::WatchpointScope), payload)
            }
            "end-stepping-range" => {
                Self::stopped_from_payload(Some(StopReason::EndSteppingRange), payload)
            }
            "signal-received" => {
                Self::stopped_from_payload(Some(StopReason::SignalReceived), payload)
            }
            "solib-event" => Self::stopped_from_payload(Some(StopReason::SolibEvent), payload),
            "fork" => Self::stopped_from_payload(Some(StopReason::Fork), payload),
            "vfork" => Self::stopped_from_payload(Some(StopReason::VFork), payload),
            "syscall-entry" => Self::stopped_from_payload(Some(StopReason::SyscallEntry), payload),
            "syscall-return" => {
                Self::stopped_from_payload(Some(StopReason::SyscallReturn), payload)
            }
            "exec" => Self::stopped_from_payload(Some(StopReason::Exec), payload),
            "exited-signalled" => Ok(Self::Exited(ExitReason::Signal)),
            "exited" => Ok(Self::Exited(ExitReason::Other)),
            "exited-normally" => Ok(Self::Exited(ExitReason::Normal)),
            reason => {
                error!("Unexpected stop reason: {}", reason);
                Err(Error::ExpectedDifferentPayload)
            }
        }
    }

    fn stopped_from_payload(
        reason: Option<StopReason>,
        mut payload: raw::Dict,
    ) -> Result<Status, Error> {
        let mut frame = payload.remove_expect("frame")?.expect_dict()?;

        let address = frame.remove_expect("addr")?.expect_address()?;
        let function = frame
            .remove("func")
            .map(raw::Value::expect_string)
            .transpose()?;
        let file = frame
            .remove("file")
            .map(raw::Value::expect_path)
            .transpose()?;
        let line = frame
            .remove("line")
            .map(raw::Value::expect_number)
            .transpose()?;

        Ok(Status::Stopped(Stopped {
            reason,
            address,
            function,
            file,
            line,
        }))
    }
}
