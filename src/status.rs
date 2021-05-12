use tracing::error;

use crate::{raw, Error};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Status {
    Unstarted,
    Running,
    Stopped { reason: StoppedReason },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StoppedReason {
    /// A breakpoint was reached
    Breakpoint {
        break_num: u32,
        address: u64,
        function: String,
    },
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
    /// The inferior exited because of a signal
    ExitSignalled,
    /// The inferior exited
    Exited,
    /// The inferior exited normally
    ExitedNormally,
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

impl Status {
    pub(crate) fn from_notification(message: &str, payload: raw::Dict) -> Option<Self> {
        match message {
            "running" => Some(Status::Running),
            "stopped" => {
                match StoppedReason::from_payload(payload) {
                    Ok(reason) => {
                        let new = Status::Stopped { reason };
                        Some(new)
                    }
                    Err(err) => {
                        error!("Got a notification that looks like a status, but failed to process: {}", err);
                        None
                    }
                }
            }
            _ => None,
        }
    }
}

impl StoppedReason {
    fn from_payload(mut payload: raw::Dict) -> Result<Self, Error> {
        let reason = payload.remove_expect("reason")?.expect_string()?;
        match reason.as_str() {
            "breakpoint-hit" => {
                let break_num = payload.remove_expect("bkptno")?.expect_number()?;
                let mut frame = payload.remove_expect("frame")?.expect_dict()?;
                let address = frame.remove_expect("addr")?.expect_hex()?;
                let function = frame.remove_expect("func")?.expect_string()?;
                Ok(Self::Breakpoint {
                    break_num,
                    address,
                    function,
                })
            }
            "watchpoint-trigger" => Ok(Self::Watchpoint),
            "read-watchpoint-trigger" => Ok(Self::ReadWatchpoint),
            "access-watchpoint-trigger" => Ok(Self::AccessWatchpoint),
            "function-finished" => Ok(Self::FunctionFinished),
            "location-reached" => Ok(Self::LocationReached),
            "watchpoint-scope" => Ok(Self::WatchpointScope),
            "end-stepping-range" => Ok(Self::EndSteppingRange),
            "exited-signalled" => Ok(Self::ExitSignalled),
            "exited" => Ok(Self::Exited),
            "exited-normally" => Ok(Self::ExitedNormally),
            "signal-received" => Ok(Self::SignalReceived),
            "solib-event" => Ok(Self::SolibEvent),
            "fork" => Ok(Self::Fork),
            "vfork" => Ok(Self::VFork),
            "syscall-entry" => Ok(Self::SyscallEntry),
            "syscall-return" => Ok(Self::SyscallReturn),
            "exec" => Ok(Self::Exec),
            _ => {
                error!("Unexpected stop reason: {}", reason);
                Err(Error::ExpectedDifferentPayload)
            }
        }
    }
}
