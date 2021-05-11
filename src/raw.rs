use std::collections::HashMap;

use tracing::error;

use crate::{parser, GdbError, ResponseError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Response(Response),
    General(GeneralMessage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Notify(NotifyResponse),
    Result(ResultResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultResponse {
    message: String,
    payload: Option<Dict>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyResponse {
    message: String,
    payload: Dict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralMessage {
    Console(String),
    Log(String),
    Target(String),
    Done,
    /// Not the output of gdbmi, so probably the inferior being debugged printed
    /// this to its stdout.
    InferiorStdout(String),
    InferiorStderr(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Value {
    String(String),
    List(List),
    Dict(Dict),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Dict(HashMap<String, Value>);

pub type List = Vec<Value>;

impl Response {
    pub fn expect_result(self) -> Result<ResultResponse, ResponseError> {
        match self {
            Self::Result(result) => Ok(result),
            _ => {
                error!("Expected Response to be Result, got: {:?}", self);
                Err(ResponseError::ExpectedResultResponse)
            }
        }
    }

    pub(crate) fn from_parsed(response: parser::Response) -> Result<Self, ResponseError> {
        match response {
            parser::Response::Notify {
                message, payload, ..
            } => Ok(Self::Notify(NotifyResponse { message, payload })),
            parser::Response::Result {
                message, payload, ..
            } => {
                if message == "error" {
                    let gdb_error = Self::_into_error(payload)?;
                    Err(ResponseError::Gdb(gdb_error))
                } else {
                    Ok(Self::Result(ResultResponse { message, payload }))
                }
            }
        }
    }

    fn _into_error(payload: Option<Dict>) -> Result<GdbError, ResponseError> {
        let mut payload = if let Some(payload) = payload {
            payload
        } else {
            return Err(ResponseError::ExpectedPayload);
        };

        let code = payload.remove_expect("code")?.expect_string()?;
        let msg = payload.remove_expect("msg")?.expect_string()?;

        Ok(GdbError { code, msg })
    }
}

impl ResultResponse {
    pub fn expect_payload(self) -> Result<Dict, ResponseError> {
        self.payload.ok_or(ResponseError::ExpectedPayload)
    }

    pub fn expect_msg_is(&self, msg: &str) -> Result<(), ResponseError> {
        if self.message != msg {
            Err(ResponseError::UnexpectedResponseMessage {
                expected: msg.to_owned(),
                actual: self.message.to_owned(),
            })
        } else {
            Ok(())
        }
    }
}

impl Dict {
    pub fn new(map: HashMap<String, Value>) -> Self {
        Self(map)
    }

    pub fn as_map(&self) -> &HashMap<String, Value> {
        &self.0
    }

    pub fn as_map_mut(&mut self) -> &mut HashMap<String, Value> {
        &mut self.0
    }

    pub fn remove_expect(&mut self, key: &str) -> std::result::Result<Value, ResponseError> {
        self.0
            .remove(key)
            .map_or(Err(ResponseError::ExpectedDifferentPayload), Ok)
    }
}

impl Value {
    pub(crate) fn into_appended(self, other: Self) -> Self {
        let mut list = match self {
            val @ Self::String(_) => vec![val],
            Self::List(list) => list,
            Self::Dict(_) => panic!(
                "Attempted to workaround duplicate key bug, but can't combine dict with anything"
            ),
        };

        let mut other = match other {
            val @ Self::String(_) => vec![val],
            Self::List(list) => list,
            Self::Dict(_) => panic!(
                "Attempted to workaround duplicate key bug, but can't combine anything with dict"
            ),
        };

        for val in other.drain(..) {
            list.push(val);
        }

        Self::List(list)
    }

    pub fn expect_string(self) -> Result<String, ResponseError> {
        if let Self::String(val) = self {
            Ok(val)
        } else {
            error!("Expected string, got: {:?}", self);
            Err(ResponseError::ExpectedDifferentPayload)
        }
    }

    pub fn expect_dict(self) -> Result<Dict, ResponseError> {
        if let Self::Dict(val) = self {
            Ok(val)
        } else {
            error!("Expected dict, got: {:?}", self);
            Err(ResponseError::ExpectedDifferentPayload)
        }
    }

    pub fn expect_list(self) -> Result<List, ResponseError> {
        if let Self::List(val) = self {
            Ok(val)
        } else {
            error!("Expected dict, got: {:?}", self);
            Err(ResponseError::ExpectedDifferentPayload)
        }
    }

    pub fn expect_u32(self) -> Result<u32, ResponseError> {
        let val = if let Self::String(val) = self {
            Ok(val)
        } else {
            error!("Expected dict, got: {:?}", self);
            Err(ResponseError::ExpectedDifferentPayload)
        }?;

        Ok(val.parse()?)
    }
}
