use std::collections::HashMap;

use camino::Utf8PathBuf;
use tracing::{error, warn};

use crate::{address::Address, parser, Error, GdbError, ParseHexError};

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
    pub fn expect_result(self) -> Result<ResultResponse, Error> {
        if let Self::Result(result) = self {
            Ok(result)
        } else {
            error!("Expected Response to be Result, got: {:?}", self);
            Err(Error::ExpectedResultResponse)
        }
    }

    pub(crate) fn from_parsed(response: parser::Response) -> Result<Self, Error> {
        match response {
            parser::Response::Notify {
                message, payload, ..
            } => Ok(Self::Notify(NotifyResponse { message, payload })),
            parser::Response::Result {
                message, payload, ..
            } => {
                if message == "error" {
                    let gdb_error = Self::_into_error(payload)?;
                    Err(Error::Gdb(gdb_error))
                } else {
                    Ok(Self::Result(ResultResponse { message, payload }))
                }
            }
        }
    }

    fn _into_error(payload: Option<Dict>) -> Result<GdbError, Error> {
        let mut payload = if let Some(payload) = payload {
            payload
        } else {
            return Err(Error::ExpectedPayload);
        };

        let code = payload
            .remove("code")
            .map(Value::expect_string)
            .transpose()?;
        let msg = payload
            .remove("msg")
            .map(Value::expect_string)
            .transpose()?;

        Ok(GdbError { code, msg })
    }
}

impl ResultResponse {
    pub fn expect_payload(self) -> Result<Dict, Error> {
        self.payload.ok_or(Error::ExpectedPayload)
    }

    pub fn expect_msg_is(&self, msg: &str) -> Result<(), Error> {
        if self.message == msg {
            Ok(())
        } else {
            Err(Error::UnexpectedResponseMessage {
                expected: msg.to_owned(),
                actual: self.message.clone(),
            })
        }
    }
}

impl Dict {
    #[must_use]
    pub fn new(map: HashMap<String, Value>) -> Self {
        Self(map)
    }

    #[must_use]
    pub fn as_map(&self) -> &HashMap<String, Value> {
        &self.0
    }

    pub fn as_map_mut(&mut self) -> &mut HashMap<String, Value> {
        &mut self.0
    }

    pub fn remove_expect(&mut self, key: &str) -> Result<Value, Error> {
        self.0.remove(key).map_or_else(
            || {
                warn!("Expected key {} to be present in {:?}", key, self);
                Err(Error::ExpectedDifferentPayload)
            },
            Ok,
        )
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.0.remove(key)
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

    pub fn expect_string(self) -> Result<String, Error> {
        if let Self::String(val) = self {
            Ok(val)
        } else {
            error!("Expected string, got: {:?}", self);
            Err(Error::ExpectedDifferentPayload)
        }
    }

    pub fn expect_dict(self) -> Result<Dict, Error> {
        if let Self::Dict(val) = self {
            Ok(val)
        } else {
            error!("Expected dict, got: {:?}", self);
            Err(Error::ExpectedDifferentPayload)
        }
    }

    pub fn expect_list(self) -> Result<List, Error> {
        if let Self::List(val) = self {
            Ok(val)
        } else {
            error!("Expected dict, got: {:?}", self);
            Err(Error::ExpectedDifferentPayload)
        }
    }

    pub fn expect_number(self) -> Result<u32, Error> {
        let val = if let Self::String(val) = self {
            Ok(val)
        } else {
            error!("Expected dict, got: {:?}", self);
            Err(Error::ExpectedDifferentPayload)
        }?;

        Ok(val.parse()?)
    }

    pub fn expect_path(self) -> Result<Utf8PathBuf, Error> {
        let path = self.expect_string()?.into();
        Ok(path)
    }

    pub fn expect_hex(self) -> Result<u64, Error> {
        parse_hex(&self.expect_string()?)
    }

    pub fn expect_address(self) -> Result<Address, Error> {
        self.expect_hex().map(Address)
    }
}

pub fn parse_hex(s: &str) -> Result<u64, Error> {
    if let Some(hex) = s.strip_prefix("0x") {
        let num = u64::from_str_radix(hex, 16)?;
        Ok(num)
    } else {
        Err(ParseHexError::InvalidPrefix.into())
    }
}
