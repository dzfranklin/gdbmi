use std::collections::HashMap;

use crate::{
    raw::{Dict, GeneralMessage, List, Value},
    string_stream::StringStream,
    Token,
};
use lazy_static::lazy_static;
use regex::Regex;

// TODO: Refactor to use bytes instead of strings

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// Expected result message, got
    ExpectedResultMsg(String),
    /// Expected dict value, got end of input
    ExpectedDictValueUnexpectedEof,
    /// Expected dict value, got character {0}
    ExpectedDictValueUnexpectedChar(char),
    /// Failed to parse token, got {0}
    TokenParse(String, #[source] std::num::ParseIntError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Message {
    Response(Response),
    General(GeneralMessage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Response {
    Notify {
        token: Option<Token>,
        message: String,
        payload: Dict,
    },
    Result {
        token: Option<Token>,
        message: String,
        payload: Option<Dict>,
    },
}

impl Response {
    pub(crate) fn token(&self) -> Option<Token> {
        match self {
            Self::Notify { token, .. } => *token,
            Self::Result { token, .. } => *token,
        }
    }
}

impl From<GeneralMessage> for Message {
    fn from(msg: GeneralMessage) -> Self {
        Self::General(msg)
    }
}

impl From<Response> for Message {
    fn from(msg: Response) -> Self {
        Self::Response(msg)
    }
}

/// Parse the output of gdbmi
///
/// See https://sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI-Stream-Records.html#GDB_002fMI-Stream-Records
/// for details on types of gdb mi output.
pub(crate) fn parse_message(i: &str) -> Result<Message> {
    assert!(!i.contains('\n'));
    let mut stream = StringStream::new(i.to_owned());

    if NOTIFY_RE.is_match(i) {
        let (token, message, payload) = get_notify_msg_and_payload(&mut stream)?;
        let resp = Response::Notify {
            token,
            message,
            payload,
        }
        .into();
        Ok(resp)
    } else if RESULT_RE.is_match(i) {
        let (token, message, payload) = get_result_msg_and_payload(i, &mut stream)?;
        let resp = Response::Result {
            token,
            message,
            payload,
        }
        .into();
        Ok(resp)
    } else if let Some(caps) = CONSOLE_RE.captures(i) {
        let message = caps.get(1).unwrap().as_str().to_owned();
        Ok(GeneralMessage::Console(message).into())
    } else if let Some(caps) = LOG_RE.captures(i) {
        let payload = caps.get(1).unwrap().as_str().to_owned();
        Ok(GeneralMessage::Log(payload).into())
    } else if let Some(caps) = TARGET_OUTPUT_RE.captures(i) {
        let payload = caps.get(1).unwrap().as_str().to_owned();
        Ok(GeneralMessage::Target(payload).into())
    } else if RESPONSE_FINISHED_RE.is_match(i) {
        Ok(GeneralMessage::Done.into())
    } else {
        Ok(GeneralMessage::InferiorStdout(i.to_owned()).into())
    }
}

lazy_static! {
    // GDB machine interface output patterns to match
    // https://sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI-Stream-Records.html

    // https://sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI-Result-Records.html
    // In addition to a number of out-of-band notifications,
    // the response to a gdb/mi command includes one of the following result indications:
    // done, running, connected, error, exit
    static ref RESULT_RE: Regex = Regex::new(r"^(\d*)\^(\S+?)(,(.*))?$").unwrap();

    // https://sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI-Async-Records.html
    // Async records are used to notify the gdb/mi client of additional
    // changes that have occurred. Those changes can either be a consequence
    // of gdb/mi commands (e.g., a breakpoint modified) or a result of target activity
    // (e.g., target stopped).
    static ref NOTIFY_RE: Regex = Regex::new(r"^(\d*)[*=](\S+?),(.*)$").unwrap();

    // https://sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI-Stream-Records.html
    // "~" string-output
    // The console output stream contains text that should be displayed
    // in the CLI console window. It contains the textual responses to CLI commands.
    static ref CONSOLE_RE: Regex = Regex::new(r#"(?s)~"(.*)""#).unwrap();

    // https://sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI-Stream-Records.html
    // "&" string-output
    // The log stream contains debugging messages being produced by gdb's internals.
    static ref LOG_RE: Regex = Regex::new(r#"(?s)&"(.*)""#).unwrap();

    // https://sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI-Stream-Records.html
    // "@" string-output
    // The target output stream contains any textual output from the
    // running target. This is only present when GDB's event loop is truly asynchronous,
    // which is currently only the case for remote targets.
    static ref TARGET_OUTPUT_RE: Regex = Regex::new(r#"(?s)@"(.*)""#).unwrap();

    // Response finished
    static ref RESPONSE_FINISHED_RE: Regex = Regex::new(r"^\(gdb\)\s*$").unwrap();
}

const WHITESPACE: [u8; 4] = [b' ', b'\t', b'\r', b'\n'];
const DICT_START: u8 = b'{';
const DICT_END: u8 = b'}';
const ARRAY_START: u8 = b'[';
const ARRAY_END: u8 = b']';
const STRING_START: u8 = b'"';
const VALUE_SEP: u8 = b',';
const VALUE_STARTS: [u8; 3] = [DICT_START, ARRAY_START, STRING_START];

fn get_notify_msg_and_payload(stream: &mut StringStream) -> Result<(Option<Token>, String, Dict)> {
    let token = stream.advance_past_chars(&['=', '*']);
    let token = parse_token_maybe_empty(token)?;
    let message = stream.advance_past_chars(&[',']).trim().to_owned();
    let payload = parse_dict(stream)?;
    Ok((token, message, payload))
}

fn get_result_msg_and_payload(
    full: &str,
    stream: &mut StringStream,
) -> Result<(Option<Token>, String, Option<Dict>)> {
    let caps = RESULT_RE
        .captures(full)
        .ok_or_else(|| Error::ExpectedResultMsg(full.into()))?;

    let token = caps.get(1).unwrap().as_str();
    let token = parse_token_maybe_empty(token)?;

    let message = caps.get(2).unwrap().as_str().to_owned();

    let payload = if caps.get(3).is_some() {
        stream.advance_past_chars(&[VALUE_SEP as char]);
        Some(parse_dict(stream)?)
    } else {
        None
    };

    Ok((token, message, payload))
}

/// Parse dictionary, with optional starting character '{'
/// return (tuple):
///     Number of characters parsed from to_parse
///     Parsed dictionary
fn parse_dict(stream: &mut StringStream) -> Result<Dict> {
    let mut obj: HashMap<String, Value> = HashMap::new();

    loop {
        let c = stream.read(1).as_bytes();
        if c.is_empty() || c[0] == DICT_END {
            break;
        }
        let c = c[0];

        if WHITESPACE.contains(&c) || c == DICT_START || c == VALUE_SEP {
            continue;
        }

        stream.seek_back(1);
        let (key, val) = parse_key_val(stream)?;

        if let Some(existing) = obj.remove(&key) {
            // This is a gdb bug. We should never get repeated keys in a dict!
            // See https://sourceware.org/bugzilla/show_bug.cgi?id=22217
            // and https://github.com/cs01/pygdbmi/issues/19
            // Example:
            //   thread-ids={thread-id="1",thread-id="2"}
            // Results in:
            //   thread-ids: {{'thread-id': ['1', '2']}}
            // Rather than the lossy
            //   thread-ids: {'thread-id': 2}  # '1' got overwritten!
            let entry = existing.into_appended(val);
            obj.insert(key, entry);
        } else {
            obj.insert(key, val);
        }

        let mut lookahead_for_garbage = true;
        let mut c = stream.read(1).as_bytes();
        while lookahead_for_garbage {
            if c.is_empty() || c[0] == DICT_END || c[0] == VALUE_SEP {
                lookahead_for_garbage = false;
            } else {
                c = stream.read(1).as_bytes();
            }
        }
        stream.seek_back(1);
    }

    Ok(Dict::new(obj))
}

fn parse_key_val(stream: &mut StringStream) -> Result<(String, Value)> {
    let key = parse_key(stream);
    let val = parse_val(stream)?;
    Ok((key, val))
}

fn parse_key(stream: &mut StringStream) -> String {
    stream.advance_past_chars(&['=']).to_owned()
}

fn parse_val(stream: &mut StringStream) -> Result<Value> {
    let c = stream.read(1);
    if c.is_empty() {
        return Err(Error::ExpectedDictValueUnexpectedEof);
    }
    let c = c.as_bytes()[0];

    match c {
        DICT_START => Ok(Value::Dict(parse_dict(stream)?)),
        ARRAY_START => Ok(Value::List(parse_array(stream)?)),
        b'"' => {
            let val = stream.advance_past_string_with_gdb_escapes();
            Ok(Value::String(val))
        }
        _ => Err(Error::ExpectedDictValueUnexpectedChar(c as char)),
    }
}

fn parse_token_maybe_empty(i: &str) -> Result<Option<Token>> {
    if i.is_empty() {
        Ok(None)
    } else {
        let token = parse_token(i)?;
        Ok(Some(token))
    }
}

fn parse_token(i: &str) -> Result<Token> {
    i.parse()
        .map(Token)
        .map_err(|err| Error::TokenParse(i.to_owned(), err))
}

/// Parse an array, stream should be passed the initial [
fn parse_array(stream: &mut StringStream) -> Result<List> {
    let mut arr = Vec::new();
    loop {
        let c = stream.read(1);
        if c.is_empty() {
            break;
        }
        let c = c.as_bytes()[0];

        if VALUE_STARTS.contains(&c) {
            stream.seek_back(1);
            let val = parse_val(stream)?;
            arr.push(val);
        } else if WHITESPACE.contains(&c) || c == VALUE_SEP {
            continue;
        } else if c == ARRAY_END {
            // Stop when this array has finished. Note
            // that elements of this array can be also be arrays.
            break;
        }
    }
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use pretty_assertions::assert_eq;

    type Result = eyre::Result<()>;

    #[test]
    fn test_parse_basic() -> Result {
        assert_eq!(
            Message::from(Response::Result {
                token: None,
                message: "done".into(),
                payload: None
            }),
            parse_message("^done")?
        );

        assert_eq!(
            Message::from(GeneralMessage::Console("done".into())),
            parse_message(r#"~"done""#)?
        );

        assert_eq!(
            Message::from(GeneralMessage::Target("done".into())),
            parse_message(r#"@"done""#)?
        );

        assert_eq!(
            Message::from(GeneralMessage::Log("done".into())),
            parse_message(r#"&"done""#)?
        );

        assert_eq!(
            Message::from(GeneralMessage::InferiorStdout("done".into())),
            parse_message("done")?
        );

        Ok(())
    }

    #[test]
    fn test_parse_basic_with_token() -> Result {
        assert_eq!(
            Message::from(Response::Result {
                token: Some(Token(544760273)),
                message: "done".into(),
                payload: None
            }),
            parse_message("544760273^done")?
        );

        Ok(())
    }

    #[test]
    fn test_escape_sequences() -> Result {
        assert_eq!(
            Message::from(GeneralMessage::Console("".into())),
            parse_message(r#"~"""#)?
        );

        assert_eq!(
            Message::from(GeneralMessage::Console(r#"\b\f\n\r\t""#.into())),
            parse_message(r#"~"\b\f\n\r\t"""#)?
        );

        assert_eq!(
            Message::from(GeneralMessage::Target("".into())),
            parse_message(r#"@"""#)?
        );

        assert_eq!(
            Message::from(GeneralMessage::Target(r#"\b\f\n\r\t""#.into())),
            parse_message(r#"@"\b\f\n\r\t"""#)?
        );

        assert_eq!(
            Message::from(GeneralMessage::Log("".into())),
            parse_message(r#"&"""#)?
        );

        assert_eq!(
            Message::from(GeneralMessage::Log(r#"\b\f\n\r\t""#.into())),
            parse_message(r#"&"\b\f\n\r\t"""#)?
        );

        // test that an escaped backslash gets captured
        assert_eq!(
            Message::from(GeneralMessage::Log(r"\".into())),
            parse_message(r#"&"\""#)?,
        );

        Ok(())
    }

    #[test]
    fn test_repeated_dict_key_workaround() -> Result {
        // See https://sourceware.org/bugzilla/show_bug.cgi?id=22217
        // and https://github.com/cs01/pygdbmi/issues/19
        let mut payload = HashMap::new();

        let mut thread_ids = HashMap::new();
        thread_ids.insert(
            "thread-id".into(),
            Value::List(vec![
                Value::String("3".into()),
                Value::String("2".into()),
                Value::String("1".into()),
            ]),
        );
        payload.insert("thread-ids".into(), Value::Dict(Dict::new(thread_ids)));

        payload.insert("current-thread-id".into(), Value::String("1".into()));

        payload.insert("number-of-threads".into(), Value::String("3".into()));

        let expected: Message = Response::Result {
            token: None,
            message: "done".into(),
            payload: Some(Dict::new(payload)),
        }
        .into();

        let actual = parse_message(
            r#"^done,thread-ids={thread-id="3",thread-id="2",thread-id="1"}, current-thread-id="1",number-of-threads="3""#,
        )?;

        assert_eq!(expected, actual);

        Ok(())
    }

    #[test]
    fn test_real_world_dict() -> Result {
        let mut bkpt = HashMap::new();
        bkpt.insert("addr".into(), Value::String("0x000000000040059c".into()));
        bkpt.insert("disp".into(), Value::String("keep".into()));
        bkpt.insert("enabled".into(), Value::String("y".into()));
        bkpt.insert("file".into(), Value::String("hello.c".into()));
        bkpt.insert(
            "fullname".into(),
            Value::String("/home/git/pygdbmi/tests/sample_c_app/hello.c".into()),
        );
        bkpt.insert("func".into(), Value::String("main".into()));
        bkpt.insert("line".into(), Value::String("9".into()));
        bkpt.insert("number".into(), Value::String("1".into()));
        bkpt.insert("empty_arr".into(), Value::List(vec![]));
        bkpt.insert(
            "original-location".into(),
            Value::String("hello.c:9".into()),
        );
        bkpt.insert(
            "thread-groups".into(),
            Value::List(vec![Value::String("i1".into())]),
        );
        bkpt.insert("times".into(), Value::String("1".into()));
        bkpt.insert("type".into(), Value::String("breakpoint".into()));

        let mut payload = HashMap::new();
        payload.insert("bkpt".into(), Value::Dict(Dict::new(bkpt)));

        let expected: Message = Response::Notify {
            message: "breakpoint-modified".into(),
            payload: Dict::new(payload),
            token: None,
        }
        .into();

        let actual = parse_message(
            r#"=breakpoint-modified,bkpt={number="1",empty_arr=[],type="breakpoint",disp="keep",enabled="y",addr="0x000000000040059c",func="main",file="hello.c",fullname="/home/git/pygdbmi/tests/sample_c_app/hello.c",line="9",thread-groups=["i1"],times="1",original-location="hello.c:9"}"#,
        )?;

        assert_eq!(expected, actual);

        Ok(())
    }

    #[test]
    fn test_record_with_token() -> Result {
        assert_eq!(
            Message::from(Response::Result {
                payload: None,
                message: "done".into(),
                token: Some(Token(1342)),
            }),
            parse_message("1342^done")?
        );

        Ok(())
    }

    #[test]
    fn test_extra_characters_at_end_of_dict_are_discarded() -> Result {
        // See pygdbmi issue #30
        let mut payload = HashMap::new();
        payload.insert("name".into(), Value::String("gdb".into()));
        assert_eq!(
            Message::from(Response::Notify {
                message: "event".into(),
                payload: Dict::new(payload),
                token: None,
            }),
            parse_message(r#"=event,name="gdb"discardme"#)?,
        );
        Ok(())
    }
}
