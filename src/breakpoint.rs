use camino::Utf8PathBuf;

use crate::{raw, Error};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LineSpec {
    Line { file: Utf8PathBuf, num: u32 },
    Function(String),
    FunctionExplicitFile { file: Utf8PathBuf, name: String },
}

impl LineSpec {
    pub fn line(file: impl Into<Utf8PathBuf>, num: u32) -> Self {
        Self::Line {
            file: file.into(),
            num,
        }
    }

    pub fn function(name: impl Into<String>) -> Self {
        Self::Function(name.into())
    }

    pub fn function_with_explicit_file(
        file: impl Into<Utf8PathBuf>,
        name: impl Into<String>,
    ) -> Self {
        Self::FunctionExplicitFile {
            file: file.into(),
            name: name.into(),
        }
    }

    #[must_use]
    pub fn serialize(self) -> String {
        match self {
            Self::Line { file, num } => format!("{}:{}", file, num),
            Self::Function(name) => name,
            Self::FunctionExplicitFile { file, name } => format!("{}:{}", file, name),
        }
    }
}

// TODO: This doesn't include all the potential outputs of gdb.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Breakpoint {
    pub number: u32,
    pub addr: Addr,
    pub file: Option<Utf8PathBuf>,
    pub line: Option<u32>,
    pub thread_groups: Vec<String>,
    pub times: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Addr {
    Value(u64),
    Pending,
    Multiple,
    Unknown,
}

impl Breakpoint {
    pub fn from_raw(mut raw: raw::Dict) -> Result<Self, Error> {
        let number = raw.remove_expect("number")?.expect_number()?;
        let times = raw.remove_expect("times")?.expect_number()?;

        let line = raw
            .remove("line")
            .map(raw::Value::expect_number)
            .transpose()?;

        let file = raw
            .remove("fullname")
            .map(raw::Value::expect_path)
            .transpose()?;

        let addr = if let Some(addr) = raw.as_map_mut().remove("addr") {
            let addr = addr.expect_string()?;
            match addr.as_str() {
                "<PENDING>" => Addr::Pending,
                "<MULTIPLE>" => Addr::Multiple,
                addr => Addr::Value(raw::parse_hex(addr)?),
            }
        } else {
            Addr::Unknown
        };

        let thread_groups = raw
            .remove_expect("thread-groups")?
            .expect_list()?
            .into_iter()
            .map(raw::Value::expect_string)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            number,
            addr,
            file,
            line,
            thread_groups,
            times,
        })
    }
}
