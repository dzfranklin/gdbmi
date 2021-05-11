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

    pub fn serialize(self) -> String {
        match self {
            Self::Line { file, num } => format!("{}:{}", file, num),
            Self::Function(name) => name,
            Self::FunctionExplicitFile { file, name } => format!("{}:{}", file, name),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Breakpoint {
    pub number: u32,
    pub addr: u64,
    pub file: Utf8PathBuf,
    pub line: u32,
    pub thread_groups: Vec<String>,
    pub times: u32,
}

impl Breakpoint {
    pub fn from_raw(mut raw: raw::Dict) -> Result<Self, Error> {
        let number = raw.remove_expect("number")?.expect_number()?;
        let addr = raw.remove_expect("addr")?.expect_hex()?;
        let file = raw.remove_expect("fullname")?.expect_path()?;
        let line = raw.remove_expect("line")?.expect_number()?;
        let times = raw.remove_expect("times")?.expect_number()?;

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
