use camino::Utf8PathBuf;

use crate::{address::Address, raw, Error};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Frame {
    pub level: u32,
    pub address: Address,
    pub function: Option<String>,
    pub file: Option<Utf8PathBuf>,
    pub line: Option<u32>,
}

impl Frame {
    pub fn from_dict(mut raw: raw::Dict) -> Result<Self, Error> {
        let level = raw.remove_expect("level")?.expect_number()?;
        let address = raw.remove_expect("addr")?.expect_address()?;
        let function = raw
            .remove("func")
            .map(raw::Value::expect_string)
            .transpose()?;
        let file = raw
            .remove("fullname")
            .map(raw::Value::expect_path)
            .transpose()?;
        let line = raw
            .remove("line")
            .map(raw::Value::expect_number)
            .transpose()?;
        Ok(Self {
            level,
            address,
            function,
            file,
            line,
        })
    }
}
