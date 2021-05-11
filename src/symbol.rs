use crate::{raw, Error};
use camino::Utf8PathBuf;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub line: u32,
    pub name: String,
    pub function_type: String,
    pub description: String,
}

pub(crate) fn from_symbol_info_functions_payload(
    mut payload: raw::Dict,
) -> Result<HashMap<Utf8PathBuf, Vec<Function>>, Error> {
    let raw = payload
        .remove_expect("symbols")?
        .expect_dict()?
        .remove_expect("debug")?
        .expect_list()?;

    let mut files = HashMap::new();

    for group in raw {
        let mut group = group.expect_dict()?;

        let filename = group.remove_expect("filename")?.expect_path()?;

        let mut symbols = Vec::new();
        let raw_symbols = group.remove_expect("symbols")?.expect_list()?;
        for raw in raw_symbols {
            let mut raw = raw.expect_dict()?;
            let line = raw.remove_expect("line")?.expect_number()?;
            let name = raw.remove_expect("name")?.expect_string()?;
            let symbol_type = raw.remove_expect("type")?.expect_string()?;
            let description = raw.remove_expect("description")?.expect_string()?;

            symbols.push(Function {
                line,
                name,
                function_type: symbol_type,
                description,
            });
        }

        files.insert(filename, symbols);
    }

    Ok(files)
}
