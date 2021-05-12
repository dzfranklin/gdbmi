use lazy_static::lazy_static;
use regex::Regex;

use crate::Error;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Checkpoint(pub u32);

pub(super) fn parse_save_line(line: &str) -> Result<Checkpoint, Error> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^Checkpoint (\d+) at").unwrap();
    }

    let num: u32 = RE
        .captures(line)
        .ok_or(Error::ExpectedDifferentConsole)?
        .get(1)
        .unwrap()
        .as_str()
        .parse()?;

    Ok(Checkpoint(num))
}
