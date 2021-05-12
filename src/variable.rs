use crate::{raw, Error};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Variable {
    pub name: String,
    pub var_type: String,
    pub value: Option<String>,
    /// If this is an argument to a function
    pub is_arg: bool,
}

impl Variable {
    pub fn from_value(payload: raw::Value) -> Result<Self, Error> {
        let mut payload = payload.expect_dict()?;
        let name = payload.remove_expect("name")?.expect_string()?;
        let var_type = payload.remove_expect("type")?.expect_string()?;
        let value = payload
            .remove("value")
            .map(raw::Value::expect_string)
            .transpose()?;
        let is_arg = payload
            .remove("arg")
            .map(raw::Value::expect_number)
            .transpose()?
            .unwrap_or(0)
            == 1;

        Ok(Self {
            name,
            var_type,
            value,
            is_arg,
        })
    }
}

pub(super) fn from_stack_list(mut payload: raw::Dict) -> Result<Vec<Variable>, Error> {
    payload
        .remove_expect("variables")?
        .expect_list()?
        .into_iter()
        .map(Variable::from_value)
        .collect()
}
