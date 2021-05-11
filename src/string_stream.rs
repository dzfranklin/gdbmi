pub(crate) struct StringStream {
    raw_text: String,
    index: usize,
}

impl StringStream {
    pub(crate) fn new(raw_text: String) -> Self {
        Self { raw_text, index: 0 }
    }

    /// Read count characters starting at self.index, and return those characters as a string
    pub(crate) fn read(&mut self, count: usize) -> &str {
        let new_index = self.index + count;
        let buf = if new_index > self.raw_text.len() {
            &self.raw_text[self.index..]
        } else {
            &self.raw_text[self.index..new_index]
        };
        self.index = new_index;
        buf
    }

    pub(crate) fn seek_back(&mut self, offset: usize) {
        self.index = self.index.saturating_sub(offset);
    }

    /// Advance the index past specific chars
    ///
    /// Return substring that was advanced past
    pub(crate) fn advance_past_chars(&mut self, chars: &[char]) -> &str {
        let start_index = self.index;
        loop {
            let current_char = self.raw_text.as_bytes()[self.index] as char;
            self.index += 1;
            if chars.contains(&current_char) || self.index == self.raw_text.len() {
                break;
            }
        }
        &self.raw_text[start_index..self.index - 1]
    }

    /// Characters that gdb escapes that should not be escaped by this parser
    pub(crate) fn advance_past_string_with_gdb_escapes(&mut self) -> String {
        let mut buf = String::new();
        loop {
            let c = self.raw_text.as_bytes()[self.index] as char;
            self.index += 1;

            match c {
                '\\' => {
                    // We are on a backslash and there is another character after the backslash
                    // to parse. Handle this case specially since gdb escaped it for

                    // Get the next char that is being escaped
                    let c2 = self.raw_text.as_bytes()[self.index] as char;
                    self.index += 1;
                    // only store the escaped character in the buffer; don't store the backslash
                    // (don't leave it escaped)
                    buf.push(c2);
                }
                '"' => {
                    // Quote is closed. Exit (and don't include the end quote).
                    break;
                }
                c => {
                    // capture this character, and keep capturing
                    buf.push(c);
                }
            }
        }
        buf
    }
}
