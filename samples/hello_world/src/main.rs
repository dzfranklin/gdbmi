use std::thread;
use std::time::Duration;

#[derive(Debug)]
struct HelloMsg {
    msg: String,
}

impl HelloMsg {
    fn say(&self) {
        println!("{}", self.msg);
    }
}

fn main() {
    let msg = HelloMsg {
        msg: "Hello world!".into(),
    };
    thread::sleep(Duration::from_secs(1));
    msg.say();
}
