use std::thread;
use std::time::Duration;

#[derive(Debug)]
struct HelloMsg {
    msg: String,
}

fn main() {
    let msg = HelloMsg {
        msg: "Hello world!".into(),
    };
    thread::sleep(Duration::from_secs(1));
    println!("{}", msg.msg);
}
