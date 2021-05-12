use duct::cmd;
use lazy_static::lazy_static;
use std::{
    collections::HashSet,
    sync::{Mutex, Once},
};

static INIT: Once = Once::new();

pub fn init() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .pretty()
            .init();

        color_eyre::install().unwrap();
    });
}

pub type Result = eyre::Result<()>;

lazy_static! {
    static ref RECORDED: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    static ref BUILT: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

pub fn build(name: &str) -> String {
    let mut built = BUILT.lock().unwrap();
    if !built.contains(name) {
        cmd!(
            "cargo",
            "build",
            "-Z",
            "unstable-options",
            "--out-dir",
            "../.out"
        )
        .dir(format!("samples/{}", name))
        .stdin_null()
        .stdout_null()
        .stderr_null()
        .run()
        .expect("Failed to build sample");
        built.insert(name.to_owned());
    }
    format!("samples/.out/{}", name)
}

#[cfg(feature = "test_rr")]
pub fn record(name: &str) -> String {
    let trace_out = format!("samples/.trace/{}", name);

    let mut recorded = RECORDED.lock().unwrap();
    if !recorded.contains(name) {
        let bin = build(name);

        cmd!("mkdir", "-p", "samples/.trace").run().unwrap();
        let _result = cmd!("rm", "-rf", &trace_out).run();

        cmd!("rr", "record", "--output-trace-dir", &trace_out, bin)
            .stdin_null()
            .stdout_null()
            .stderr_null()
            .run()
            .expect("Failed to record sample");

        recorded.insert(name.to_owned());
    }

    trace_out
}

pub fn build_hello_world() -> String {
    build("hello_world")
}

#[cfg(feature = "test_rr")]
pub fn record_hello_world() -> String {
    record("hello_world")
}
