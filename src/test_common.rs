use duct::cmd;
use std::{sync::Once, time::Duration};

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

pub const TIMEOUT: Duration = Duration::from_secs(5);

pub fn build_hello_world() -> eyre::Result<String> {
    cmd!(
        "cargo",
        "build",
        "-Z",
        "unstable-options",
        "--out-dir",
        "../.out"
    )
    .dir("samples/hello_world")
    .run()?;
    Ok("samples/.out/hello_world".into())
}
