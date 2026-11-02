use std::env;
use std::io::Read;
use std::process::{Command, Stdio};

const CHILD_MARKER: &str = "fixture-child-ready";

fn main() {
    let mode = env::args().nth(1);
    if mode.as_deref() == Some("child") {
        println!("{CHILD_MARKER}");
        return;
    }
    let executable = env::current_exe().expect("current executable");
    let mut child = Command::new(executable)
        .arg("child")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");
    let mut stdout = child.stdout.take().expect("child stdout");
    let mut output = String::new();
    stdout.read_to_string(&mut output).expect("read output");
    let status = child.wait().expect("wait for child");
    assert!(status.success());
    assert_eq!(output.trim(), CHILD_MARKER);
}
