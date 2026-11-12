use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

const SOURCE_CANARY: &str = "SYNTHETIC_SOURCE_CANARY_7f8c";
const KEY_CANARY: &str = "KEYCANARY-73A10X";
const COMMAND_CANARIES: [&str; 3] = [
    "::add-mask::SYNTHETIC_SOURCE_CANARY_7f8c",
    "::error::SYNTHETIC_SOURCE_CANARY_7f8c",
    "::set-output name=x::SYNTHETIC_SOURCE_CANARY_7f8c",
];

pub fn render_number(value: u32) -> String {
    let mut buffer = itoa::Buffer::new();
    devlane_rehearsal_support::own(buffer.format(value))
}

fn key_hex() -> String {
    let mut bytes = KEY_CANARY.as_bytes().to_vec();
    bytes.extend(0u8..16);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn emit_canaries() {
    for canary in COMMAND_CANARIES.iter().chain([&SOURCE_CANARY, &KEY_CANARY]) {
        let _ = writeln!(std::io::stdout(), "{canary}");
        let _ = writeln!(std::io::stderr(), "{canary}");
    }
    let group = format!(
        "{}{}[group]SYNTHETIC_SOURCE_CANARY_7f8c",
        char::from(35),
        char::from(35),
    );
    let _ = writeln!(std::io::stdout(), "{group}");
    let _ = writeln!(std::io::stderr(), "{group}");
}

fn scan_key_bytes(directory: &Path, expected: &str, depth: usize) {
    if depth > 6 {
        return;
    }
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue;
        }
        if name == "node_modules" || name == "cargo-home" || name == "npm-cache" {
            continue;
        }
        if file_type.is_dir() {
            scan_key_bytes(&path, expected, depth + 1);
        } else if file_type.is_file() {
            if let Ok(metadata) = path.metadata() {
                if metadata.len() < 1_048_576 {
                    if let Ok(bytes) = fs::read(path) {
                        let encoded = bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>();
                        assert!(!encoded.contains(expected), "key-file-boundary");
                    }
                }
            }
        }
    }
}

fn assert_isolation_boundaries() {
    let key = key_hex();
    for (name, value) in std::env::vars() {
        assert_ne!(name, "DEVLANE_DECRYPT_KEY", "environment-name-boundary");
        assert!(!name.starts_with("GITHUB_"), "github-environment-boundary");
        assert!(!name.starts_with("RUNNER_"), "runner-environment-boundary");
        assert!(
            !name.starts_with("ACTIONS_"),
            "actions-environment-boundary"
        );
        assert!(
            !value.contains(KEY_CANARY) && !value.contains(&key),
            "environment-value-boundary"
        );
    }
    assert!(
        !std::env::args().any(|value| value.contains(KEY_CANARY) || value.contains(&key)),
        "argument-boundary"
    );

    if cfg!(target_os = "linux") {
        let environ = fs::read("/proc/self/environ").expect("proc-environ");
        let environ = String::from_utf8_lossy(&environ);
        assert!(
            !environ.contains("DEVLANE_DECRYPT_KEY"),
            "proc-environ-name-boundary"
        );
        assert!(
            !environ.contains(KEY_CANARY) && !environ.contains(&key),
            "proc-environ-value-boundary"
        );

        for entry in fs::read_dir("/proc/self/fd").expect("proc-fd") {
            if let Ok(target) = fs::read_link(entry.expect("proc-fd-entry").path()) {
                assert!(
                    !target.to_string_lossy().starts_with("socket:["),
                    "descriptor-boundary"
                );
            }
        }

        let proc_runner_home = "/proc/1/root/ho".to_owned() + "me/runner";
        assert!(
            !Path::new(&proc_runner_home).exists(),
            "host-path-boundary"
        );

        let process_count = fs::read_dir("/proc")
            .expect("proc-root")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
            })
            .count();
        assert!(process_count <= 64, "process-visibility-boundary");
    }

    for forbidden in [
        "/ho".to_owned() + "me/runner",
        "/run/docker.sock".to_owned(),
        "/var/run/docker.sock".to_owned(),
    ] {
        assert!(!Path::new(&forbidden).exists(), "host-path-boundary");
    }

    for root in [
        "/trusted",
        "/workspace/source",
        "/tmp",
        "/devlane-home",
        "/scratch/tmp",
        "/scratch/reports",
    ] {
        scan_key_bytes(Path::new(root), &key, 0);
    }

    let public = SocketAddr::from(([1, 1, 1, 1], 443));
    assert!(
        TcpStream::connect_timeout(&public, Duration::from_millis(300)).is_err(),
        "network-boundary"
    );
    emit_canaries();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_has_no_control_secrets_or_sockets() {
        assert_isolation_boundaries();
        assert_eq!(render_number(7), "7");
        let _ = fastrand::u8(..);
        assert!(SOURCE_CANARY.contains("SYNTHETIC_SOURCE_CANARY"));
    }
}
