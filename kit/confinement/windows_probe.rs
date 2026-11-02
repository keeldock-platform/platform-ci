use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::windows::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use std::time::Duration;

extern "system" {
    fn WSAStartup(version: u16, data: *mut u8) -> i32;
}

fn code(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(value) => format!("err{}", value),
        None => String::from("errnone"),
    }
}

fn wsa_ready() -> bool {
    let mut data = [0u8; 512];
    let result = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
    result == 0
}

fn probe_wsa() -> String {
    let mut data = [0u8; 512];
    let result = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
    format!("rc={}", result)
}

fn probe_connect(target: &str) -> String {
    if !wsa_ready() {
        return String::from("wsa=failed");
    }
    let addresses: Vec<SocketAddr> = match target.to_socket_addrs() {
        Ok(list) => list.collect(),
        Err(error) => return format!("resolve={}", code(&error)),
    };
    if addresses.is_empty() {
        return String::from("resolve=empty");
    }
    let mut last = String::from("none");
    for address in addresses.iter().take(2) {
        match TcpStream::connect_timeout(address, Duration::from_secs(8)) {
            Ok(_) => return String::from("resolve=ok connect=open"),
            Err(error) => last = code(&error),
        }
    }
    format!("resolve=ok connect={}", last)
}

fn probe_dns(host: &str) -> String {
    if !wsa_ready() {
        return String::from("wsa=failed");
    }
    match (host, 443u16).to_socket_addrs() {
        Ok(list) => format!("resolve=ok count={}", list.count()),
        Err(error) => format!("resolve={}", code(&error)),
    }
}

fn probe_udp(target: &str) -> String {
    if !wsa_ready() {
        return String::from("wsa=failed");
    }
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(value) => value,
        Err(error) => return format!("bind={}", code(&error)),
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
    let query: [u8; 29] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    if let Err(error) = socket.send_to(&query, target) {
        return format!("send={}", code(&error));
    }
    let mut reply = [0u8; 512];
    match socket.recv_from(&mut reply) {
        Ok(_) => String::from("send=ok recv=data"),
        Err(error) => format!("send=ok recv={}", code(&error)),
    }
}

fn open_state(options: &mut OpenOptions, path: &str) -> String {
    match options.open(path) {
        Ok(_) => String::from("ok"),
        Err(error) => code(&error),
    }
}

fn probe_nul() -> String {
    let read = open_state(OpenOptions::new().read(true), "NUL");
    let write = open_state(OpenOptions::new().write(true), "NUL");
    let both = open_state(OpenOptions::new().read(true).write(true), "NUL");
    let device = open_state(OpenOptions::new().read(true).write(true), "\\\\.\\NUL");
    format!("read={} write={} readwrite={} device={}", read, write, both, device)
}

fn probe_nuldac() -> String {
    match OpenOptions::new()
        .access_mode(0x0004_0000)
        .share_mode(3)
        .open("\\\\.\\NUL")
    {
        Ok(_) => String::from("result=ok"),
        Err(error) => format!("result={}", code(&error)),
    }
}

fn probe_write(path: &str) -> String {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => match file.write_all(b"kd") {
            Ok(_) => String::from("create=ok write=ok"),
            Err(error) => format!("create=ok write={}", code(&error)),
        },
        Err(error) => format!("create={}", code(&error)),
    }
}

fn probe_read(path: &str) -> String {
    match OpenOptions::new().read(true).open(path) {
        Ok(mut file) => {
            let mut buffer = [0u8; 16];
            match file.read(&mut buffer) {
                Ok(count) => format!("open=ok read=ok bytes={}", count),
                Err(error) => format!("open=ok read={}", code(&error)),
            }
        }
        Err(error) => format!("open={}", code(&error)),
    }
}

fn probe_list(path: &str) -> String {
    match fs::read_dir(path) {
        Ok(entries) => format!("list=ok count={}", entries.count()),
        Err(error) => format!("list={}", code(&error)),
    }
}

fn probe_stat(path: &str) -> String {
    match fs::metadata(path) {
        Ok(_) => String::from("stat=ok"),
        Err(error) => format!("stat={}", code(&error)),
    }
}

fn probe_stdin() -> String {
    let mut buffer = [0u8; 16];
    match std::io::stdin().read(&mut buffer) {
        Ok(0) => String::from("result=eof"),
        Ok(_) => String::from("result=data"),
        Err(error) => format!("result={}", code(&error)),
    }
}

fn status_text(outcome: std::io::Result<std::process::ExitStatus>) -> String {
    match outcome {
        Ok(status) => {
            if status.success() {
                String::from("result=ok")
            } else {
                String::from("result=fail")
            }
        }
        Err(error) => format!("result={}", code(&error)),
    }
}

fn probe_spawn(mode: &str) -> String {
    let executable = match env::current_exe() {
        Ok(value) => value,
        Err(error) => return format!("result={}", code(&error)),
    };
    let mut command = Command::new(executable);
    command.arg("echo");
    match mode {
        "inherit" => status_text(
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status(),
        ),
        "piped_no_null" => status_text(
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map(|output| output.status),
        ),
        "output" => status_text(command.output().map(|output| output.status)),
        _ => String::from("result=usage"),
    }
}

fn probe_tempdir() -> String {
    let dir = env::temp_dir();
    let exists = if dir.is_dir() { "yes" } else { "no" };
    let file = dir.join(format!("kd_t_{}.tmp", std::process::id()));
    let writable = match OpenOptions::new().write(true).create_new(true).open(&file) {
        Ok(handle) => {
            drop(handle);
            let _ = fs::remove_file(&file);
            "yes"
        }
        Err(_) => "no",
    };
    format!("exists={} writable={} path={}", exists, writable, dir.display())
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    let command = arguments.get(1).map(|value| value.as_str()).unwrap_or("");
    let first = arguments.get(2).map(|value| value.as_str()).unwrap_or("");
    let text = match command {
        "wsa" => probe_wsa(),
        "connect" => probe_connect(first),
        "dns" => probe_dns(first),
        "udp" => probe_udp(first),
        "nul" => probe_nul(),
        "nuldac" => probe_nuldac(),
        "write" => probe_write(first),
        "read" => probe_read(first),
        "list" => probe_list(first),
        "stat" => probe_stat(first),
        "stdin" => probe_stdin(),
        "spawn" => probe_spawn(first),
        "tempdir" => probe_tempdir(),
        "echo" => String::from("result=ok"),
        _ => String::from("usage"),
    };
    println!("kd-probe {} {}", command, text);
}
