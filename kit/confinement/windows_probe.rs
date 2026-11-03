use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

extern "system" {
    fn WSAStartup(version: u16, data: *mut u8) -> i32;
    fn GetLastError() -> u32;
    fn SetLastError(code: u32);
    fn CloseHandle(handle: isize) -> i32;
    fn GetCurrentProcess() -> isize;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
    fn CreateNamedPipeW(name: *const u16, open_mode: u32, pipe_mode: u32, instances: u32, out_size: u32, in_size: u32, timeout: u32, security: *mut u8) -> isize;
    fn RegisterEventSourceW(server: *const u16, source: *const u16) -> isize;
    fn DeregisterEventSource(handle: isize) -> i32;
    fn RegOpenKeyExW(key: isize, sub: *const u16, options: u32, access: u32, result: *mut isize) -> i32;
    fn RegCreateKeyExW(key: isize, sub: *const u16, reserved: u32, class: *const u16, options: u32, access: u32, security: *mut u8, result: *mut isize, disposition: *mut u32) -> i32;
    fn RegDeleteKeyW(key: isize, sub: *const u16) -> i32;
    fn RegCloseKey(key: isize) -> i32;
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> isize;
    fn CloseServiceHandle(handle: isize) -> i32;
    fn IsProcessInJob(process: isize, job: isize, result: *mut i32) -> i32;
    fn OpenProcessToken(process: isize, access: u32, token: *mut isize) -> i32;
    fn SetTokenInformation(token: isize, class: u32, information: *mut u8, length: u32) -> i32;
    fn AdjustTokenPrivileges(token: isize, disable_all: i32, state: *mut u8, length: u32, previous: *mut u8, returned: *mut u32) -> i32;
    fn CreateAppContainerProfile(name: *const u16, display: *const u16, description: *const u16, capabilities: *mut u8, count: u32, sid: *mut isize) -> i32;
    fn DeleteAppContainerProfile(name: *const u16) -> i32;
    fn FreeSid(sid: isize) -> isize;
    fn CoInitializeEx(reserved: *mut u8, flags: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(clsid: *const u8, outer: *mut u8, context: u32, iid: *const u8, object: *mut *mut u8) -> i32;
    fn SysAllocString(text: *const u16) -> *mut u16;
    fn SysFreeString(text: *mut u16);
    fn LoadLibraryExW(name: *const u16, file: isize, flags: u32) -> isize;
    fn GetProcAddress(module: isize, name: *const u8) -> usize;
    fn GetModuleHandleW(name: *const u16) -> isize;
    fn CreateFileW(name: *const u16, access: u32, share: u32, security: *mut u8, creation: u32, flags: u32, template: isize) -> isize;
    fn GetFinalPathNameByHandleW(handle: isize, buffer: *mut u16, length: u32, flags: u32) -> u32;
    fn QueryDosDeviceW(name: *const u16, target: *mut u16, length: u32) -> u32;
    fn CreateDirectoryW(path: *const u16, security: *mut u8) -> i32;
    fn RemoveDirectoryW(path: *const u16) -> i32;
    fn DeviceIoControl(handle: isize, code: u32, input: *mut u8, input_size: u32, output: *mut u8, output_size: u32, returned: *mut u32, overlapped: *mut u8) -> i32;
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0u16)).collect()
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

fn valid_token(text: &str, extra: &str, limit: usize) -> bool {
    !text.is_empty() && text.len() <= limit && text.chars().all(|value| value.is_ascii_alphanumeric() || extra.contains(value))
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
            Err(error) => {
                if last == "none" || last == "err10013" {
                    last = code(&error);
                }
            }
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

fn probe_append(path: &str) -> String {
    format!("open={}", open_state(OpenOptions::new().append(true), path))
}

fn probe_pipemake(mode: &str, id: &str) -> String {
    if !valid_token(id, "-", 40) {
        return String::from("create=usage");
    }
    let name = match mode {
        "root" => format!("\\\\.\\pipe\\kd-att-{}", id),
        "local" => format!("\\\\.\\pipe\\LOCAL\\kd-att-{}", id),
        _ => return String::from("create=usage"),
    };
    let name = wide(&name);
    let handle = unsafe { CreateNamedPipeW(name.as_ptr(), 3, 0, 1, 4096, 4096, 0, ptr::null_mut()) };
    if handle == -1 {
        let last = last_error();
        return format!("create=err{}", last);
    }
    unsafe {
        CloseHandle(handle);
    }
    String::from("create=ok")
}

fn probe_pipeopen(name: &str) -> String {
    if !valid_token(name, ".-_{}", 120) {
        return String::from("open=usage");
    }
    let path = format!("\\\\.\\pipe\\{}", name);
    format!("open={}", open_state(OpenOptions::new().read(true).write(true), &path))
}

fn probe_procopen(target: &str, class: &str) -> String {
    let pid: u32 = if target == "self" {
        std::process::id()
    } else {
        match target.parse::<u32>() {
            Ok(value) => value,
            Err(_) => return String::from("open=usage"),
        }
    };
    let access: u32 = match class {
        "vmread" => 0x1010,
        "environ" => 0x0410,
        "dup" => 0x1040,
        "debug" => 0x082A,
        _ => return String::from("open=usage"),
    };
    let handle = unsafe { OpenProcess(access, 0, pid) };
    if handle == 0 {
        let last = last_error();
        return format!("open=err{}", last);
    }
    unsafe {
        CloseHandle(handle);
    }
    String::from("open=ok")
}

fn probe_conout() -> String {
    format!("open={}", open_state(OpenOptions::new().write(true), "CONOUT$"))
}

fn probe_eventlog() -> String {
    let source = wide("Application");
    let handle = unsafe { RegisterEventSourceW(ptr::null(), source.as_ptr()) };
    if handle == 0 {
        let last = last_error();
        return format!("open=err{}", last);
    }
    unsafe {
        DeregisterEventSource(handle);
    }
    String::from("open=ok")
}

fn probe_envhunt(scope: &str) -> String {
    let mut found: u32 = 0;
    for (key, _) in env::vars_os() {
        let name = key.to_string_lossy().to_ascii_uppercase();
        let hit = match scope {
            "actions" => name.starts_with("ACTIONS_") || name.starts_with("GITHUB_") || name.starts_with("RUNNER_"),
            "proxy" => name.ends_with("_PROXY"),
            _ => return String::from("found=usage"),
        };
        if hit {
            found += 1;
        }
    }
    format!("found={}", found)
}

fn probe_marker() -> String {
    println!("::debug::kd-marker");
    String::from("text=ok")
}

fn hive(id: &str) -> Option<isize> {
    match id {
        "hkcu" => Some(0x8000_0001u32 as i32 as isize),
        "hklm" => Some(0x8000_0002u32 as i32 as isize),
        _ => None,
    }
}

fn probe_regread(id: &str) -> String {
    let root = match hive(id) {
        Some(value) => value,
        None => return String::from("open=usage"),
    };
    let sub = wide("Software\\KeelDock\\Canary");
    let mut key: isize = 0;
    let status = unsafe { RegOpenKeyExW(root, sub.as_ptr(), 0, 0x20019, &mut key) };
    if status != 0 {
        return format!("open=err{}", status);
    }
    unsafe {
        RegCloseKey(key);
    }
    String::from("open=ok")
}

fn probe_regcreate(id: &str) -> String {
    let root = match hive(id) {
        Some(value) => value,
        None => return String::from("create=usage"),
    };
    let sub = wide("Software\\KeelDock\\Att");
    let mut key: isize = 0;
    let mut disposition: u32 = 0;
    let status = unsafe { RegCreateKeyExW(root, sub.as_ptr(), 0, ptr::null(), 0, 0x20006, ptr::null_mut(), &mut key, &mut disposition) };
    if status != 0 {
        return format!("create=err{}", status);
    }
    let removed = unsafe {
        RegCloseKey(key);
        RegDeleteKeyW(root, sub.as_ptr())
    };
    if removed != 0 {
        return format!("create=ok delete=err{}", removed);
    }
    String::from("create=ok")
}

fn probe_dacopen(path: &str) -> String {
    match OpenOptions::new()
        .access_mode(0x0004_0000)
        .share_mode(7)
        .custom_flags(0x0200_0000)
        .open(path)
    {
        Ok(_) => String::from("open=ok"),
        Err(error) => format!("open={}", code(&error)),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn probe_walk(root: &str, seconds: &str, needle: &str) -> String {
    let limit = match seconds.parse::<u64>() {
        Ok(value) if value > 0 && value <= 600 => Duration::from_secs(value),
        _ => return String::from("scanned=0 found=usage"),
    };
    if needle.len() < 16 || needle.len() > 64 {
        return String::from("scanned=0 found=usage");
    }
    let started = Instant::now();
    let mut stack: Vec<(PathBuf, u32)> = vec![(PathBuf::from(root), 0)];
    let mut scanned: u64 = 0;
    let mut found = false;
    let mut buffer = vec![0u8; 65536];
    while let Some((directory, depth)) = stack.pop() {
        if found || started.elapsed() >= limit {
            break;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(value) => value,
            Err(_) => continue,
        };
        for entry in entries {
            if started.elapsed() >= limit {
                break;
            }
            let entry = match entry {
                Ok(value) => value,
                Err(_) => continue,
            };
            let meta = match entry.metadata() {
                Ok(value) => value,
                Err(_) => continue,
            };
            if meta.file_attributes() & 0x400 != 0 {
                continue;
            }
            if meta.is_dir() {
                if depth < 40 {
                    stack.push((entry.path(), depth + 1));
                }
            } else if meta.is_file() {
                scanned += 1;
                if let Ok(mut file) = fs::File::open(entry.path()) {
                    if let Ok(count) = file.read(&mut buffer) {
                        if contains_bytes(&buffer[..count], needle.as_bytes()) {
                            found = true;
                            break;
                        }
                    }
                }
            }
        }
    }
    format!("scanned={} found={}", scanned, if found { 1 } else { 0 })
}

fn probe_jobbreak() -> String {
    let executable = match env::current_exe() {
        Ok(value) => value,
        Err(error) => return format!("spawn={}", code(&error)),
    };
    let mut command = Command::new(executable);
    command.arg("echo");
    command.creation_flags(0x0100_0000);
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    match command.status() {
        Ok(_) => String::from("spawn=ok"),
        Err(error) => format!("spawn={}", code(&error)),
    }
}

fn probe_jobmember() -> String {
    let mut result: i32 = 0;
    let call = unsafe { IsProcessInJob(GetCurrentProcess(), 0, &mut result) };
    if call == 0 {
        let last = last_error();
        return format!("injob=err{}", last);
    }
    if result != 0 {
        String::from("injob=yes")
    } else {
        String::from("injob=no")
    }
}

fn probe_profile() -> String {
    let name = wide(&format!("kd-att-{}", std::process::id()));
    let mut sid: isize = 0;
    let hr = unsafe { CreateAppContainerProfile(name.as_ptr(), name.as_ptr(), name.as_ptr(), ptr::null_mut(), 0, &mut sid) };
    if hr < 0 {
        return format!("create=hr{:08x}", hr as u32);
    }
    let removed = unsafe {
        FreeSid(sid);
        DeleteAppContainerProfile(name.as_ptr())
    };
    if removed < 0 {
        return format!("create=ok delete=hr{:08x}", removed as u32);
    }
    String::from("create=ok")
}

fn probe_scm() -> String {
    let handle = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), 0x0003) };
    if handle == 0 {
        let last = last_error();
        return format!("open=err{}", last);
    }
    unsafe {
        CloseServiceHandle(handle);
    }
    String::from("open=ok")
}

fn probe_symlink(link: &str, target: &str) -> String {
    match std::os::windows::fs::symlink_file(target, link) {
        Ok(_) => String::from("create=ok"),
        Err(error) => format!("create={}", code(&error)),
    }
}

fn probe_hardlink(link: &str, existing: &str) -> String {
    match fs::hard_link(existing, link) {
        Ok(_) => String::from("create=ok"),
        Err(error) => format!("create={}", code(&error)),
    }
}

fn plain_path(path: &str) -> Result<(), &'static str> {
    let bytes = path.as_bytes();
    if bytes.len() < 4 {
        return Err("short");
    }
    if bytes.len() > 400 {
        return Err("long");
    }
    if !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err("root");
    }
    let rest = &path[3..];
    if !rest.bytes().all(|value| value.is_ascii_alphanumeric() || b"\\_.@-".contains(&value)) {
        return Err("char");
    }
    if rest.split('\\').any(|part| part.is_empty()) {
        return Err("empty");
    }
    if rest.split('\\').any(|part| part == "." || part == "..") {
        return Err("dot");
    }
    Ok(())
}

fn open_directory(path: &str, access: u32) -> Result<isize, u32> {
    let name = wide(path);
    let handle = unsafe { CreateFileW(name.as_ptr(), access, 7, ptr::null_mut(), 3, 0x0200_0000, 0) };
    if handle == -1 {
        Err(last_error())
    } else {
        Ok(handle)
    }
}

fn final_name(handle: isize, flags: u32) -> String {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, flags) };
    if length == 0 || length as usize >= buffer.len() {
        return format!("err{}", last_error());
    }
    String::from("ok")
}

fn handle_state(opened: &Result<isize, u32>) -> String {
    match opened {
        Ok(_) => String::from("ok"),
        Err(value) => format!("err{}", value),
    }
}

fn device_state(path: &str, access: u32) -> String {
    let name = wide(path);
    let handle = unsafe { CreateFileW(name.as_ptr(), access, 3, ptr::null_mut(), 3, 0, 0) };
    if handle == -1 {
        return format!("err{}", last_error());
    }
    unsafe {
        CloseHandle(handle);
    }
    String::from("ok")
}

fn probe_finalpath(dir: &str) -> String {
    if let Err(reason) = plain_path(dir) {
        return format!("open0=usage_{}", reason);
    }
    let opened = open_directory(dir, 0);
    let read_attributes = open_directory(dir, 0x0010_0080);
    let names: Vec<String> = match opened {
        Ok(handle) => [0u32, 2, 1, 4, 8, 10].iter().map(|flags| final_name(handle, *flags)).collect(),
        Err(_) => vec![String::from("na"); 6],
    };
    let ra_dos = match read_attributes {
        Ok(handle) => final_name(handle, 0),
        Err(_) => String::from("na"),
    };
    for item in [&opened, &read_attributes] {
        if let Ok(handle) = item {
            unsafe {
                CloseHandle(*handle);
            }
        }
    }
    let mpm = device_state("\\\\.\\MountPointManager", 0);
    let mpmr = device_state("\\\\.\\MountPointManager", 0x8000_0000);
    let device = wide(&format!("{}:", &dir[..1]));
    let mut target = vec![0u16; 4096];
    let count = unsafe { QueryDosDeviceW(device.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
    let qdd = if count == 0 { format!("err{}", last_error()) } else { String::from("ok") };
    let canon = match fs::canonicalize(dir) {
        Ok(_) => String::from("ok"),
        Err(error) => code(&error),
    };
    let mut line = format!("open0={} openra={} n_dos={}", handle_state(&opened), handle_state(&read_attributes), names[0]);
    if ra_dos != names[0] {
        line.push_str(&format!(" ra_dos={}", ra_dos));
    }
    line.push_str(&format!(
        " n_nt={} n_guid={} n_none={} o_dos={} o_nt={} mpm={} mpmr={} qdd={} canon={}",
        names[1], names[2], names[3], names[4], names[5], mpm, mpmr, qdd, canon
    ));
    line
}

fn push_u16(data: &mut Vec<u8>, value: usize) {
    data.extend_from_slice(&(value as u16).to_le_bytes());
}

fn push_text(data: &mut Vec<u8>, text: &[u16]) {
    for value in text {
        data.extend_from_slice(&value.to_le_bytes());
    }
}

fn remove_state(path: &[u16]) -> String {
    if unsafe { RemoveDirectoryW(path.as_ptr()) } == 0 {
        format!("err{}", last_error())
    } else {
        String::from("ok")
    }
}

fn probe_junction(link: &str, target: &str, mode: &str) -> String {
    let usage = if let Err(reason) = plain_path(link) {
        format!("link_{}", reason)
    } else if let Err(reason) = plain_path(target) {
        format!("target_{}", reason)
    } else if (mode != "" && mode != "new") || link.eq_ignore_ascii_case(target) {
        String::from("args")
    } else {
        String::new()
    };
    if !usage.is_empty() {
        return format!("mkdir=usage_{} open=na fsctl=na readback=na remove=na", usage);
    }
    let link_name = wide(link);
    let target_name = wide(target);
    if mode == "new" && unsafe { CreateDirectoryW(target_name.as_ptr(), ptr::null_mut()) } == 0 {
        return format!("mkdir=err{} open=na fsctl=na readback=na remove=na", last_error());
    }
    let finish = |text: String| -> String {
        if mode == "new" {
            unsafe {
                RemoveDirectoryW(target_name.as_ptr());
            }
        }
        text
    };
    if unsafe { CreateDirectoryW(link_name.as_ptr(), ptr::null_mut()) } == 0 {
        return finish(format!("mkdir=err{} open=na fsctl=na readback=na remove=na", last_error()));
    }
    let handle = unsafe { CreateFileW(link_name.as_ptr(), 0x4000_0000, 0, ptr::null_mut(), 3, 0x0220_0000, 0) };
    if handle == -1 {
        let opened = last_error();
        let removed = remove_state(&link_name);
        return finish(format!("mkdir=ok open=err{} fsctl=na readback=na remove={}", opened, removed));
    }
    let substitute: Vec<u16> = format!("\\??\\{}", target).encode_utf16().collect();
    let print: Vec<u16> = target.encode_utf16().collect();
    let path_bytes = (substitute.len() + 1 + print.len() + 1) * 2;
    let mut data: Vec<u8> = Vec::with_capacity(16 + path_bytes);
    data.extend_from_slice(&0xA000_0003u32.to_le_bytes());
    push_u16(&mut data, 8 + path_bytes);
    push_u16(&mut data, 0);
    push_u16(&mut data, 0);
    push_u16(&mut data, substitute.len() * 2);
    push_u16(&mut data, (substitute.len() + 1) * 2);
    push_u16(&mut data, print.len() * 2);
    push_text(&mut data, &substitute);
    push_u16(&mut data, 0);
    push_text(&mut data, &print);
    push_u16(&mut data, 0);
    let mut returned: u32 = 0;
    let set = unsafe { DeviceIoControl(handle, 0x0009_00A4, data.as_mut_ptr(), data.len() as u32, ptr::null_mut(), 0, &mut returned, ptr::null_mut()) };
    let fsctl = if set == 0 { format!("err{}", last_error()) } else { String::from("ok") };
    let readback = if set == 0 {
        String::from("na")
    } else {
        let mut output = vec![0u8; 16384];
        let got = unsafe { DeviceIoControl(handle, 0x0009_00A8, ptr::null_mut(), 0, output.as_mut_ptr(), output.len() as u32, &mut returned, ptr::null_mut()) };
        if got == 0 {
            format!("err{}", last_error())
        } else if returned >= 4 && output[..4] == 0xA000_0003u32.to_le_bytes() {
            String::from("ok")
        } else {
            String::from("err13")
        }
    };
    unsafe {
        CloseHandle(handle);
    }
    let removed = remove_state(&link_name);
    finish(format!("mkdir=ok open=ok fsctl={} readback={} remove={}", fsctl, readback, removed))
}

fn probe_mountmgr(mode: &str) -> String {
    let access: u32 = match mode {
        "dac" => 0x0004_0000,
        "write" => 0x4000_0000,
        _ => return String::from("open=usage"),
    };
    format!("open={}", device_state("\\\\.\\MountPointManager", access))
}

fn probe_objdac(kind: &str, drive: &str) -> String {
    let (name, directory) = match kind {
        "drive_link" if drive.len() == 1 && drive.chars().all(|value| value.is_ascii_alphabetic()) => (format!("\\GLOBAL??\\{}:", drive.to_ascii_uppercase()), false),
        "mpm_link" if drive.is_empty() => (String::from("\\GLOBAL??\\MountPointManager"), false),
        "global_dir" if drive.is_empty() => (String::from("\\GLOBAL??"), true),
        _ => return String::from("open=usage"),
    };
    let library = wide("ntdll.dll");
    let module = unsafe { GetModuleHandleW(library.as_ptr()) };
    if module == 0 {
        return format!("open=load_err{}", last_error());
    }
    let symbol: &[u8] = if directory { &b"NtOpenDirectoryObject\0"[..] } else { &b"NtOpenSymbolicLinkObject\0"[..] };
    let open_address = unsafe { GetProcAddress(module, symbol.as_ptr()) };
    let convert_address = unsafe { GetProcAddress(module, b"RtlNtStatusToDosError\0".as_ptr()) };
    if open_address == 0 || convert_address == 0 {
        return String::from("open=proc_err");
    }
    let open: extern "system" fn(*mut isize, u32, *const u64) -> i32 = unsafe { std::mem::transmute(open_address) };
    let convert: extern "system" fn(i32) -> u32 = unsafe { std::mem::transmute(convert_address) };
    let text = wide(&name);
    let bytes = ((text.len() - 1) * 2) as u64;
    let unicode: [u64; 2] = [bytes | ((bytes + 2) << 16), text.as_ptr() as u64];
    let attributes: [u64; 6] = [48, 0, unicode.as_ptr() as u64, 0x40, 0, 0];
    let mut handle: isize = 0;
    let status = open(&mut handle, 0x0004_0000, attributes.as_ptr());
    if status < 0 {
        return format!("open=err{}", convert(status));
    }
    unsafe {
        CloseHandle(handle);
    }
    String::from("open=ok")
}

fn probe_tokenraise() -> String {
    let mut token: isize = 0;
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), 0x0088, &mut token) };
    if opened == 0 {
        let last = last_error();
        return format!("open=err{} set=na", last);
    }
    let mut buffer: [usize; 4] = [0, 0x20, 0x1000_0000_0000_0101, 0x2000];
    let sid_address = buffer.as_mut_ptr().wrapping_add(2) as usize;
    buffer[0] = sid_address;
    let done = unsafe { SetTokenInformation(token, 25, buffer.as_mut_ptr() as *mut u8, 28) };
    let state = if done != 0 {
        String::from("ok")
    } else {
        format!("err{}", last_error())
    };
    unsafe {
        CloseHandle(token);
    }
    format!("open=ok set={}", state)
}

fn probe_tokenpriv() -> String {
    let mut token: isize = 0;
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), 0x0028, &mut token) };
    if opened == 0 || token == 0 {
        let last = last_error();
        return format!("open=err{}", last);
    }
    let mut state: [u32; 4] = [1, 20, 0, 2];
    unsafe {
        SetLastError(0);
    }
    let call = unsafe { AdjustTokenPrivileges(token, 0, state.as_mut_ptr() as *mut u8, 16, ptr::null_mut(), ptr::null_mut()) };
    let last = last_error();
    unsafe {
        CloseHandle(token);
    }
    if call != 0 && last == 0 {
        String::from("adjust=ok")
    } else {
        format!("adjust=err{}", last)
    }
}

fn vtable_entry(object: *mut u8, index: usize) -> usize {
    unsafe {
        let table = *(object as *const *const usize);
        *table.add(index)
    }
}

fn release_object(object: *mut u8) {
    if object.is_null() {
        return;
    }
    let release: extern "system" fn(*mut u8) -> u32 = unsafe { std::mem::transmute(vtable_entry(object, 2)) };
    release(object);
}

fn probe_taskreg() -> String {
    let init = unsafe { CoInitializeEx(ptr::null_mut(), 0) };
    if init < 0 {
        return format!("create=hr{:08x}", init as u32);
    }
    let clsid: [u32; 4] = [0x0F87369F, 0x4CFCA4E5, 0xE6733EBD, 0xDD724515];
    let iid: [u32; 4] = [0x2FABA4C7, 0x40134DA9, 0xCC209796, 0x850FD43F];
    let mut object: *mut u8 = ptr::null_mut();
    let made = unsafe { CoCreateInstance(clsid.as_ptr() as *const u8, ptr::null_mut(), 5, iid.as_ptr() as *const u8, &mut object) };
    if made < 0 || object.is_null() {
        unsafe {
            CoUninitialize();
        }
        return format!("create=hr{:08x}", made as u32);
    }
    let mut server: [u64; 3] = [0, 0, 0];
    let mut user: [u64; 3] = [0, 0, 0];
    let mut domain: [u64; 3] = [0, 0, 0];
    let mut secret: [u64; 3] = [0, 0, 0];
    let connect: extern "system" fn(*mut u8, *mut u8, *mut u8, *mut u8, *mut u8) -> i32 = unsafe { std::mem::transmute(vtable_entry(object, 10)) };
    let connected = connect(object, server.as_mut_ptr() as *mut u8, user.as_mut_ptr() as *mut u8, domain.as_mut_ptr() as *mut u8, secret.as_mut_ptr() as *mut u8);
    release_object(object);
    unsafe {
        CoUninitialize();
    }
    if connected < 0 {
        return format!("create=ok connect=hr{:08x}", connected as u32);
    }
    String::from("create=ok connect=ok")
}

fn probe_wmi() -> String {
    let init = unsafe { CoInitializeEx(ptr::null_mut(), 0) };
    if init < 0 {
        return format!("create=hr{:08x}", init as u32);
    }
    let clsid: [u32; 4] = [0x4590F811, 0x11D01D3A, 0xAA001F89, 0x242E4B00];
    let iid: [u32; 4] = [0xDC12A687, 0x11CF737F, 0xAA004D88, 0x242E4B00];
    let mut object: *mut u8 = ptr::null_mut();
    let made = unsafe { CoCreateInstance(clsid.as_ptr() as *const u8, ptr::null_mut(), 5, iid.as_ptr() as *const u8, &mut object) };
    if made < 0 || object.is_null() {
        unsafe {
            CoUninitialize();
        }
        return format!("create=hr{:08x}", made as u32);
    }
    let namespace = wide("ROOT\\CIMV2");
    let name = unsafe { SysAllocString(namespace.as_ptr()) };
    let mut services: *mut u8 = ptr::null_mut();
    let connect: extern "system" fn(*mut u8, *mut u16, *mut u16, *mut u16, *mut u16, i32, *mut u16, *mut u8, *mut *mut u8) -> i32 = unsafe { std::mem::transmute(vtable_entry(object, 3)) };
    let connected = connect(object, name, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut(), &mut services);
    release_object(services);
    unsafe {
        SysFreeString(name);
    }
    release_object(object);
    unsafe {
        CoUninitialize();
    }
    if connected < 0 {
        return format!("create=ok connect=hr{:08x}", connected as u32);
    }
    String::from("create=ok connect=ok")
}

fn probe_wfp() -> String {
    let library = wide("fwpuclnt.dll");
    let module = unsafe { LoadLibraryExW(library.as_ptr(), 0, 0x0800) };
    if module == 0 {
        let last = last_error();
        return format!("open=load_err{}", last);
    }
    let open_address = unsafe { GetProcAddress(module, b"FwpmEngineOpen0\0".as_ptr()) };
    let close_address = unsafe { GetProcAddress(module, b"FwpmEngineClose0\0".as_ptr()) };
    if open_address == 0 || close_address == 0 {
        return String::from("open=proc_err");
    }
    let open: extern "system" fn(*const u16, u32, *mut u8, *const u8, *mut isize) -> u32 = unsafe { std::mem::transmute(open_address) };
    let close: extern "system" fn(isize) -> u32 = unsafe { std::mem::transmute(close_address) };
    let mut engine: isize = 0;
    let status = open(ptr::null(), 10, ptr::null_mut(), ptr::null(), &mut engine);
    if status != 0 {
        return format!("open=err{}", status);
    }
    close(engine);
    String::from("open=ok")
}

fn probe_procpeer() -> String {
    let executable = match env::current_exe() {
        Ok(value) => value,
        Err(error) => return format!("spawn={}", code(&error)),
    };
    let mut command = Command::new(executable);
    command.arg("peerwait");
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(value) => value,
        Err(error) => return format!("spawn={}", code(&error)),
    };
    let handle = unsafe { OpenProcess(0x1010, 0, child.id()) };
    let state = if handle == 0 {
        let last = last_error();
        format!("open=err{}", last)
    } else {
        unsafe {
            CloseHandle(handle);
        }
        String::from("open=ok")
    };
    drop(child.stdin.take());
    let _ = child.wait();
    state
}

fn probe_peerwait() -> String {
    let mut buffer = [0u8; 16];
    let _ = std::io::stdin().read(&mut buffer);
    String::from("result=ok")
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    let command = arguments.get(1).map(|value| value.as_str()).unwrap_or("");
    let first = arguments.get(2).map(|value| value.as_str()).unwrap_or("");
    let second = arguments.get(3).map(|value| value.as_str()).unwrap_or("");
    let third = arguments.get(4).map(|value| value.as_str()).unwrap_or("");
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
        "append" => probe_append(first),
        "pipemake" => probe_pipemake(first, second),
        "pipeopen" => probe_pipeopen(first),
        "procopen" => probe_procopen(first, second),
        "conout" => probe_conout(),
        "eventlog" => probe_eventlog(),
        "envhunt" => probe_envhunt(first),
        "marker" => probe_marker(),
        "regread" => probe_regread(first),
        "regcreate" => probe_regcreate(first),
        "dacopen" => probe_dacopen(first),
        "walk" => probe_walk(first, second, third),
        "jobbreak" => probe_jobbreak(),
        "jobmember" => probe_jobmember(),
        "profile" => probe_profile(),
        "scm" => probe_scm(),
        "symlink" => probe_symlink(first, second),
        "hardlink" => probe_hardlink(first, second),
        "finalpath" => probe_finalpath(first),
        "junction" => probe_junction(first, second, third),
        "mountmgr" => probe_mountmgr(first),
        "objdac" => probe_objdac(first, second),
        "tokenraise" => probe_tokenraise(),
        "tokenpriv" => probe_tokenpriv(),
        "taskreg" => probe_taskreg(),
        "wmi" => probe_wmi(),
        "wfp" => probe_wfp(),
        "procpeer" => probe_procpeer(),
        "peerwait" => probe_peerwait(),
        _ => String::from("usage"),
    };
    println!("kd-probe {} {}", command, text);
}
