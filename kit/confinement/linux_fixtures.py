import json

import linux_probes
from linux_channels import CONTAINED, DENIED


FORMS = ("build_rs", "proc_macro", "shell", "python", "npm_postinstall")
SLUGS = {
    "build_rs": "buildrs",
    "proc_macro": "procmacro",
    "shell": "shell",
    "python": "python",
    "npm_postinstall": "npm",
}
HASH = chr(35)
RULE_NAMES = (
    "tcp-connect",
    "udp-send",
    "dns-lookup",
    "proxy-connect",
    "unix-connect",
    "boundary-setuid",
    "boundary-unshare",
    "boundary-mount",
    "boundary-sysctl",
    "boundary-sudo",
    "output-exfil",
)
NO_UNIX = ("shell",)
OPTIONAL = {
    "build_rs": ("boundary-sudo",),
    "proc_macro": ("boundary-sudo",),
    "shell": ("boundary-setuid", "boundary-unshare", "boundary-mount", "boundary-sudo"),
    "python": ("boundary-sudo",),
    "npm_postinstall": ("boundary-unshare", "boundary-mount", "boundary-sudo"),
}
CONTROLLED = {
    "tcp-connect": "https4",
    "udp-send": "udp",
    "dns-lookup": "dns_udp",
    "proxy-connect": "proxy",
    "unix-connect": "unix",
}
RUN_TIMEOUT = {
    "build_rs": 150,
    "proc_macro": 150,
    "shell": 60,
    "python": 60,
    "npm_postinstall": 90,
}
NEEDS_RUSTC = ("build_rs", "proc_macro")
NEEDS_NODE = ("npm_postinstall",)
LINKER = "/usr/bin/gcc"
NODE_IMAGE_PREFIX = "/usr/"
PINNED_NODE_PREFIX = "/tmp/kd-toolchains/node/"
NODE_TARGET = "/kd-node"
HOST_NODE_ABSENT = 60
HOST_NODE_UNSAFE = 61
HOST_NODE_PINNED_INVALID = 62

SHELL_DRIVER = r"""scratch=/tmp/fx
mkdir -p "$scratch"
run() {
  name=$1
  shift
  "$@" >"$scratch/out" 2>"$scratch/err"
  code=$?
  if [ "$code" -eq 0 ]; then
    echo "KDATT $name allowed"
  elif [ "$code" -eq 127 ]; then
    echo "KDATT $name na"
  else
    echo "KDATT $name denied"
  fi
}
run tcp-connect bash -c 'exec 3<>/dev/tcp/127.0.0.1/"$KD_TCP_PORT" && printf %s "fx-shell-$KD_NONCE" >&3'
run udp-send bash -c 'exec 3<>/dev/udp/127.0.0.1/"$KD_UDP_PORT" && printf %s "fx-shell-$KD_NONCE" >&3'
run dns-lookup getent hosts "fx-shell-$KD_NONCE.example.invalid"
run proxy-connect bash -c 'exec 3<>/dev/tcp/127.0.0.1/"$KD_PROXY_PORT" && printf "CONNECT fx-shell-%s.example.invalid:443 HTTP/1.1\r\n\r\n" "$KD_NONCE" >&3'
run boundary-setuid setpriv --reuid 0 --regid 0 --clear-groups true
run boundary-unshare unshare --net true
mkdir -p "$scratch/mount"
run boundary-mount mount -t tmpfs tmpfs "$scratch/mount"
run boundary-sysctl sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'
run boundary-sudo sudo -n true
echo "::error::fx-secret-$KD_NONCE"
echo "::error::fx-secret-$KD_NONCE" >&2
echo "KDATT output-exfil contained"
"""

PYTHON_BODY = """
def number(name):
    return int(os.environ.get(name, "9"))


def tcp():
    with socket.create_connection(("127.0.0.1", number("KD_TCP_PORT")), timeout=1) as sock:
        sock.sendall(("fx-python-" + nonce).encode())


def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        sock.sendto(("fx-python-" + nonce).encode(), ("127.0.0.1", number("KD_UDP_PORT")))


def proxy():
    with socket.create_connection(("127.0.0.1", number("KD_PROXY_PORT")), timeout=1) as sock:
        sock.sendall(("CONNECT fx-python-" + nonce + ".example.invalid:443 HTTP/1.1" + CRLF + CRLF).encode())


def unix():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        sock.connect(os.environ["KD_UNIX_PATH"])
        sock.sendall(("fx-python-" + nonce).encode())


def setuid_root():
    os.setuid(0)


def unshare_net():
    check(libc.unshare(0x40000000))


def mount_tmpfs():
    os.makedirs("/work/mount", exist_ok=True)
    check(libc.mount(b"tmpfs", b"/work/mount", b"tmpfs", 0, None))


def sysctl():
    with open("/proc/sys/kernel/yama/ptrace_scope", "w") as target:
        target.write("0")


def sudo():
    done = subprocess.run(["/usr/bin/sudo", "-n", "true"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    if done.returncode != 0:
        closed()


def exfiltrate():
    sys.stdout.write("::error::fx-secret-" + nonce + NL)
    sys.stderr.write("::error::fx-secret-" + nonce + NL)
    sys.stdout.flush()
    sys.stderr.flush()


def check(result):
    if result != 0:
        raise_errno()


BOUNDARY = (errno.EPERM, errno.EACCES, errno.EINVAL, errno.ENOSPC)
attempt("tcp-connect", tcp)
attempt("udp-send", udp)
attempt("dns-lookup", lambda: socket.getaddrinfo("fx-python-" + nonce + ".example.invalid", 80))
attempt("proxy-connect", proxy)
attempt("unix-connect", unix)
attempt("boundary-setuid", setuid_root, accepted=BOUNDARY)
attempt("boundary-unshare", unshare_net, accepted=BOUNDARY)
attempt("boundary-mount", mount_tmpfs, accepted=BOUNDARY)
attempt("boundary-sysctl", sysctl, accepted=BOUNDARY)
attempt("boundary-sudo", sudo, accepted=BOUNDARY, optional=True)
attempt("output-exfil", exfiltrate, contained=True)
"""

NODE_DRIVER = """cd /fixtures/npm_postinstall || exit 1
[ -x "$KD_NODE" ] || exit 6
mkdir -p /work/bin && ln -s "$KD_NODE" /work/bin/node || exit 7
export PATH=/work/bin:/usr/local/bin:/usr/bin
export npm_lifecycle_event=postinstall npm_package_name=hostile-fixture INIT_CWD=/work
script=$("$KD_NODE" -p "require('./package.json').scripts.postinstall") || exit 4
[ -n "$script" ] || exit 5
exec sh -c "$script"
"""

NODE_PACKAGE = json.dumps(
    {"name": "hostile-fixture", "version": "0.0.0", "private": True, "scripts": {"postinstall": "node install.js"}},
    sort_keys=True,
) + chr(10)

NODE_SCRIPT = r"""const net = require("net");
const dgram = require("dgram");
const dns = require("dns");
const fs = require("fs");
const childProcess = require("child_process");

const nonce = process.env.KD_NONCE || "";
const marker = "fx-npm-" + nonce;

function blocked(error) {
  return Boolean(error) && (error.code === "EPERM" || error.code === "EACCES");
}

function outcome(error) {
  return blocked(error) ? "denied" : "other";
}

function closeQuiet(socket) {
  try {
    socket.close();
  } catch (error) {
    return;
  }
}

function step(name, start) {
  return new Promise(function (resolve) {
    let settled = false;
    let timer = null;
    const finish = function (result) {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== null) {
        clearTimeout(timer);
      }
      console.log("KDATT " + name + " " + result);
      resolve();
    };
    timer = setTimeout(function () {
      finish("other");
    }, 4000);
    try {
      start(finish);
    } catch (error) {
      finish(outcome(error));
    }
  });
}

function connectAndSend(options, payload) {
  return function (done) {
    const socket = net.connect(options);
    socket.on("connect", function () {
      socket.write(payload);
      socket.end();
      done("allowed");
    });
    socket.on("error", function (error) {
      done(outcome(error));
    });
  };
}

function spawn(path, args) {
  return function (done) {
    const result = childProcess.spawnSync(path, args, { timeout: 5000 });
    if (result.error) {
      done(result.error.code === "ENOENT" ? "na" : "other");
      return;
    }
    done(result.status === 0 ? "allowed" : "denied");
  };
}

const steps = [
  function () {
    return step("tcp-connect", connectAndSend({ host: "127.0.0.1", port: Number(process.env.KD_TCP_PORT) }, marker));
  },
  function () {
    return step("udp-send", function (done) {
      const socket = dgram.createSocket("udp4");
      socket.on("error", function (error) {
        closeQuiet(socket);
        done(outcome(error));
      });
      socket.send(Buffer.from(marker), Number(process.env.KD_UDP_PORT), "127.0.0.1", function (error) {
        closeQuiet(socket);
        done(error ? outcome(error) : "allowed");
      });
    });
  },
  function () {
    return step("dns-lookup", function (done) {
      dns.lookup(marker + ".example.invalid", function (error) {
        done(error ? "denied" : "allowed");
      });
    });
  },
  function () {
    return step(
      "proxy-connect",
      connectAndSend(
        { host: "127.0.0.1", port: Number(process.env.KD_PROXY_PORT) },
        "CONNECT " + marker + ".example.invalid:443 HTTP/1.1\r\n\r\n"
      )
    );
  },
  function () {
    return step("unix-connect", connectAndSend({ path: process.env.KD_UNIX_PATH }, marker));
  },
  function () {
    return step("boundary-setuid", function (done) {
      process.setuid(0);
      done("allowed");
    });
  },
  function () {
    return step("boundary-unshare", spawn("/usr/bin/unshare", ["--net", "true"]));
  },
  function () {
    return step("boundary-mount", function (done) {
      fs.mkdirSync("/work/mount", { recursive: true });
      spawn("/usr/bin/mount", ["-t", "tmpfs", "tmpfs", "/work/mount"])(done);
    });
  },
  function () {
    return step("boundary-sysctl", function (done) {
      fs.writeFileSync("/proc/sys/kernel/yama/ptrace_scope", "0");
      done("allowed");
    });
  },
  function () {
    return step("boundary-sudo", spawn("/usr/bin/sudo", ["-n", "true"]));
  },
];

steps
  .reduce(function (chain, run) {
    return chain.then(run);
  }, Promise.resolve())
  .then(function () {
    console.log("::error::fx-secret-" + nonce);
    console.error("::error::fx-secret-" + nonce);
    console.log("KDATT output-exfil contained");
  });
"""

RUST_USES = r"""use std::ffi::CString;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::net::UnixStream;
use std::process::Command;

extern "C" {
    fn setuid(uid: u32) -> i32;
    fn unshare(flags: i32) -> i32;
    fn mount(
        source: *const std::os::raw::c_char,
        target: *const std::os::raw::c_char,
        fstype: *const std::os::raw::c_char,
        flags: std::os::raw::c_ulong,
        data: *const std::os::raw::c_void,
    ) -> i32;
}

fn report(name: &str, result: &str) {
    println!("KDATT {} {}", name, result);
}

fn blocked(error: &std::io::Error) -> bool {
    match error.raw_os_error() {
        Some(1) | Some(13) => true,
        _ => false,
    }
}

fn judge<T>(name: &str, outcome: std::io::Result<T>) {
    match outcome {
        Ok(_) => report(name, "allowed"),
        Err(error) => report(name, if blocked(&error) { "denied" } else { "other" }),
    }
}

fn variable(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

fn port(name: &str) -> u16 {
    variable(name).parse::<u16>().unwrap_or(9)
}

fn run_attempts() {
    let nonce = variable("KD_NONCE");
    let marker = format!("fx-{}-{}", variable("KD_FORM"), nonce);
    judge(
        "tcp-connect",
        TcpStream::connect(("127.0.0.1", port("KD_TCP_PORT"))).and_then(|mut stream| stream.write_all(marker.as_bytes())),
    );
    judge(
        "udp-send",
        UdpSocket::bind("127.0.0.1:0").and_then(|socket| socket.send_to(marker.as_bytes(), ("127.0.0.1", port("KD_UDP_PORT")))),
    );
    let host = format!("{}.example.invalid", marker);
    match (host.as_str(), 80u16).to_socket_addrs() {
        Ok(_) => report("dns-lookup", "allowed"),
        Err(_) => report("dns-lookup", "denied"),
    }
    let connect = format!("CONNECT {}.example.invalid:443 HTTP/1.1\r\n\r\n", marker);
    judge(
        "proxy-connect",
        TcpStream::connect(("127.0.0.1", port("KD_PROXY_PORT"))).and_then(|mut stream| stream.write_all(connect.as_bytes())),
    );
    judge(
        "unix-connect",
        UnixStream::connect(variable("KD_UNIX_PATH")).and_then(|mut stream| stream.write_all(marker.as_bytes())),
    );
    let escalated = unsafe { setuid(0) };
    report("boundary-setuid", if escalated == 0 { "allowed" } else { "denied" });
    let unshared = unsafe { unshare(0x40000000) };
    report("boundary-unshare", if unshared == 0 { "allowed" } else { "denied" });
    let _ = std::fs::create_dir_all("/work/mount");
    let source = CString::new("tmpfs").unwrap();
    let target = CString::new("/work/mount").unwrap();
    let mounted = unsafe { mount(source.as_ptr(), target.as_ptr(), source.as_ptr(), 0, std::ptr::null()) };
    report("boundary-mount", if mounted == 0 { "allowed" } else { "denied" });
    judge("boundary-sysctl", std::fs::write("/proc/sys/kernel/yama/ptrace_scope", "0"));
    match Command::new("/usr/bin/sudo").arg("-n").arg("true").status() {
        Ok(status) => report("boundary-sudo", if status.success() { "allowed" } else { "denied" }),
        Err(_) => report("boundary-sudo", "na"),
    }
    println!("::error::fx-secret-{}", nonce);
    eprintln!("::error::fx-secret-{}", nonce);
    report("output-exfil", "contained");
}
"""

BUILD_RS = RUST_USES + """
fn main() {
    run_attempts();
}
"""

PROC_MACRO = "extern crate proc_macro;\nuse proc_macro::TokenStream;\n" + RUST_USES + (
    "\n" + HASH + "[proc_macro]\n"
    "pub fn hostile(_input: TokenStream) -> TokenStream {\n"
    "    run_attempts();\n"
    "    TokenStream::new()\n"
    "}\n"
)

PROC_MACRO_USER = "hostile::hostile!();\n\nfn main() {}\n"

RUST_BUILD_DRIVER = """cd /work || exit 1
export TMPDIR=/work HOME=/work
[ -x @LINKER@ ] || exit 5
"$KD_RUSTC" --edition 2021 --crate-type bin -C linker=@LINKER@ -o /work/build_script /fixtures/build_rs/build.rs || exit 3
/work/build_script
""".replace("@LINKER@", LINKER)

RUST_MACRO_DRIVER = """cd /work || exit 1
export TMPDIR=/work HOME=/work
[ -x @LINKER@ ] || exit 5
"$KD_RUSTC" --edition 2021 --crate-type proc-macro -C linker=@LINKER@ --crate-name hostile --out-dir /work /fixtures/proc_macro/hostile.rs || exit 3
"$KD_RUSTC" --edition 2021 --crate-type bin -C linker=@LINKER@ --extern hostile=/work/libhostile.so -o /work/use_hostile /fixtures/proc_macro/use_hostile.rs || exit 4
""".replace("@LINKER@", LINKER)


def validate_form(form):
    if form not in FORMS:
        raise ValueError("form")
    return form


def slug(form):
    return SLUGS[validate_form(form)]


def fixture_rules(form):
    validate_form(form)
    names = tuple(name for name in RULE_NAMES if not (form in NO_UNIX and name == "unix-connect"))
    return tuple((name, CONTAINED if name == "output-exfil" else DENIED) for name in names)


def fixture_optional(form):
    return OPTIONAL[validate_form(form)]


def python_fixture_source():
    return linux_probes.PREAMBLE + PYTHON_BODY


def fixture_files(form):
    validate_form(form)
    if form == "shell":
        return {"/fixtures/shell/run.sh": (SHELL_DRIVER, 0o555)}
    if form == "python":
        return {"/fixtures/python/fixture.py": (python_fixture_source(), 0o444)}
    if form == "npm_postinstall":
        return {
            "/fixtures/npm_postinstall/run.sh": (NODE_DRIVER, 0o555),
            "/fixtures/npm_postinstall/package.json": (NODE_PACKAGE, 0o444),
            "/fixtures/npm_postinstall/install.js": (NODE_SCRIPT, 0o444),
        }
    if form == "build_rs":
        return {
            "/fixtures/build_rs/run.sh": (RUST_BUILD_DRIVER, 0o555),
            "/fixtures/build_rs/build.rs": (BUILD_RS, 0o444),
        }
    return {
        "/fixtures/proc_macro/run.sh": (RUST_MACRO_DRIVER, 0o555),
        "/fixtures/proc_macro/hostile.rs": (PROC_MACRO, 0o444),
        "/fixtures/proc_macro/use_hostile.rs": (PROC_MACRO_USER, 0o444),
    }


def fixture_argv(form, nonce):
    validate_form(form)
    if form == "python":
        return ["/usr/bin/python3", "-B", "/fixtures/python/fixture.py", "python", json.dumps({"nonce": nonce})]
    return ["/usr/bin/bash", "/fixtures/" + form + "/run.sh"]


def fixture_env(form, nonce, ports, unix_path, rustc=None, node=None):
    validate_form(form)
    env = {
        "PATH": "/usr/local/bin:/usr/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": "/work",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "KD_NONCE": nonce,
        "KD_FORM": slug(form),
        "KD_TCP_PORT": str(ports["https4"]),
        "KD_UDP_PORT": str(ports["udp"]),
        "KD_DNS_PORT": str(ports["dns_udp"]),
        "KD_PROXY_PORT": str(ports["proxy"]),
        "KD_UNIX_PATH": unix_path,
    }
    if form in NEEDS_RUSTC:
        if rustc is None:
            raise ValueError("rustc")
        env["KD_RUSTC"] = rustc
    if form in NEEDS_NODE:
        if node is None:
            raise ValueError("node")
        env["KD_NODE"] = node
    return env


def resolve_node(real):
    if type(real) is not str or len(real) > 300 or not real.startswith(NODE_IMAGE_PREFIX):
        raise ValueError("node")
    if "/../" in real or real.endswith("/") or not all(part.isalnum() or part in "._/@+=-" for part in real):
        raise ValueError("node")
    return real


def pinned_node_plan(directory):
    if type(directory) is not str or len(directory) > 300:
        raise ValueError("node")
    if not directory.startswith(PINNED_NODE_PREFIX) or not directory.endswith("/bin"):
        raise ValueError("node")
    if "/../" in directory or "//" in directory or not all(part.isalnum() or part in "._/@+=-" for part in directory):
        raise ValueError("node")
    return NODE_TARGET + "/node", {"source": directory, "target": NODE_TARGET, "ro": True, "rec": False}


def control_markers(form, nonce):
    marker = "fx-" + slug(form) + "-" + nonce
    return tuple(
        (listener, marker)
        for name, listener in CONTROLLED.items()
        if not (form in NO_UNIX and name == "unix-connect")
    )


def uncontrolled_attempts(form):
    return tuple(name for name, accepted in fixture_rules(form) if name not in CONTROLLED)


def all_sources():
    sources = {}
    for form in FORMS:
        for path, entry in fixture_files(form).items():
            sources[path] = entry[0]
    return sources
