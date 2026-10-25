import Darwin
import Foundation

enum ProbeStatus {
    static let invalidInput: Int32 = 20
    static let identityInvalid: Int32 = 21
    static let sandboxMissing: Int32 = 22
    static let childFailed: Int32 = 23
    static let storageUnavailable: Int32 = 24
    static let outsideWriteAllowed: Int32 = 25
    static let childSandboxMissing: Int32 = 26
    static let networkAllowed: Int32 = 27
    static let childNetworkAllowed: Int32 = 28
    static let ipcAllowed: Int32 = 29
    static let childIpcAllowed: Int32 = 30
}

let bootstrapNotPrivileged: kern_return_t = 1100
let deniedMachServices = [
    "com.apple.nsurlsessiond",
    "com.apple.trustd",
    "com.apple.trustd.agent",
    "com.apple.dnssd.service",
    "com.apple.coreservices.launchservicesd",
    "com.apple.lsd.open",
    "com.apple.lsd.mapdb",
    "com.apple.lsd.modifydb",
    "com.apple.system.notification_center",
    "com.apple.distributed_notifications@Uv3",
    "com.apple.SystemConfiguration.configd",
]
typealias BootstrapLookUp = @convention(c) (mach_port_t, UnsafePointer<CChar>, UnsafeMutablePointer<mach_port_t>) -> kern_return_t

func option(_ name: String) -> String? {
    guard let index = CommandLine.arguments.firstIndex(of: name),
          index + 1 < CommandLine.arguments.count else {
        return nil
    }
    return CommandLine.arguments[index + 1]
}

func isAbsolutePath(_ path: String) -> Bool {
    !path.isEmpty && path.hasPrefix("/") && !path.contains("\0")
}

func isExecutableFile(_ path: String) -> Bool {
    var isDirectory = ObjCBool(false)
    return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
        && !isDirectory.boolValue
        && FileManager.default.isExecutableFile(atPath: path)
}

func readIsDenied(_ path: String) -> Bool {
    let descriptor = open(path, O_RDONLY)
    if descriptor >= 0 {
        close(descriptor)
        return false
    }
    return errno == EACCES || errno == EPERM
}

func connectIsDenied(_ family: Int32, _ type: Int32, _ address: UnsafePointer<sockaddr>, _ length: socklen_t) -> Bool {
    let descriptor = socket(family, type, 0)
    if descriptor < 0 {
        return errno == EPERM
    }
    defer { close(descriptor) }
    if connect(descriptor, address, length) == 0 {
        return false
    }
    return errno == EPERM
}

func inetConnectIsDenied(_ type: Int32) -> Bool {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = UInt16(49152).bigEndian
    address.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
    return withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
            connectIsDenied(AF_INET, type, generic, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
}

func unixConnectIsDenied() -> Bool {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let socketPath = Array("/var/run/mDNSResponder".utf8CString)
    guard socketPath.count <= MemoryLayout.size(ofValue: address.sun_path) else {
        return false
    }
    withUnsafeMutableBytes(of: &address.sun_path) { buffer in
        for (index, byte) in socketPath.enumerated() {
            buffer[index] = UInt8(bitPattern: byte)
        }
    }
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    return withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
            connectIsDenied(AF_UNIX, SOCK_STREAM, generic, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
}

func networkIsDenied() -> Bool {
    inetConnectIsDenied(SOCK_DGRAM) && inetConnectIsDenied(SOCK_STREAM) && unixConnectIsDenied()
}

func ipcIsDenied() -> Bool {
    guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "bootstrap_look_up") else {
        return false
    }
    let lookUp = unsafeBitCast(symbol, to: BootstrapLookUp.self)
    var bootstrap = mach_port_t(0)
    guard task_get_special_port(mach_task_self_, TASK_BOOTSTRAP_PORT, &bootstrap) == KERN_SUCCESS,
          bootstrap != mach_port_t(0) else {
        return false
    }
    for service in deniedMachServices {
        var port = mach_port_t(0)
        let result = lookUp(bootstrap, service, &port)
        if result == KERN_SUCCESS {
            mach_port_deallocate(mach_task_self_, port)
            return false
        }
        if result != bootstrapNotPrivileged {
            return false
        }
    }
    return true
}

func startProcess(_ executable: String, _ arguments: [String]) throws -> Process {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = FileHandle.standardOutput
    process.standardError = FileHandle.standardError
    try process.run()
    return process
}

func parentStatus(for child: Process) -> Int32 {
    if child.terminationStatus == 0 {
        return 0
    }
    guard child.terminationReason == .exit else {
        return ProbeStatus.childFailed
    }
    switch child.terminationStatus {
    case ProbeStatus.invalidInput,
         ProbeStatus.identityInvalid,
         ProbeStatus.storageUnavailable,
         ProbeStatus.outsideWriteAllowed,
         ProbeStatus.childSandboxMissing,
         ProbeStatus.childNetworkAllowed,
         ProbeStatus.childIpcAllowed:
        return child.terminationStatus
    default:
        return ProbeStatus.childFailed
    }
}

func runParent(
    _ marker: String,
    _ writableDirectory: String,
    _ storageDirectory: String,
    _ pythonExecutable: String,
    _ compilerExecutable: String,
    _ linkerExecutable: String,
    _ sdkRoot: String
) -> Never {
    guard getuid() > 0, getuid() == geteuid() else {
        exit(ProbeStatus.identityInvalid)
    }
    close(STDIN_FILENO)
    guard readIsDenied(marker) else {
        exit(ProbeStatus.sandboxMissing)
    }
    guard networkIsDenied() else {
        exit(ProbeStatus.networkAllowed)
    }
    guard ipcIsDenied() else {
        exit(ProbeStatus.ipcAllowed)
    }
    guard let executable = Bundle.main.executableURL else {
        exit(ProbeStatus.childFailed)
    }
    let helper = executable.deletingLastPathComponent().appendingPathComponent("CapabilityChild")
    do {
        let child = try startProcess(helper.path, [
            "--child",
            "--marker", marker,
            "--writable-directory", writableDirectory,
            "--storage-directory", storageDirectory,
            "--python-executable", pythonExecutable,
            "--compiler-executable", compilerExecutable,
            "--linker-executable", linkerExecutable,
            "--sdk-root", sdkRoot,
        ])
        child.waitUntilExit()
        exit(parentStatus(for: child))
    } catch {
        exit(ProbeStatus.childFailed)
    }
}

func runChild(
    _ marker: String,
    _ writableDirectory: String,
    _ storageDirectory: String,
    _ pythonExecutable: String,
    _ compilerExecutable: String,
    _ linkerExecutable: String,
    _ sdkRoot: String
) -> Never {
    guard getuid() > 0, getuid() == geteuid() else {
        exit(ProbeStatus.identityInvalid)
    }
    guard readIsDenied(marker) else {
        exit(ProbeStatus.childSandboxMissing)
    }
    guard networkIsDenied() else {
        exit(ProbeStatus.childNetworkAllowed)
    }
    guard ipcIsDenied() else {
        exit(ProbeStatus.childIpcAllowed)
    }
    guard isAbsolutePath(storageDirectory),
          isAbsolutePath(pythonExecutable),
          isAbsolutePath(compilerExecutable),
          isAbsolutePath(linkerExecutable),
          isAbsolutePath(sdkRoot) else {
        exit(ProbeStatus.invalidInput)
    }
    close(STDIN_FILENO)
    let support = URL(fileURLWithPath: storageDirectory, isDirectory: true)
    let workDirectory = support.appendingPathComponent("capability", isDirectory: true)
    let temporaryDirectory = workDirectory.appendingPathComponent("tmp", isDirectory: true)
    do {
        try FileManager.default.createDirectory(at: temporaryDirectory, withIntermediateDirectories: true)
    } catch {
        exit(ProbeStatus.storageUnavailable)
    }
    setenv("HOME", workDirectory.path, 1)
    setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1)
    setenv("TMPDIR", temporaryDirectory.path, 1)
    setenv("PYTHONNOUSERSITE", "1", 1)
    setenv("PYTHONDONTWRITEBYTECODE", "1", 1)
    setenv("LANG", "C", 1)

    var sdkIsDirectory = ObjCBool(false)
    guard isExecutableFile("/bin/sh"),
          isExecutableFile(pythonExecutable),
          isExecutableFile(compilerExecutable),
          isExecutableFile(linkerExecutable),
          FileManager.default.fileExists(atPath: sdkRoot, isDirectory: &sdkIsDirectory),
          sdkIsDirectory.boolValue else {
        exit(ProbeStatus.childFailed)
    }

    let shellCommand = "if [ -r \"$1\" ]; then exit 31; fi; /bin/sleep 4"
    let shell: Process
    let python: Process
    do {
        shell = try startProcess("/bin/sh", ["-c", shellCommand, "sh", marker])
        python = try startProcess(pythonExecutable, [
            "-c",
            "import subprocess,sys,time\ntry:\n open(sys.argv[1], 'rb').close()\n raise SystemExit(32)\nexcept OSError:\n pass\np = subprocess.Popen(['/bin/sleep', '4'])\ntime.sleep(4)\nraise SystemExit(p.wait())",
            marker,
        ])
    } catch {
        exit(ProbeStatus.childFailed)
    }

    let holdPath = workDirectory.appendingPathComponent("compiler-hold").path
    unlink(holdPath)
    guard mkfifo(holdPath, 0o600) == 0 else {
        exit(ProbeStatus.storageUnavailable)
    }
    let openedHold = open(holdPath, O_RDWR)
    guard openedHold >= 0 else {
        exit(ProbeStatus.storageUnavailable)
    }
    let holdDescriptor = fcntl(openedHold, F_DUPFD_CLOEXEC, 10)
    close(openedHold)
    guard holdDescriptor >= 10 else {
        exit(ProbeStatus.storageUnavailable)
    }
    let holdDeadline = Date().addingTimeInterval(3)
    let holdCompiler: Process
    do {
        holdCompiler = try startProcess(compilerExecutable, [
            "-x", "c",
            "-isysroot", sdkRoot,
            "-fsyntax-only",
            holdPath,
        ])
    } catch {
        exit(ProbeStatus.childFailed)
    }

    let source = workDirectory.appendingPathComponent("descendant.c")
    let blockedOutput = URL(fileURLWithPath: writableDirectory).appendingPathComponent("outside-build").path
    let builtOutput = workDirectory.appendingPathComponent("capability-child").path
    var cSource = """
    extern int open(const char *, int, ...);
    extern int close(int);
    extern int fork(void);
    extern int waitpid(int, int *, int);
    extern unsigned int sleep(unsigned int);
    extern void _exit(int);
    int main(int argc, char **argv) {
        int descriptor = open(argv[1], 0);
        if (descriptor >= 0) { close(descriptor); return 41; }
        int child = fork();
        if (child < 0) return 42;
        if (child == 0) {
            int nested = open(argv[1], 0);
            if (nested >= 0) { close(nested); _exit(43); }
            sleep(4);
            _exit(0);
        }
        int status = 0;
        if (waitpid(child, &status, 0) < 0) return 44;
        return status == 0 ? 0 : 45;
    }
    """
    for index in 0..<12000 {
        cSource += "int generated_\(index)(void) { return \(index); }\n"
    }
    do {
        try cSource.write(to: source, atomically: false, encoding: .utf8)
    } catch {
        exit(ProbeStatus.storageUnavailable)
    }

    do {
        let outsideCompiler = try startProcess(compilerExecutable, [
            "-x", "c",
            "-isysroot", sdkRoot,
            "-fuse-ld=\(linkerExecutable)",
            "-o", blockedOutput,
            source.path,
        ])
        outsideCompiler.waitUntilExit()
        if outsideCompiler.terminationStatus == 0 {
            exit(ProbeStatus.outsideWriteAllowed)
        }
        let builtCompiler = try startProcess(compilerExecutable, [
            "-x", "c",
            "-isysroot", sdkRoot,
            "-fuse-ld=\(linkerExecutable)",
            "-o", builtOutput,
            source.path,
        ])
        builtCompiler.waitUntilExit()
        guard builtCompiler.terminationStatus == 0 else {
            exit(ProbeStatus.childFailed)
        }
        let holdRemaining = holdDeadline.timeIntervalSinceNow
        if holdRemaining > 0 {
            Thread.sleep(forTimeInterval: holdRemaining)
        }
        close(holdDescriptor)
        holdCompiler.waitUntilExit()
        guard holdCompiler.terminationStatus == 0 else {
            exit(ProbeStatus.childFailed)
        }
        let builtChild = try startProcess(builtOutput, [marker])
        builtChild.waitUntilExit()
        shell.waitUntilExit()
        python.waitUntilExit()
        guard builtChild.terminationStatus == 0,
              shell.terminationStatus == 0,
              python.terminationStatus == 0 else {
            exit(ProbeStatus.childFailed)
        }
    } catch {
        exit(ProbeStatus.childFailed)
    }
    exit(0)
}

guard let marker = option("--marker"),
      let writableDirectory = option("--writable-directory"),
      let storageDirectory = option("--storage-directory"),
      let pythonExecutable = option("--python-executable"),
      let compilerExecutable = option("--compiler-executable"),
      let linkerExecutable = option("--linker-executable"),
      let sdkRoot = option("--sdk-root"),
      isAbsolutePath(pythonExecutable),
      isAbsolutePath(compilerExecutable),
      isAbsolutePath(linkerExecutable),
      isAbsolutePath(sdkRoot) else {
    exit(ProbeStatus.invalidInput)
}

if CommandLine.arguments.contains("--child") {
    runChild(marker, writableDirectory, storageDirectory, pythonExecutable, compilerExecutable, linkerExecutable, sdkRoot)
} else {
    runParent(marker, writableDirectory, storageDirectory, pythonExecutable, compilerExecutable, linkerExecutable, sdkRoot)
}
