import Darwin
import Foundation

enum ProbeStatus {
    static let invalidInput: Int32 = 20
    static let identityInvalid: Int32 = 21
    static let sandboxMissing: Int32 = 22
    static let childFailed: Int32 = 23
    static let storageUnavailable: Int32 = 24
    static let outsideWriteAllowed: Int32 = 25
}

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

func startProcess(_ executable: String, _ arguments: [String]) throws -> Process {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = FileHandle.standardOutput
    process.standardError = FileHandle.standardError
    try process.run()
    return process
}

func runParent(
    _ marker: String,
    _ writableDirectory: String,
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
    guard let executable = Bundle.main.executableURL else {
        exit(ProbeStatus.childFailed)
    }
    let helper = executable.deletingLastPathComponent().appendingPathComponent("CapabilityChild")
    do {
        let child = try startProcess(helper.path, [
            "--child",
            "--marker", marker,
            "--writable-directory", writableDirectory,
            "--python-executable", pythonExecutable,
            "--compiler-executable", compilerExecutable,
            "--linker-executable", linkerExecutable,
            "--sdk-root", sdkRoot,
        ])
        child.waitUntilExit()
        exit(child.terminationStatus == 0 ? 0 : ProbeStatus.childFailed)
    } catch {
        exit(ProbeStatus.childFailed)
    }
}

func runChild(
    _ marker: String,
    _ writableDirectory: String,
    _ pythonExecutable: String,
    _ compilerExecutable: String,
    _ linkerExecutable: String,
    _ sdkRoot: String
) -> Never {
    guard getuid() > 0, getuid() == geteuid(), readIsDenied(marker) else {
        exit(ProbeStatus.sandboxMissing)
    }
    guard isAbsolutePath(pythonExecutable),
          isAbsolutePath(compilerExecutable),
          isAbsolutePath(linkerExecutable),
          isAbsolutePath(sdkRoot) else {
        exit(ProbeStatus.invalidInput)
    }
    close(STDIN_FILENO)
    guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
        exit(ProbeStatus.storageUnavailable)
    }
    let workDirectory = support.appendingPathComponent("capability", isDirectory: true)
    let temporaryDirectory = workDirectory.appendingPathComponent("tmp", isDirectory: true)
    do {
        try FileManager.default.createDirectory(at: temporaryDirectory, withIntermediateDirectories: true)
    } catch {
        exit(ProbeStatus.storageUnavailable)
    }
    setenv("HOME", NSHomeDirectory(), 1)
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
        try cSource.write(to: source, atomically: true, encoding: .utf8)
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
    runChild(marker, writableDirectory, pythonExecutable, compilerExecutable, linkerExecutable, sdkRoot)
} else {
    runParent(marker, writableDirectory, pythonExecutable, compilerExecutable, linkerExecutable, sdkRoot)
}
