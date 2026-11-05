// Vite's windowsSafeRealPathSync calls optimizeSafeRealPathSync, which runs exec('net use').
// That pipe hangs under Windows LPAC. ENOTSUP keeps plain fs.realpathSync; gates do not use
// mapped network drives.
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';

const originalExec = childProcess.exec;
childProcess.exec = function (command, ...args) {
  if (typeof command === 'string' && command.trim().toLowerCase() === 'net use') {
    const callback = args.filter((arg) => typeof arg === 'function').at(-1);
    if (callback) {
      const error = Object.assign(new Error('net use disabled'), { code: 'ENOTSUP' });
      process.nextTick(() => callback(error));
    }
    return {};
  }
  return originalExec.call(this, command, ...args);
};
syncBuiltinESMExports();
