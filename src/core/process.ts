import { spawn } from 'child_process';
import path from 'path';
import { StringDecoder } from 'string_decoder';

/** Receives a scanner's log output (its stderr), one sanitized line at a time. */
export type ToolLog = (line: string) => void;

export interface RunOptions {
  cwd?: string;
  timeoutMs: number;
  /** Hard cap on captured stdout; the process is killed when it is exceeded. */
  maxOutputBytes?: number;
  env?: NodeJS.ProcessEnv;
  /** When set, the command line, every stderr line and the exit status are streamed here as they happen. */
  log?: ToolLog;
}

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

const DEFAULT_MAX_OUTPUT_BYTES = Number(process.env['SCAN_MAX_OUTPUT_MB'] || 64) * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;
const MAX_LOG_LINE_CHARS = 4000;

// ANSI escape sequences and other control characters. Scanner logs echo file names and
// responses from the scanned target, which must not be able to drive the operator's terminal.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]|[\x00-\x08\x0b-\x1f\x7f]/g;

export function sanitizeLogLine(line: string): string {
  const clean = line.replace(CONTROL_CHARS, '').trimEnd();
  return clean.length > MAX_LOG_LINE_CHARS ? `${clean.slice(0, MAX_LOG_LINE_CHARS)}...` : clean;
}

/** Splits a stream into lines (\n, \r\n or bare \r from progress bars) and forwards the non-empty ones. */
function lineForwarder(prefix: string, log: ToolLog): { write: (chunk: string) => void; flush: () => void } {
  let pending = '';
  const emit = (line: string) => {
    const clean = sanitizeLogLine(line);
    if (clean) log(`${prefix} ${clean}`);
  };
  return {
    write: (chunk) => {
      const parts = (pending + chunk).split(/\r\n|\n|\r/);
      pending = parts.pop() ?? '';
      parts.forEach(emit);
      // A line that never ends (a runaway progress bar) is emitted in pieces instead of buffered forever.
      if (pending.length > MAX_LOG_LINE_CHARS) {
        emit(pending);
        pending = '';
      }
    },
    flush: () => {
      emit(pending);
      pending = '';
    }
  };
}

/**
 * Run a scanner binary without a shell. Arguments are passed as an argv array, so
 * nothing in them is interpreted by a shell; callers still put `--` before
 * user-controlled positionals so they cannot be parsed as flags.
 */
export function runCommand(bin: string, args: string[], options: RunOptions): Promise<RunResult> {
  const maxOutput = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const prefix = `[${path.basename(bin)}]`;
  const log = options.log;
  const forward = log ? lineForwarder(prefix, log) : undefined;
  const started = Date.now();
  log?.(`${prefix} $ ${[bin, ...args].map(sanitizeLogLine).join(' ')}`);

  return new Promise((resolve, reject) => {
    // Reviewed: running scanners is this module's job. `bin` comes from operator config
    // (*_PATH env vars / defaults), never from scan input; shell is off and args are an argv array.
    const child = spawn(bin, args, { // nosemgrep: javascript.lang.security.detect-child-process
      cwd: options.cwd,
      env: options.env ?? process.env,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderr = '';
    const stderrDecoder = new StringDecoder('utf8');
    let failure: Error | undefined;

    const kill = (reason: Error) => {
      if (failure) return;
      failure = reason;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 5000).unref();
    };

    const timer = setTimeout(
      () => kill(new Error(`${bin} timed out after ${Math.round(options.timeoutMs / 1000)}s`)),
      options.timeoutMs
    );

    child.stdout.on('data', (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxOutput) {
        kill(new Error(`${bin} output exceeded ${maxOutput} bytes`));
        return;
      }
      stdout.push(chunk);
    });

    child.stderr.on('data', (chunk: Buffer) => {
      const text = stderrDecoder.write(chunk);
      forward?.write(text);
      // Keep the end of stderr: that is where scanners report the error that made them fail.
      stderr += text;
      if (stderr.length > MAX_STDERR_BYTES) stderr = stderr.slice(-MAX_STDERR_BYTES);
    });

    child.on('error', (error) => {
      clearTimeout(timer);
      log?.(`${prefix} failed to start: ${error.message}`);
      reject(new Error(`Failed to start ${bin}: ${error.message}`));
    });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      forward?.flush();
      const seconds = ((Date.now() - started) / 1000).toFixed(1);
      log?.(`${prefix} ${failure ? `stopped: ${failure.message}` : `exited with ${code ?? `signal ${signal}`}`} after ${seconds}s`);
      if (failure) {
        reject(failure);
        return;
      }
      resolve({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr });
    });
  });
}

export function parseJsonOutput<T>(bin: string, output: string): T {
  try {
    return JSON.parse(output) as T;
  } catch (error) {
    throw new Error(`Failed to parse ${bin} JSON output: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Last lines of stderr, for error messages without dumping the whole log. */
export function stderrTail(stderr: string, lines = 5): string {
  return stderr.trim().split('\n').slice(-lines).join('\n');
}
