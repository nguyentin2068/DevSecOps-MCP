import { spawn } from 'child_process';

export interface RunOptions {
  cwd?: string;
  timeoutMs: number;
  /** Hard cap on captured stdout; the process is killed when it is exceeded. */
  maxOutputBytes?: number;
  env?: NodeJS.ProcessEnv;
}

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

const DEFAULT_MAX_OUTPUT_BYTES = Number(process.env['SCAN_MAX_OUTPUT_MB'] || 64) * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;

/**
 * Run a scanner binary without a shell. Arguments are passed as an argv array, so
 * nothing in them is interpreted by a shell; callers still put `--` before
 * user-controlled positionals so they cannot be parsed as flags.
 */
export function runCommand(bin: string, args: string[], options: RunOptions): Promise<RunResult> {
  const maxOutput = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;

  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderr = '';
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
      if (stderr.length < MAX_STDERR_BYTES) {
        stderr += chunk.toString('utf8').slice(0, MAX_STDERR_BYTES - stderr.length);
      }
    });

    child.on('error', (error) => {
      clearTimeout(timer);
      reject(new Error(`Failed to start ${bin}: ${error.message}`));
    });

    child.on('close', (code) => {
      clearTimeout(timer);
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
