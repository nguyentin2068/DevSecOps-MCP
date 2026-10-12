import winston from 'winston';

// Every log line goes to stderr: stdout carries the MCP stdio protocol and the CLI's results.
export const logger = winston.createLogger({
  level: process.env['LOG_LEVEL'] || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      stderrLevels: ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly']
    })
  ]
});

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
