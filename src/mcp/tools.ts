import Joi from 'joi';
import { SecurityRules } from '../core/config';
import { ValidationError } from '../core/guards';
import { evaluatePolicy } from '../core/policy';
import { renderReport, ReportFormat } from '../core/report';
import { ReportStore, SCAN_ID_PATTERN } from '../core/report-store';
import { ScanResult } from '../core/types';

export interface ToolContext {
  store: ReportStore;
  rules: SecurityRules;
  maxResponseBytes: number;
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface ToolResponse {
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

const scanIdJson = { type: 'string', pattern: SCAN_ID_PATTERN.source, description: 'Scan id as returned by the CLI' };
const scanIdJoi = Joi.string().pattern(SCAN_ID_PATTERN);
const scanIdsJson = { type: 'array', items: scanIdJson, minItems: 1, maxItems: 50 };
const scanIdsJoi = Joi.array().items(scanIdJoi.required()).min(1).max(50).unique();

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: 'validate_security_policy',
    description:
      'Evaluate stored scan results against the server security policy (security-rules.yml). Returns PASS, WARN or FAIL with the reasons. Failed scans or missing data always FAIL.',
    inputSchema: {
      type: 'object',
      properties: { scan_ids: { ...scanIdsJson, description: 'Scan ids to evaluate together' } },
      required: ['scan_ids'],
      additionalProperties: false
    }
  },
  {
    name: 'generate_security_report',
    description: 'Render a consolidated report for stored scans in markdown, json or sarif, including the policy decision.',
    inputSchema: {
      type: 'object',
      properties: {
        scan_ids: scanIdsJson,
        format: { type: 'string', enum: ['markdown', 'json', 'sarif'], default: 'markdown' },
        include_remediation: { type: 'boolean', default: true }
      },
      required: ['scan_ids'],
      additionalProperties: false
    }
  }
];

const ARG_SCHEMAS: Record<string, Joi.ObjectSchema> = {
  validate_security_policy: Joi.object({ scan_ids: scanIdsJoi.required() }),
  generate_security_report: Joi.object({
    scan_ids: scanIdsJoi.required(),
    format: Joi.string().valid('markdown', 'json', 'sarif').default('markdown'),
    include_remediation: Joi.boolean().default(true)
  })
};

function text(ctx: ToolContext, value: unknown): ToolResponse {
  const body = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  if (Buffer.byteLength(body) > ctx.maxResponseBytes) {
    throw new ValidationError(
      `Response is larger than ${ctx.maxResponseBytes} bytes; narrow the request (fewer scans, a higher min_severity, or markdown format)`
    );
  }
  return { content: [{ type: 'text', text: body }] };
}

async function loadResults(ctx: ToolContext, scanIds: string[]): Promise<ScanResult[]> {
  const results: ScanResult[] = [];
  for (const id of scanIds) results.push(await ctx.store.get(id));
  return results;
}

/** Dispatch a tool call. Every tool is read-only: nothing here starts a scan or writes files. */
export async function callTool(name: string, rawArgs: unknown, ctx: ToolContext): Promise<ToolResponse> {
  const schema = ARG_SCHEMAS[name];
  if (!schema) throw new ValidationError(`Unknown tool: ${name}`);
  const { error, value } = schema.validate(rawArgs ?? {}, { abortEarly: true, allowUnknown: false });
  if (error) throw new ValidationError(`Invalid arguments for ${name}: ${error.message}`);

  switch (name) {
    case 'validate_security_policy': {
      const results = await loadResults(ctx, value.scan_ids);
      return text(ctx, evaluatePolicy(results, ctx.rules));
    }
    case 'generate_security_report': {
      const results = await loadResults(ctx, value.scan_ids);
      const decision = evaluatePolicy(results, ctx.rules);
      return text(ctx, renderReport(results, decision, value.format as ReportFormat, value.include_remediation));
    }
    default:
      throw new ValidationError(`Unknown tool: ${name}`);
  }
}
