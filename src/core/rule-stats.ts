import { DojoFinding } from './defectdojo';
import { TOOLS_BY_SCAN_TYPE } from './types';

/**
 * Per-rule statistics from DefectDojo, for tuning rules. A finding's rule is its
 * vuln_id_from_tool: the project rule ID (sast-<language>-<NNNN>) for SAST, the CVE/GHSA for
 * dependency scanners and the template id for Nuclei.
 *
 * Decisions come from people in DefectDojo (false_p, verified, risk accepted): this integration
 * never sets them, so they are the reliable signal. AI verdict tags are reported next to them as
 * a hint only; a rule should not be disabled because a model said so.
 */
export interface RuleStat {
  rule: string;
  /** Opengrep rule (directory.id in opengrep-rules) behind a project rule ID, when known. */
  original?: string;
  tool?: string;
  total: number;
  open: number;
  /** Decided by a person: false positive / true issue (verified or risk accepted). */
  false_positive: number;
  confirmed: number;
  mitigated: number;
  /** Duplicates: DefectDojo's own deduplication, or a corr-duplicate of another rule or tool. */
  duplicate: number;
  ai_false_positive: number;
  ai_true_positive: number;
  /** false_positive / (false_positive + confirmed); null until someone has reviewed one. */
  fp_rate: number | null;
  suggestion: Suggestion;
}

export type Suggestion = 'tune-or-disable' | 'redundant' | 'review-ai-suspects-fp' | 'reliable' | 'not-enough-data';

const SUGGESTION_ORDER: Record<Suggestion, number> = {
  'tune-or-disable': 0,
  redundant: 1,
  'review-ai-suspects-fp': 2,
  'not-enough-data': 3,
  reliable: 4
};

export const SUGGESTION_TEXT: Record<Suggestion, string> = {
  'tune-or-disable': 'Most reviewed findings are false positives: tune the rule (exclusions, patterns) or disable it',
  redundant: 'Mostly reported by another rule or tool too: keep one of them',
  'review-ai-suspects-fp': 'Few reviews yet, but the AI flags many as false positives: review a sample',
  reliable: 'Reviewed findings are mostly real: keep',
  'not-enough-data': 'Not enough reviewed findings yet'
};

const KNOWN_TOOLS = new Set(Object.values(TOOLS_BY_SCAN_TYPE).flat());

export interface RuleStatsOptions {
  /** Reviewed findings needed before a rule is called noisy or reliable. */
  minReviewed: number;
  /** Project rule ID -> opengrep-rules key, from the rule ID catalog. */
  originals?: Record<string, string>;
}

export function computeRuleStats(findings: DojoFinding[], options: RuleStatsOptions): RuleStat[] {
  const stats = new Map<string, Omit<RuleStat, 'fp_rate' | 'suggestion'>>();
  for (const finding of findings) {
    const rule = finding.vuln_id_from_tool || finding.title || `finding-${finding.id}`;
    const tags = finding.tags ?? [];
    const tool = tags.find((tag) => KNOWN_TOOLS.has(tag));
    const key = `${tool ?? ''}|${rule}`;
    let stat = stats.get(key);
    if (!stat) {
      stat = { rule, total: 0, open: 0, false_positive: 0, confirmed: 0, mitigated: 0, duplicate: 0, ai_false_positive: 0, ai_true_positive: 0 };
      if (tool) stat.tool = tool;
      const original = options.originals?.[rule];
      if (original) stat.original = original;
      stats.set(key, stat);
    }
    stat.total++;
    if (finding.active && !finding.is_mitigated && !finding.false_p) stat.open++;
    if (finding.false_p) stat.false_positive++;
    else if (finding.verified || finding.risk_accepted) stat.confirmed++;
    if (finding.is_mitigated) stat.mitigated++;
    if (finding.duplicate || tags.includes('corr-duplicate')) stat.duplicate++;
    if (tags.includes('ai-false-positive')) stat.ai_false_positive++;
    if (tags.includes('ai-true-positive')) stat.ai_true_positive++;
  }

  const out: RuleStat[] = [];
  for (const stat of stats.values()) {
    const reviewed = stat.false_positive + stat.confirmed;
    const fpRate = reviewed ? stat.false_positive / reviewed : null;
    let suggestion: Suggestion = 'not-enough-data';
    if (reviewed >= options.minReviewed && fpRate !== null && fpRate >= 0.7) suggestion = 'tune-or-disable';
    else if (stat.total >= 3 && stat.duplicate / stat.total >= 0.8) suggestion = 'redundant';
    else if (reviewed < options.minReviewed && stat.total >= 3 && stat.ai_false_positive / stat.total >= 0.5) suggestion = 'review-ai-suspects-fp';
    else if (reviewed >= options.minReviewed && fpRate !== null && fpRate <= 0.2) suggestion = 'reliable';
    out.push({ ...stat, fp_rate: fpRate, suggestion });
  }
  return out.sort(
    (a, b) => SUGGESTION_ORDER[a.suggestion] - SUGGESTION_ORDER[b.suggestion] || (b.fp_rate ?? -1) - (a.fp_rate ?? -1) || b.total - a.total || a.rule.localeCompare(b.rule)
  );
}

function cell(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

export function renderRuleStatsMarkdown(product: string, stats: RuleStat[], minReviewed: number): string {
  const lines = [
    `# Rule statistics: ${cell(product)}`,
    '',
    `From DefectDojo. "FP" and "Confirmed" are decisions made by people (false positive; verified or risk accepted); AI tags are a hint only. A rule needs ${minReviewed} reviewed findings before it is called noisy or reliable.`,
    '',
    '| Rule | Opengrep rule | Tool | Total | Open | FP | Confirmed | FP rate | Duplicate | AI: FP | Suggestion |',
    '|---|---|---|---|---|---|---|---|---|---|---|'
  ];
  for (const s of stats) {
    lines.push(
      `| ${cell(s.rule)} | ${cell(s.original ?? '')} | ${s.tool ?? ''} | ${s.total} | ${s.open} | ${s.false_positive} | ${s.confirmed} | ${
        s.fp_rate === null ? '-' : `${Math.round(s.fp_rate * 100)}%`
      } | ${s.duplicate} | ${s.ai_false_positive} | ${SUGGESTION_TEXT[s.suggestion]} |`
    );
  }
  return `${lines.join('\n')}\n`;
}
