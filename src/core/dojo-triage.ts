import { CorrelatedGroup } from './correlate';
import { AI_TAG, DefectDojoClient, DojoFinding, hasAiVerdict, ImportsRecord, isDecided, replaceManagedTags } from './defectdojo';
import { runTriage, TriageModel, TriageOptions, TriageReport, TriageStatus } from './triage';

export interface DojoTriageOptions {
  model: TriageModel;
  modelName: string;
  config: TriageOptions['config'];
  scanIds: string[];
  /** Triage again findings that already carry an AI verdict from an earlier build. */
  retriage?: boolean;
}

export interface DojoTriageOutcome {
  report: TriageReport;
  findings_tagged: number;
  notes_added: number;
}

/**
 * AI triage after the DefectDojo import, using DefectDojo as the source of truth:
 * - groups whose open findings a person already decided (false positive, risk accepted,
 *   verified, out of scope), or that are all closed, are not sent to the model;
 * - groups whose open findings already carry an AI verdict from an earlier build are skipped
 *   unless `retriage` is set, so each finding is triaged once instead of every build;
 * - verdicts are written back to the open, undecided findings only: `ai-*` tags (other tags
 *   kept) and one note with the rationale. Status fields are never changed.
 */
export async function triageInDefectDojo(
  client: DefectDojoClient,
  groups: CorrelatedGroup[],
  imports: ImportsRecord,
  options: DojoTriageOptions
): Promise<DojoTriageOutcome> {
  const byKey = new Map<string, DojoFinding>();
  for (const entry of imports.imports) {
    if (entry.status !== 'imported' || entry.test_id === undefined) continue;
    for (const finding of await client.findingsOfTest(entry.test_id)) {
      if (finding.unique_id_from_tool) byKey.set(`${entry.scan_id}:${finding.unique_id_from_tool}`, finding);
    }
  }

  const skip = new Map<string, TriageStatus>();
  const openMembers = new Map<string, DojoFinding[]>();
  for (const group of groups) {
    const members = group.refs.map((ref) => byKey.get(`${ref.scan_id}:${ref.finding.id}`)).filter((f): f is DojoFinding => Boolean(f));
    const open = members.filter((finding) => finding.active !== false && !finding.is_mitigated && !isDecided(finding));
    openMembers.set(group.id, open);
    if (members.length === 0) skip.set(group.id, 'not_in_defectdojo');
    else if (open.length === 0) skip.set(group.id, 'human_decided');
    else if (!options.retriage && open.every(hasAiVerdict)) skip.set(group.id, 'previously_triaged');
  }

  const report = await runTriage(groups, {
    model: options.model,
    modelName: options.modelName,
    config: options.config,
    scanIds: options.scanIds,
    skip
  });

  let tagged = 0;
  let notes = 0;
  for (const group of report.groups) {
    const triage = group.triage;
    if (!triage) continue;
    const tags = [`ai-${triage.verdict.replace(/_/g, '-')}`, `ai-confidence-${triage.confidence}`, `ai-priority-${triage.priority.toLowerCase()}`];
    const note = [
      `AI triage (advisory, ${report.model}): ${triage.verdict}, confidence ${triage.confidence}, priority ${triage.priority}.`,
      triage.rationale,
      triage.recommendation ? `Recommendation: ${triage.recommendation}` : '',
      group.findings.length > 1 ? `Correlated group ${group.id}: reported by ${group.tools.join(', ')} (${group.findings.length} findings).` : ''
    ]
      .filter(Boolean)
      .join('\n\n');
    for (const finding of openMembers.get(group.id) ?? []) {
      const next = replaceManagedTags(finding.tags ?? [], AI_TAG, tags);
      if (next) {
        await client.setTags(finding.id, next);
        tagged++;
      }
      await client.addNote(finding.id, note);
      notes++;
    }
  }
  return { report, findings_tagged: tagged, notes_added: notes };
}
