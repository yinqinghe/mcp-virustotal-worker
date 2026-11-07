import { FormattedResult } from './types.js';
import { logToFile } from '../utils/logging.js';

const PREVIEW = 3;

function section(title: string, items: any[] | undefined, render: (item: any) => string): string[] {
  if (!items || items.length === 0) return [];
  const preview = items.slice(0, PREVIEW).map(render).filter(Boolean);
  const more = items.length > PREVIEW ? ` (+${items.length - PREVIEW} more)` : '';
  return [`- **${title}** (${items.length}): ${preview.join('; ')}${more}`];
}

export function formatBehaviourSummary(hash: string, data: any): FormattedResult {
  try {
    if (!data) {
      return { type: 'text', text: `No sandbox behaviour summary available for ${hash}.` };
    }

    const lines: string[] = [
      `### 🧪 Sandbox Behaviour Summary: \`${hash}\``,
    ];

    if (data.verdicts?.length) {
      lines.push(`- **Verdicts**: ${data.verdicts.join(', ')}`);
    }
    if (data.tags?.length) {
      lines.push(`- **Behaviour Tags**: ${data.tags.slice(0, 10).join(', ')}`);
    }

    // MITRE ATT&CK Techniques (top 4)
    if (data.mitre_attack_techniques?.length) {
      const techs = data.mitre_attack_techniques.slice(0, 4).map((t: any) => {
        const id = t.id || t.signature_id || 'T?';
        const name = t.signature_description || t.description || '';
        return `${id} (${name})`;
      });
      const more = data.mitre_attack_techniques.length > 4 ? ` (+${data.mitre_attack_techniques.length - 4} more)` : '';
      lines.push(`- **MITRE ATT&CK** (${data.mitre_attack_techniques.length}): ${techs.join('; ')}${more}`);
    }

    // High-value activity sections
    lines.push(
      ...section('Processes Created', data.processes_created, (p) => String(p)),
      ...section('Processes Injected', data.processes_injected, (p) => String(p)),
      ...section('Commands Executed', data.command_executions, (c) => String(c)),
      ...section('Files Dropped', data.files_dropped, (f) => `${f.path || f.name || 'file'}`),
      ...section('Files Written', data.files_written, (f) => String(f)),
      ...section('Registry Keys Set', data.registry_keys_set, (r) => `${r.key || ''}`),
      ...section('DNS Lookups', data.dns_lookups, (d) => `${d.hostname || ''}`),
      ...section('Network Traffic', data.ip_traffic, (t) => `${t.destination_ip || ''}:${t.destination_port || ''}`),
      ...section('HTTP Requests', data.http_conversations, (h) => `${h.request_method || 'GET'} ${h.url || ''}`),
      ...section('Mutexes', data.mutexes_created, (m) => String(m)),
    );

    // IDS Alerts (compact)
    if (data.ids_results?.length) {
      const alerts = data.ids_results.slice(0, 3).map((r: any) => `${r.rule_msg || r.rule_id || 'Alert'} [${r.alert_severity || 'info'}]`);
      const more = data.ids_results.length > 3 ? ` (+${data.ids_results.length - 3} more)` : '';
      lines.push(`- **IDS Alerts** (${data.ids_results.length}): ${alerts.join('; ')}${more}`);
    }

    // Signatures
    if (data.signature_matches?.length) {
      const sigs = data.signature_matches.slice(0, 3).map((s: any) => `${s.description || s.id || 'Signature'}`);
      const more = data.signature_matches.length > 3 ? ` (+${data.signature_matches.length - 3} more)` : '';
      lines.push(`- **Signatures** (${data.signature_matches.length}): ${sigs.join('; ')}${more}`);
    }

    return { type: 'text', text: lines.join('\n') };
  } catch (error) {
    logToFile(`Error formatting behaviour summary: ${error}`);
    return { type: 'text', text: 'Error formatting behaviour summary' };
  }
}
