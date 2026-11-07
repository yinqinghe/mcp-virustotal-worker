// src/formatters/domain.ts

import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { logToFile } from '../utils/logging.js';
import { DomainData } from '../types/virustotal.js';

export function formatDomainResults(data: DomainData): FormattedResult {
  try {
    const domain = data?.id || 'Unknown Domain';
    const attributes = (data as any)?.attributes || {};
    const stats = attributes?.last_analysis_stats || {};
    const categories = attributes?.categories || {};
    const ranks = attributes?.popularity_ranks || {};
    const whois = attributes?.whois || '';
    const dnsRecords = attributes?.last_dns_records || [];
    const threatSeverity = attributes?.threat_severity;
    const reputation = attributes?.reputation ?? 0;

    const lines: string[] = [
      `### 🌍 VirusTotal Domain Analysis: \`${domain}\``,
      `- ${formatDetectionResults(stats)}`,
      `- **Reputation**: ${reputation}${threatSeverity?.threat_severity_level ? ` | Threat Level: ${threatSeverity.threat_severity_level}` : ''}`,
    ];

    // Categories (distinct inline)
    if (Object.keys(categories).length > 0) {
      const distinctCats = Array.from(new Set(Object.values(categories))).slice(0, 5);
      lines.push(`- **Categories**: ${distinctCats.join(', ')}`);
    }

    // DNS Records (compact inline)
    if (dnsRecords.length > 0) {
      const dnsSummary = dnsRecords
        .slice(0, 4)
        .map((r: any) => `${r.type}: ${r.value}`)
        .join(' | ');
      const more = dnsRecords.length > 4 ? ` (+${dnsRecords.length - 4} more)` : '';
      lines.push(`- **DNS Records**: ${dnsSummary}${more}`);
    }

    // Popularity Rankings (compact inline)
    if (Object.keys(ranks).length > 0) {
      const rankList = Object.entries(ranks)
        .slice(0, 3)
        .map(([service, info]: [string, any]) => `${service}: #${info.rank || 'N/A'}`)
        .join(', ');
      lines.push(`- **Popularity**: ${rankList}`);
    }

    // WHOIS summary (1 line)
    if (whois) {
      const whoisLines = String(whois).split('\n');
      const findField = (prefixes: string[]) => {
        for (const line of whoisLines) {
          const trimmed = line.trim();
          for (const prefix of prefixes) {
            if (trimmed.toLowerCase().startsWith(prefix.toLowerCase())) {
              return trimmed.split(':')[1]?.trim() || '';
            }
          }
        }
        return '';
      };
      const registrar = findField(['Registrar:']);
      const created = findField(['Creation Date:']);
      const org = findField(['Registrant Organization:', 'Admin Organization:']);
      const whoisSummary = [
        registrar ? `Registrar: ${registrar}` : null,
        created ? `Created: ${created.split('T')[0]}` : null,
        org ? `Org: ${org}` : null,
      ].filter(Boolean).join(' | ');

      if (whoisSummary) {
        lines.push(`- **WHOIS**: ${whoisSummary}`);
      }
    }

    // Relationships summary
    const relationships = (data as any)?.relationships;
    if (relationships && Object.keys(relationships).length > 0) {
      lines.push(`- **Relationships Summary**:`);
      for (const [relType, relData] of Object.entries(relationships as Record<string, any>)) {
        const items = Array.isArray(relData.data) ? relData.data : relData.data ? [relData.data] : [];
        const count = relData.meta?.count ?? items.length;
        if (count === 0 && items.length === 0) continue;

        const previewItems: string[] = [];
        for (const it of items.slice(0, 3)) {
          const itAttrs = it.attributes || {};
          const label =
            itAttrs.meaningful_name ||
            itAttrs.ip_address ||
            itAttrs.host_name ||
            itAttrs.name ||
            it.id;
          if (label) previewItems.push(String(label));
        }

        const more = count > 3 ? ` (+${count - 3} more)` : '';
        lines.push(`  • **${relType}** (${count}): ${previewItems.join(', ')}${more}`);
      }
    }

    return {
      type: 'text',
      text: lines.join('\n'),
    };
  } catch (error) {
    logToFile(`Error formatting domain results: ${error}`);
    return {
      type: 'text',
      text: 'Error formatting domain results',
    };
  }
}
