// src/formatters/ip.ts

import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

interface IpData {
  id?: string;
  ip?: string;
  attributes?: any;
  relationships?: Record<string, RelationshipData>;
}

export function formatRelationshipData(relType: string, item: any): string {
  const attrs = item.attributes || {};

  switch (relType) {
    case 'communicating_files':
    case 'downloaded_files': {
      const name = attrs.meaningful_name || attrs.names?.[0] || item.id;
      const type = attrs.type_description || attrs.type || 'File';
      return `• ${name} (${type})`;
    }

    case 'resolutions': {
      const host = attrs.host_name || item.id;
      const date = attrs.date ? formatDateTime(Number(attrs.date)).split(' ')[0] : '';
      return `• ${host}${date ? ` (${date})` : ''}`;
    }

    case 'urls': {
      const url = attrs.url || item.id;
      const mal = attrs.last_analysis_stats?.malicious;
      return `• ${url}${mal ? ` [🔴 ${mal} mal]` : ''}`;
    }

    case 'historical_ssl_certificates': {
      const sub = attrs.subject?.CN || item.id;
      const iss = attrs.issuer?.O || attrs.issuer?.CN || '';
      return `• ${sub}${iss ? ` (Issuer: ${iss})` : ''}`;
    }

    case 'related_threat_actors': {
      return `• Threat Actor: ${attrs.name || item.id}`;
    }

    default:
      return `• ${attrs.meaningful_name || attrs.name || item.id}`;
  }
}

export function formatIpResults(data: IpData): FormattedResult {
  try {
    const ip = data?.id || data?.ip || 'Unknown IP';
    const attributes = data?.attributes || {};
    const stats = attributes?.last_analysis_stats || {};
    const votes = attributes?.total_votes || { harmless: 0, malicious: 0 };
    const reputation = attributes?.reputation ?? 0;

    const netParts = [
      attributes.as_owner ? `${attributes.as_owner}` : null,
      attributes.asn ? `ASN: ${attributes.asn}` : null,
      attributes.country ? `Country: ${attributes.country}` : null,
      attributes.network ? `Net: ${attributes.network}` : null,
    ].filter(Boolean);

    const lines: string[] = [
      `### 🌐 VirusTotal IP Analysis: \`${ip}\``,
      `- **Network**: ${netParts.join(' | ') || 'N/A'}`,
      `- ${formatDetectionResults(stats)}`,
      `- **Reputation**: ${reputation} (Votes: ${votes.harmless} harmless, ${votes.malicious} malicious)`,
    ];

    // SSL Certificate (1-line compact)
    if (attributes?.last_https_certificate) {
      const cert = attributes.last_https_certificate;
      const sub = cert.subject?.CN || 'Unknown';
      const iss = cert.issuer?.O || cert.issuer?.CN || 'Unknown';
      const validUntil = cert.validity?.not_after ? formatDateTime(new Date(cert.validity.not_after).getTime() / 1000).split(' ')[0] : '';
      lines.push(`- **SSL Cert**: ${sub} (Issuer: ${iss}${validUntil ? `, Valid until: ${validUntil}` : ''})`);
    }

    // Key WHOIS summary (1 line)
    if (attributes?.whois) {
      const whoisLines = String(attributes.whois).split('\n');
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
      const org = findField(['OrgName:', 'Organization:', 'netname:']);
      const country = findField(['Country:']);
      const regDate = findField(['RegDate:', 'created:']);
      const whoisSummary = [
        org ? `Org: ${org}` : null,
        country ? `Country: ${country}` : null,
        regDate ? `RegDate: ${regDate}` : null,
      ].filter(Boolean).join(' | ');

      if (whoisSummary) {
        lines.push(`- **WHOIS**: ${whoisSummary}`);
      }
    }

    // Tags
    if (attributes?.tags?.length) {
      lines.push(`- **Tags**: ${attributes.tags.slice(0, 8).join(', ')}`);
    }

    // Relationships (Compact inline previews)
    if (data.relationships && Object.keys(data.relationships).length > 0) {
      lines.push(`- **Relationships Summary**:`);
      for (const [relType, relData] of Object.entries(data.relationships)) {
        const items = Array.isArray(relData.data) ? relData.data : relData.data ? [relData.data] : [];
        const count = relData.meta?.count ?? items.length;
        if (count === 0 && items.length === 0) continue;

        const previewItems: string[] = [];
        for (const it of items.slice(0, 3)) {
          const itAttrs = it.attributes || {};
          const label =
            itAttrs.meaningful_name ||
            itAttrs.host_name ||
            itAttrs.url ||
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
    logToFile(`Error formatting IP results: ${error}`);
    return {
      type: 'text',
      text: 'Error formatting IP results',
    };
  }
}
