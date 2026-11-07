// src/formatters/url.ts

import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

export interface UrlAttributes {
  url?: string;
  last_final_url?: string;
  title?: string;
  categories?: Record<string, string>;
  first_submission_date?: number;
  last_analysis_date?: number;
  last_http_response_code?: number;
  reputation?: number;
  targeted_brand?: Record<string, string>;
  tags?: string[];
  total_votes?: {
    harmless: number;
    malicious: number;
  };
  last_analysis_stats?: {
    harmless: number;
    malicious: number;
    suspicious: number;
    timeout: number;
    undetected: number;
  };
}

export interface UrlData {
  id?: string;
  url?: string;
  attributes?: UrlAttributes;
  scan_id?: string;
  scan_date?: string;
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

    case 'contacted_domains': {
      return `• ${item.id || attrs.id}`;
    }

    case 'contacted_ips': {
      const ip = attrs.ip_address || item.id;
      const country = attrs.country ? ` (${attrs.country})` : '';
      const mal = attrs.last_analysis_stats?.malicious;
      return `• ${ip}${country}${mal ? ` [🔴 ${mal} mal]` : ''}`;
    }

    case 'redirects_to':
    case 'redirecting_urls': {
      return `• ${attrs.url || item.id}`;
    }

    case 'related_threat_actors': {
      return `• Threat Actor: ${attrs.name || item.id}`;
    }

    default:
      return `• ${attrs.meaningful_name || attrs.name || item.id}`;
  }
}

export function formatUrlScanResults(data: UrlData): FormattedResult {
  try {
    const attributes = data?.attributes || {};
    const stats = attributes?.last_analysis_stats || {};
    const url = attributes?.url || data?.url || data?.id || 'Unknown URL';
    const votes = attributes?.total_votes || { harmless: 0, malicious: 0 };
    const reputation = attributes?.reputation ?? 0;

    const lines: string[] = [
      `### 🔗 VirusTotal URL Analysis: \`${url}\``,
      attributes.last_final_url && attributes.last_final_url !== url
        ? `- **Final Redirect**: \`${attributes.last_final_url}\``
        : null,
      `- ${formatDetectionResults(stats)}`,
      `- **Reputation**: ${reputation} (Votes: ${votes.harmless} harmless, ${votes.malicious} malicious)${attributes.last_http_response_code ? ` | HTTP Status: ${attributes.last_http_response_code}` : ''}`,
    ].filter(Boolean) as string[];

    if (attributes.title) {
      lines.push(`- **Page Title**: ${attributes.title.trim().replace(/\s+/g, ' ')}`);
    }

    // Categories (compact)
    if (attributes.categories && Object.keys(attributes.categories).length > 0) {
      const distinctCats = Array.from(new Set(Object.values(attributes.categories))).slice(0, 5);
      lines.push(`- **Categories**: ${distinctCats.join(', ')}`);
    }

    // Targeted Brand
    if (attributes.targeted_brand && Object.keys(attributes.targeted_brand).length > 0) {
      const brands = Object.values(attributes.targeted_brand).join(', ');
      lines.push(`- **Targeted Brands**: ${brands}`);
    }

    // Tags
    if (attributes.tags?.length) {
      lines.push(`- **Tags**: ${attributes.tags.slice(0, 8).join(', ')}`);
    }

    // Relationships summary
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
            itAttrs.ip_address ||
            itAttrs.url ||
            itAttrs.id ||
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
    logToFile(`Error formatting URL scan results: ${error}`);
    return {
      type: 'text',
      text: 'Error formatting URL scan results',
    };
  }
}
