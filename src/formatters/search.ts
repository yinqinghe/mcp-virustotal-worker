import { FormattedResult } from './types.js';
import { formatDateTime } from './utils.js';
import { logToFile } from '../utils/logging.js';

interface SearchItem {
  type: string;
  id: string;
  attributes?: Record<string, any>;
}

interface SearchMeta {
  cursor?: string;
  count?: number;
}

function formatItem(item: SearchItem): string {
  const attrs = item.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const detection = stats.malicious !== undefined
    ? ` [🔴 ${stats.malicious}/${(stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)} mal]`
    : '';

  switch (item.type) {
    case 'file': {
      const name = attrs.meaningful_name || attrs.names?.[0] || item.id;
      const fileType = attrs.type_description || attrs.type_tag || 'File';
      const sha256 = attrs.sha256 ? ` | SHA256: ${attrs.sha256}` : '';
      return `• [File] \`${name}\` (${fileType}${sha256})${detection}`;
    }
    case 'url': {
      const url = attrs.url || item.id;
      const title = attrs.title ? ` "${attrs.title.slice(0, 50)}"` : '';
      return `• [URL] \`${url}\`${title}${detection}`;
    }
    case 'domain':
      return `• [Domain] \`${item.id}\`${detection}`;
    case 'ip_address': {
      const net = [attrs.as_owner, attrs.country].filter(Boolean).join(', ');
      return `• [IP] \`${item.id}\`${net ? ` (${net})` : ''}${detection}`;
    }
    case 'comment': {
      const text = (attrs.text || '').replace(/\s+/g, ' ').slice(0, 100);
      return `• [Comment] ${item.id}: ${text}${text.length >= 100 ? '…' : ''}`;
    }
    default:
      return `• [${item.type}] \`${item.id}\``;
  }
}

export function formatSearchResults(
  query: string,
  data: SearchItem[],
  meta?: SearchMeta,
): FormattedResult {
  try {
    const items = Array.isArray(data) ? data : [];
    const lines: string[] = [
      `### 🔎 VirusTotal Search: \`${query}\` (${items.length}${meta?.count ? ` of ${meta.count}` : ''} results)`,
    ];

    if (items.length === 0) {
      lines.push('No matching objects found.');
    } else {
      for (const item of items) {
        lines.push(formatItem(item));
      }
    }

    if (meta?.cursor) {
      lines.push(`\n📄 Next page cursor: \`${meta.cursor}\``);
    }

    return { type: 'text', text: lines.join('\n') };
  } catch (error) {
    logToFile(`Error formatting search results: ${error}`);
    return { type: 'text', text: 'Error formatting search results' };
  }
}
