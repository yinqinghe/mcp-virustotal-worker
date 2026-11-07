import { FormattedResult } from './types.js';
import { formatDateTime } from './utils.js';
import { logToFile } from '../utils/logging.js';

interface CollectionData {
  type?: string;
  id?: string;
  attributes?: {
    name?: string;
    description?: string;
    collection_type?: string;
    tags?: string[];
    targeted_regions?: string[];
    targeted_industries?: string[];
    source_region?: string;
    motivations?: string[];
    threat_categories?: string[];
    aliases?: string[];
    creation_date?: number;
    last_modification_date?: number;
    files_count?: number;
    urls_count?: number;
    domains_count?: number;
    ip_addresses_count?: number;
    references_count?: number;
    [key: string]: any;
  };
  relationships?: Record<string, { data: any; meta?: { count?: number } }>;
}

export function formatCollectionResults(data: CollectionData): FormattedResult {
  try {
    const attrs = data?.attributes || {};
    const name = attrs.name || data?.id || 'Unknown';
    const lines: string[] = [
      `### 📚 Collection: \`${name}\` (ID: \`${data?.id || 'N/A'}\`)`,
    ];

    if (attrs.collection_type) lines.push(`- **Type**: ${attrs.collection_type}`);
    if (attrs.description) {
      const desc = attrs.description.replace(/\s+/g, ' ').slice(0, 200);
      lines.push(`- **Description**: ${desc}${desc.length >= 200 ? '…' : ''}`);
    }

    const metaParts = [
      attrs.aliases?.length ? `Aliases: ${attrs.aliases.join(', ')}` : null,
      attrs.threat_categories?.length ? `Threats: ${attrs.threat_categories.join(', ')}` : null,
      attrs.targeted_industries?.length ? `Targets: ${attrs.targeted_industries.join(', ')}` : null,
    ].filter(Boolean);
    if (metaParts.length > 0) {
      lines.push(`- **Context**: ${metaParts.join(' | ')}`);
    }

    const counts: string[] = [];
    if (attrs.files_count != null) counts.push(`Files: ${attrs.files_count}`);
    if (attrs.urls_count != null) counts.push(`URLs: ${attrs.urls_count}`);
    if (attrs.domains_count != null) counts.push(`Domains: ${attrs.domains_count}`);
    if (attrs.ip_addresses_count != null) counts.push(`IPs: ${attrs.ip_addresses_count}`);
    if (counts.length) {
      lines.push(`- **IOC Counts**: ${counts.join(' | ')}`);
    }

    if (data.relationships && Object.keys(data.relationships).length > 0) {
      lines.push(`- **Relationships Preview**:`);
      for (const [relType, relData] of Object.entries(data.relationships)) {
        const items = Array.isArray(relData.data) ? relData.data : relData.data ? [relData.data] : [];
        const count = relData.meta?.count ?? items.length;
        if (count === 0 && items.length === 0) continue;

        const previewItems: string[] = [];
        for (const item of items.slice(0, 3)) {
          const itemAttrs = item.attributes || {};
          const label = itemAttrs.meaningful_name || itemAttrs.url || itemAttrs.ip_address || itemAttrs.name || item.id;
          if (label) previewItems.push(String(label));
        }

        const more = count > 3 ? ` (+${count - 3} more)` : '';
        lines.push(`  • **${relType}** (${count}): ${previewItems.join(', ')}${more}`);
      }
    }

    return { type: 'text', text: lines.join('\n') };
  } catch (error) {
    logToFile(`Error formatting collection results: ${error}`);
    return { type: 'text', text: 'Error formatting collection results' };
  }
}
