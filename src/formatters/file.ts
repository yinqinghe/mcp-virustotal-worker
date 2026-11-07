// src/formatters/file.ts
import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

interface FileData {
  attributes?: any;
  relationships?: Record<string, RelationshipData>;
}

export function formatFileSize(bytes: number): string {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  return `${size.toFixed(1)} ${units[unitIndex]}`;
}

// Compact relationship item renderer (for relationship pagination and report summary)
export function formatRelationshipData(relType: string, item: any): string {
  const attrs = item.attributes || {};

  switch (relType) {
    case 'behaviours': {
      const sandbox = attrs.sandbox_name || 'Sandbox';
      const verdicts = attrs.verdicts?.join(', ') || 'Clean';
      const acts = (attrs.processes_created?.length || 0) + (attrs.command_executions?.length || 0);
      return `• [${sandbox}] Verdict: ${verdicts} (Processes: ${acts}, Files Written: ${attrs.files_written?.length || 0})`;
    }

    case 'contacted_domains': {
      const id = item.id || attrs.id;
      return `• ${id}`;
    }

    case 'contacted_ips': {
      const ip = attrs.ip_address || item.id;
      const country = attrs.country ? ` (${attrs.country})` : '';
      const mal = attrs.last_analysis_stats?.malicious;
      const malInfo = mal ? ` [🔴 ${mal} mal]` : '';
      return `• ${ip}${country}${malInfo}`;
    }

    case 'dropped_files':
    case 'bundled_files':
    case 'communicating_files': {
      const name = attrs.meaningful_name || attrs.names?.[0] || item.id;
      const type = attrs.type_description || attrs.type || '';
      const size = attrs.size ? `, ${formatFileSize(attrs.size)}` : '';
      return `• ${name}${type ? ` (${type}${size})` : ''}`;
    }

    case 'related_threat_actors': {
      const name = attrs.name || item.id;
      return `• Actor: ${name}`;
    }

    case 'collections': {
      const name = attrs.name || item.id;
      return `• Collection: ${name}`;
    }

    default:
      return `• ${attrs.meaningful_name || attrs.name || item.id}`;
  }
}

export function formatFileResults(data: FileData): FormattedResult {
  try {
    const attributes = data?.attributes || {};
    const stats = attributes?.last_analysis_stats || {};
    const size = attributes?.size ? formatFileSize(attributes.size) : 'Unknown';
    const type = attributes?.type_description || attributes?.type_tag || 'Unknown';
    const name = attributes?.meaningful_name || attributes?.names?.[0] || 'Unknown File';
    const sha256 = attributes?.sha256 || 'N/A';
    const md5 = attributes?.md5 || '';

    const lines: string[] = [
      `### 📁 File Analysis: \`${name}\``,
      `- **Hashes**: SHA-256: \`${sha256}\`${md5 ? ` | MD5: \`${md5}\`` : ''}`,
      `- **Type & Size**: ${type} | ${size}${attributes?.first_submission_date ? ` | First seen: ${formatDateTime(attributes.first_submission_date).split(' ')[0]}` : ''}`,
      `- ${formatDetectionResults(stats)}`,
    ];

    // Threat classification
    const threatClass = attributes?.popular_threat_classification;
    if (threatClass?.suggested_threat_label) {
      const cats = threatClass.popular_threat_category?.map((c: any) => c.value).join(', ');
      lines.push(`- **Threat Classification**: \`${threatClass.suggested_threat_label}\`${cats ? ` (Category: ${cats})` : ''}`);
    }

    // Popular Security Vendors
    const popularEngines = ['Microsoft', 'Kaspersky', 'Symantec', 'Sophos', 'CrowdStrike'];
    const detectedPopular: string[] = [];
    if (attributes?.last_analysis_results) {
      for (const [engine, res] of Object.entries(attributes.last_analysis_results as Record<string, any>)) {
        if (popularEngines.includes(engine) && (res.category === 'malicious' || res.category === 'suspicious')) {
          detectedPopular.push(`${engine}: ${res.result || 'Malicious'}`);
        }
      }
    }
    if (detectedPopular.length > 0) {
      lines.push(`- **Flagged Engines**: ${detectedPopular.join(' | ')}`);
    }

    // Sandbox Verdicts summary (only if flagged or has verdicts)
    const sandboxResults = attributes?.sandbox_verdicts || {};
    const suspiciousSandboxes: string[] = [];
    for (const [name, verdict] of Object.entries(sandboxResults as Record<string, any>)) {
      if (verdict?.category === 'malicious' || verdict?.category === 'suspicious') {
        const id = verdict.malware_names?.[0] || verdict.malware_classification?.[0] || verdict.category;
        suspiciousSandboxes.push(`${name} [${id}]`);
      }
    }
    if (suspiciousSandboxes.length > 0) {
      lines.push(`- **Sandbox Detections**: ${suspiciousSandboxes.slice(0, 4).join(', ')}`);
    }

    // Rules summary (Sigma / YARA / IDS)
    const ruleParts: string[] = [];
    if (attributes?.sigma_analysis_results?.length) {
      ruleParts.push(`Sigma: ${attributes.sigma_analysis_results.length}`);
    }
    if (attributes?.crowdsourced_yara_results?.length) {
      ruleParts.push(`YARA: ${attributes.crowdsourced_yara_results.length}`);
    }
    if (attributes?.crowdsourced_ids_results?.length) {
      ruleParts.push(`IDS Alerts: ${attributes.crowdsourced_ids_results.length}`);
    }
    if (ruleParts.length > 0) {
      lines.push(`- **Detections Rules**: ${ruleParts.join(' | ')}`);
    }

    // Tags (inline compact)
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
            itAttrs.names?.[0] ||
            itAttrs.ip_address ||
            itAttrs.url ||
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
    logToFile(`Error formatting file results: ${error}`);
    return {
      type: 'text',
      text: 'Error formatting file results',
    };
  }
}
