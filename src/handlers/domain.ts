import { z } from 'zod';
import { queryVirusTotal, queryVirusTotalWithRelationships } from '../utils/api.js';
import { formatDomainResults, formatRelationshipPage } from '../formatters/index.js';
import {
  GetDomainReportArgsSchema,
  GetDomainRelationshipArgsSchema,
} from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipItem, RelationshipData, DomainResponse } from '../types/virustotal.js';

const DEFAULT_RELATIONSHIPS = [
  'historical_whois',
  'historical_ssl_certificates',
  'resolutions',
  'communicating_files',
  'downloaded_files',
  'referrer_files',
] as const;

function formatDate(dateStr: string | number): string {
  try {
    if (typeof dateStr === 'number') {
      return new Date(dateStr * 1000).toISOString().split('T')[0];
    }
    return new Date(dateStr).toISOString().split('T')[0];
  } catch {
    return 'Unknown';
  }
}

function formatRelationshipData(relType: string, item: RelationshipItem): string {
  const attrs = item.attributes || {};

  switch (relType) {
    case 'resolutions': {
      const date = attrs.date ? new Date(Number(attrs.date) * 1000).toISOString().split('T')[0] : '';
      const mal = attrs.ip_address_last_analysis_stats?.malicious;
      return `• IP: ${attrs.ip_address} (${attrs.host_name || 'Host'}${date ? `, ${date}` : ''})${mal ? ` [🔴 ${mal} mal]` : ''}`;
    }

    case 'communicating_files':
    case 'downloaded_files':
    case 'referrer_files': {
      const name = attrs.meaningful_name || attrs.names?.[0] || item.id;
      const type = attrs.type_description || attrs.type || 'File';
      return `• ${name} (${type})`;
    }

    case 'urls': {
      const mal = attrs.last_analysis_stats?.malicious;
      return `• ${attrs.url || item.id}${mal ? ` [🔴 ${mal} mal]` : ''}`;
    }

    case 'historical_whois': {
      const whoisMap = attrs.whois_map || {};
      const reg = whoisMap['Registrar'] || attrs.registrar_name;
      const org = whoisMap['Registrant Organization'];
      return `• WHOIS (${attrs.last_updated ? formatDate(attrs.last_updated) : 'Record'}): ${reg || 'Unknown'}${org ? ` | ${org}` : ''}`;
    }

    case 'historical_ssl_certificates': {
      const sub = attrs.subject?.CN || item.id;
      const iss = attrs.issuer?.O || attrs.issuer?.CN || '';
      return `• SSL: ${sub}${iss ? ` (Issuer: ${iss})` : ''}`;
    }

    default:
      if (attrs.hostname) return `• ${attrs.hostname}`;
      if (attrs.ip_address) return `• ${attrs.ip_address}`;
      if (attrs.url) return `• ${attrs.url}`;
      if (attrs.value) return `• ${attrs.value}`;
      return `• ${item.id}`;
  }
}

export async function handleGetDomainReport(args: z.infer<typeof GetDomainReportArgsSchema>) {
  const { domain, relationships = DEFAULT_RELATIONSHIPS } = args;

  logToFile('Getting domain report with relationships...');
  const report = (await queryVirusTotalWithRelationships(
    `/domains/${domain}`,
    relationships,
  )) as DomainResponse;

  const relationshipData: Record<string, RelationshipData> = {};
  for (const [relType, relData] of Object.entries(report.data?.relationships || {})) {
    const typed = relData as RelationshipData;
    if (Array.isArray(typed.data)) {
      relationshipData[relType] = {
        data: typed.data.map((item: RelationshipItem) => ({
          ...item,
          formattedOutput: formatRelationshipData(relType, item),
        })),
        meta: typed.meta,
      };
    } else if (typed.data) {
      relationshipData[relType] = {
        data: {
          ...typed.data,
          formattedOutput: formatRelationshipData(relType, typed.data),
        },
        meta: typed.meta,
      };
    }
  }

  const combinedData = {
    ...report.data,
    relationships: relationshipData,
  };

  return {
    content: [formatDomainResults(combinedData)],
  };
}

export async function handleGetDomainRelationship(
  args: z.infer<typeof GetDomainRelationshipArgsSchema>,
) {
  const { domain, relationship, limit, cursor } = args;

  const params: Record<string, string | number> = { limit };
  if (cursor) params.cursor = cursor;

  logToFile(`Fetching ${relationship} for domain: ${domain}`);
  const result = await queryVirusTotal(
    `/domains/${domain}/${relationship}`,
    'get',
    undefined,
    params,
  );

  return {
    content: [
      formatRelationshipPage({
        entity: 'domain',
        entityId: domain,
        relationship,
        data: result.data,
        meta: result.meta,
        renderItem: formatRelationshipData,
      }),
    ],
  };
}
