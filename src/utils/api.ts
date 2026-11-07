import axios, { AxiosError } from 'axios';
import { logToFile } from './logging.js';

export class VirusTotalApiError extends Error {
  constructor(message: string, public status?: number, public code?: string) {
    super(message);
    this.name = 'VirusTotalApiError';
  }
}

interface VirusTotalErrorResponse {
  error?: { code?: string; message?: string };
}

export function maskApiKey(key: string): string {
  if (!key) return 'none';
  if (key.length <= 8) return '****';
  return `${key.slice(0, 4)}...${key.slice(-4)}`;
}

export class ApiKeyPool {
  private keys: string[] = [];
  private currentIndex = 0;
  private cooldowns = new Map<string, number>();

  constructor(keys?: string | string[]) {
    if (keys) {
      this.setKeys(keys);
    }
  }

  setKeys(input?: string | string[]): void {
    if (!input) return;
    const rawList = Array.isArray(input) ? input : [input];
    const parsed: string[] = [];
    for (const item of rawList) {
      if (!item) continue;
      const str = String(item).trim();
      if (!str) continue;
      if (str.startsWith('[') && str.endsWith(']')) {
        try {
          const arr = JSON.parse(str);
          if (Array.isArray(arr)) {
            for (const x of arr) {
              const s = String(x).trim().replace(/^['"]|['"]$/g, '');
              if (s) parsed.push(s);
            }
            continue;
          }
        } catch {}
      }
      for (const k of str.split(/[\r\n,;]+/)) {
        const clean = k.trim().replace(/^['"]|['"]$/g, '');
        if (clean) parsed.push(clean);
      }
    }
    const unique = Array.from(new Set(parsed));
    if (unique.length > 0) {
      this.keys = unique;
      if (this.currentIndex >= this.keys.length) {
        this.currentIndex = 0;
      }
    }
  }

  getKeys(): string[] {
    return this.keys;
  }

  markCooldown(key: string, durationMs: number): void {
    this.cooldowns.set(key, Date.now() + durationMs);
  }

  isCooldown(key: string): boolean {
    const expires = this.cooldowns.get(key);
    if (!expires) return false;
    if (Date.now() >= expires) {
      this.cooldowns.delete(key);
      return false;
    }
    return true;
  }

  clearCooldown(key: string): void {
    this.cooldowns.delete(key);
  }

  getNextKeyIndex(): number {
    if (this.keys.length === 0) return -1;
    const n = this.keys.length;
    const selected = this.currentIndex;
    this.currentIndex = (this.currentIndex + 1) % n;
    return selected;
  }
}

const keyPool = new ApiKeyPool();

export function getKeyPool(): ApiKeyPool {
  return keyPool;
}

export function initVirusTotalClient(overrideKey?: string | string[]): void {
  const keys = overrideKey || process.env.VIRUSTOTAL_API_KEYS || process.env.VIRUSTOTAL_API_KEY;
  if (keys) {
    keyPool.setKeys(keys);
  }
  if (keyPool.getKeys().length === 0) {
    throw new Error('VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEYS environment variable is required');
  }
}

export async function queryVirusTotal(
  endpoint: string,
  method: 'get' | 'post' = 'get',
  data?: any,
  params?: Record<string, string | number | boolean>
) {
  if (!endpoint) throw new Error('Endpoint is required');

  if (keyPool.getKeys().length === 0) {
    initVirusTotalClient();
  }

  const keys = keyPool.getKeys();
  const n = keys.length;
  if (n === 0) {
    throw new VirusTotalApiError('No VirusTotal API keys configured', 500);
  }

  const startIndex = keyPool.getNextKeyIndex();
  let lastError: any = null;

  for (let attempt = 0; attempt < n; attempt++) {
    const keyIdx = (startIndex + attempt) % n;
    const currentKey = keys[keyIdx];

    // If key is in cooldown, and other keys are not in cooldown, skip it
    if (n > 1 && keyPool.isCooldown(currentKey)) {
      const hasAvailable = keys.some((k) => !keyPool.isCooldown(k));
      if (hasAvailable) {
        logToFile(`[Key rotation] Key ${maskApiKey(currentKey)} is in cooldown, skipping to next.`);
        continue;
      }
    }

    try {
      logToFile(`${method.toUpperCase()} ${endpoint} [Key: ${maskApiKey(currentKey)} (attempt ${attempt + 1}/${n})]`);
      if (params) logToFile(`Request params: ${Object.keys(params).join(', ')}`);

      const url = `https://www.virustotal.com/api/v3${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
      const response = await axios({
        url,
        method,
        headers: { 'x-apikey': currentKey },
        params,
        data,
      });

      logToFile(`Response status: ${response.status}`);
      keyPool.clearCooldown(currentKey);
      return response.data;
    } catch (error: any) {
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError<VirusTotalErrorResponse>;
        const status = axiosError.response?.status;
        const code = axiosError.response?.data?.error?.code;
        const message = axiosError.response?.data?.error?.message || axiosError.message;

        lastError = new VirusTotalApiError(`VirusTotal API error: ${message}`, status, code);
        logToFile(`API Error: ${status} [${code}] - ${message}`);

        // Check if error is key-related: rate limit, quota exceeded, wrong credentials, suspended
        const isQuotaOrRateLimit =
          status === 429 ||
          code === 'QuotaExceededError' ||
          code === 'TransientRateLimitExceededError' ||
          /quota|rate limit/i.test(message);

        const isAuthError =
          status === 401 ||
          status === 403 ||
          code === 'WrongCredentialsError' ||
          code === 'UserNotActiveError' ||
          /unauthorized|forbidden|credentials/i.test(message);

        if ((isQuotaOrRateLimit || isAuthError) && n > 1) {
          const cooldownMs = isQuotaOrRateLimit ? 60 * 1000 : 300 * 1000;
          keyPool.markCooldown(currentKey, cooldownMs);
          logToFile(`[Key rotation] Key ${maskApiKey(currentKey)} failed (${status} / ${code || message}). Skipping to next available key...`);
          continue;
        }

        // For non-key errors (e.g. 404 NotFound, 400 BadRequest), do not burn other keys
        throw lastError;
      }

      lastError = error;
      if (n > 1) {
        keyPool.markCooldown(currentKey, 30 * 1000);
        logToFile(`[Key rotation] Network error with key ${maskApiKey(currentKey)}. Skipping to next...`);
        continue;
      }
      throw error;
    }
  }

  throw lastError;
}

export function encodeUrlForVt(url: string): string {
  return Buffer.from(url).toString('base64url');
}

// Canonical relationship lists per VirusTotal API v3 docs
// (https://virustotal.readme.io/llms.txt — verified May 2026).
// Single source of truth: schemas/index.ts derives Zod enums from this.
export const RELATIONSHIPS = {
  url: [
    'analyses', 'collections', 'comments', 'communicating_files',
    'contacted_domains', 'contacted_ips', 'downloaded_files',
    'embedded_js_files', 'graphs', 'last_serving_ip_address',
    'network_location', 'referrer_files', 'referrer_urls',
    'redirecting_urls', 'redirects_to', 'related_comments',
    'related_references', 'related_threat_actors', 'submissions',
    'urls_related_by_tracker_id', 'user_votes', 'votes',
  ],
  file: [
    'analyses', 'behaviours', 'bundled_files', 'carbonblack_children',
    'carbonblack_parents', 'ciphered_bundled_files', 'ciphered_parents',
    'collections', 'comments', 'compressed_parents', 'contacted_domains',
    'contacted_ips', 'contacted_urls', 'dropped_files', 'email_attachments',
    'email_parents', 'embedded_domains', 'embedded_ips', 'embedded_urls',
    'execution_parents', 'graphs', 'itw_domains', 'itw_ips', 'itw_urls',
    'memory_pattern_domains', 'memory_pattern_ips', 'memory_pattern_urls',
    'overlay_children', 'overlay_parents', 'pcap_children', 'pcap_parents',
    'pe_resource_children', 'pe_resource_parents', 'related_references',
    'related_threat_actors', 'similar_files', 'submissions', 'screenshots',
    'urls_for_embedded_js', 'votes',
  ],
  ip: [
    'collections', 'comments', 'communicating_files', 'downloaded_files',
    'graphs', 'historical_ssl_certificates', 'historical_whois',
    'related_comments', 'related_references', 'related_threat_actors',
    'referrer_files', 'resolutions', 'urls', 'user_votes', 'votes',
  ],
  domain: [
    'caa_records', 'cname_records', 'collections', 'comments',
    'communicating_files', 'downloaded_files', 'graphs',
    'historical_ssl_certificates', 'historical_whois', 'immediate_parent',
    'mx_records', 'ns_records', 'parent', 'referrer_files',
    'related_comments', 'related_references', 'related_threat_actors',
    'resolutions', 'soa_records', 'siblings', 'subdomains', 'urls',
    'user_votes', 'votes',
  ],
  collection: [
    'autogenerated_graphs', 'comments', 'domains', 'files', 'ip_addresses',
    'owner', 'references', 'related_collections', 'related_references',
    'threat_actors', 'urls',
  ],
} as const;

// VT caps the relationships you can request in a single call; batch to be safe.
const RELATIONSHIPS_PER_REQUEST = 8;

// Fetch an object + a set of relationship summaries in as few calls as
// possible by using VT's `?relationships=a,b,c` query, batched.
export async function queryVirusTotalWithRelationships(
  baseEndpoint: string,
  relationships: readonly string[],
): Promise<any> {
  if (relationships.length === 0) {
    return queryVirusTotal(baseEndpoint);
  }

  const batches: string[][] = [];
  for (let i = 0; i < relationships.length; i += RELATIONSHIPS_PER_REQUEST) {
    batches.push([...relationships.slice(i, i + RELATIONSHIPS_PER_REQUEST)]);
  }

  const responses = await Promise.all(
    batches.map((batch) =>
      queryVirusTotal(baseEndpoint, 'get', undefined, {
        relationships: batch.join(','),
      }),
    ),
  );

  const base = responses[0];
  const mergedRelationships = responses.reduce<Record<string, any>>(
    (acc, r) => ({ ...acc, ...(r?.data?.relationships || {}) }),
    {},
  );

  return {
    ...base,
    data: {
      ...base.data,
      relationships: mergedRelationships,
    },
  };
}
