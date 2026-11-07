# VirusTotal MCP Worker

A Model Context Protocol (MCP) server providing access to VirusTotal's API for threat intelligence and security analysis. Supports deployment both as a local CLI / stdio MCP server and as a Cloudflare Worker (SSE / Streamable HTTP).

## Features

- **Direct IOC Lookups**:
  - `get_url_report`: Analyze URLs, scan status, and reputation.
  - `get_file_report`: Analyze files by hash (MD5, SHA-1, SHA-256).
  - `get_ip_report`: Geolocation, reputation, and resolutions for IP addresses.
  - `get_domain_report`: DNS records, WHOIS data, and security categorization.
- **Relationship Queries**:
  - `get_url_relationship`, `get_file_relationship`, `get_ip_relationship`, `get_domain_relationship`.
- **Sandbox & Threat Intelligence**:
  - `get_file_behaviour_summary`: Consolidated sandbox behavioral analysis (processes, registry, MITRE ATT&CK).
  - `get_collection`: Threat actors, malware families, campaigns, and curated IOC sets.
  - `search_vt`: Search VirusTotal corpus using VTI modifier syntax.
- **Multi-Key Support & Auto Fallback**:
  - Supports multiple API keys via `VIRUSTOTAL_API_KEYS` (comma/newline separated or JSON array).
  - **Round-Robin Polling**: Distributes queries sequentially across all available keys.
  - **Fault Tolerance**: If a key hits 429 rate limit or 401/403 auth error, it is placed on temporary cooldown and the request automatically retries with the next available key.

## Configuration

### Multi-Key Support (`VIRUSTOTAL_API_KEYS`)

You can configure multiple keys separated by commas, semicolons, or newlines:

#### 1. Cloudflare Workers (Production)
Set as a secret via Wrangler:
```bash
# 设置多 key（逗号分隔）
npx wrangler secret put VIRUSTOTAL_API_KEYS
# 输入: key1,key2,key3
```
Or for a single key:
```bash
npx wrangler secret put VIRUSTOTAL_API_KEY
```

#### 2. Local Development (.dev.vars)
Copy `.dev.vars.example` to `.dev.vars`:
```env
VIRUSTOTAL_API_KEYS=key1,key2,key3
# 或单个 key
VIRUSTOTAL_API_KEY=your_key_here
```

#### 3. Stdio / Local Run
```bash
export VIRUSTOTAL_API_KEYS=key1,key2,key3
# or
export VIRUSTOTAL_API_KEY=your_key_here
```

## Deployment

Deploy directly to Cloudflare Workers:
```bash
npm run deploy # or npx wrangler deploy
```

Run locally:
```bash
npm run dev # or npx wrangler dev
```

Typecheck:
```bash
npm run typecheck
```

## License

MIT
