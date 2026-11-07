# VirusTotal MCP Worker

A Model Context Protocol (MCP) server providing access to VirusTotal's API for threat intelligence and security analysis. Supports deployment both as a local CLI / stdio MCP server and as a Cloudflare Worker (SSE / HTTP).

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

## Configuration

Set your VirusTotal API key:

### Cloudflare Worker
Add secret via Wrangler:
```bash
npx wrangler secret put VIRUSTOTAL_API_KEY
```

For local development:
Copy `.dev.vars.example` to `.dev.vars` and add your key:
```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

### Stdio / Local Run
```bash
export VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

## Deployment

Deploy to Cloudflare Workers:
```bash
npm run deploy # or npx wrangler deploy
```

## License

MIT
