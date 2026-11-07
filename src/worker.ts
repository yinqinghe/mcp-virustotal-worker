import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { initVirusTotalClient, getKeyPool } from './utils/api.js';
import {
  GetUrlReportArgsSchema,
  GetUrlRelationshipArgsSchema,
  GetFileReportArgsSchema,
  GetFileRelationshipArgsSchema,
  GetFileBehaviourSummaryArgsSchema,
  GetIpReportArgsSchema,
  GetIpRelationshipArgsSchema,
  GetDomainReportArgsSchema,
  GetDomainRelationshipArgsSchema,
  SearchArgsSchema,
  GetCollectionArgsSchema,
} from './schemas/index.js';
import {
  handleGetUrlReport,
  handleGetUrlRelationship,
  handleGetFileReport,
  handleGetFileRelationship,
  handleGetFileBehaviourSummary,
  handleGetIpReport,
  handleGetIpRelationship,
  handleGetDomainReport,
  handleGetDomainRelationship,
  handleSearch,
  handleGetCollection,
} from './handlers/index.js';

type Env = {
  VIRUSTOTAL_API_KEY?: string;
  VIRUSTOTAL_API_KEYS?: string;
};

// Web Standards compatible SSE Server Transport
export class WebSSEServerTransport implements Transport {
  public sessionId: string;
  public onclose?: () => void;
  public onerror?: (error: Error) => void;
  public onmessage?: (message: JSONRPCMessage) => void;

  private controller?: ReadableStreamDefaultController<Uint8Array>;
  private encoder = new TextEncoder();

  constructor(private postEndpointUrl: string) {
    this.sessionId = crypto.randomUUID();
  }

  async start(): Promise<void> {}

  createStreamResponse(): Response {
    const self = this;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        self.controller = controller;
        const endpointWithSession = `${self.postEndpointUrl}?sessionId=${self.sessionId}`;
        const initData = `event: endpoint\ndata: ${endpointWithSession}\n\n`;
        controller.enqueue(self.encoder.encode(initData));
      },
      cancel() {
        self.controller = undefined;
        self.onclose?.();
      },
    });

    return new Response(stream, {
      status: 200,
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      },
    });
  }

  async send(message: JSONRPCMessage): Promise<void> {
    if (!this.controller) {
      throw new Error('SSE connection not active');
    }
    const data = `event: message\ndata: ${JSON.stringify(message)}\n\n`;
    this.controller.enqueue(this.encoder.encode(data));
  }

  async handlePostMessage(message: JSONRPCMessage): Promise<void> {
    if (this.onmessage) {
      this.onmessage(message);
    }
  }

  async close(): Promise<void> {
    if (this.controller) {
      try {
        this.controller.close();
      } catch {}
      this.controller = undefined;
    }
    this.onclose?.();
  }
}

const app = new Hono<{ Bindings: Env }>();

app.use('*', cors());

function getKeysFromEnv(env: Env): string | undefined {
  return env.VIRUSTOTAL_API_KEYS || env.VIRUSTOTAL_API_KEY;
}

app.use('*', async (c, next) => {
  const keys = getKeysFromEnv(c.env);
  if (keys) {
    initVirusTotalClient(keys);
  }
  await next();
});

const sseTransports = new Map<string, WebSSEServerTransport>();

function createMcpServer() {
  const server = new McpServer({
    name: 'virustotal-mcp-cf',
    version: '1.0.0',
  });

  server.tool(
    'get_url_report',
    'Get a comprehensive URL analysis report including security scan results and key relationships (communicating files, contacted domains/IPs, downloaded files, redirects, threat actors).',
    GetUrlReportArgsSchema.shape,
    async (args) => handleGetUrlReport(args as any)
  );

  server.tool(
    'get_url_relationship',
    'Query a specific relationship type for a URL with pagination support.',
    GetUrlRelationshipArgsSchema.shape,
    async (args) => handleGetUrlRelationship(args as any)
  );

  server.tool(
    'get_file_report',
    'Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256).',
    GetFileReportArgsSchema.shape,
    async (args) => handleGetFileReport(args as any)
  );

  server.tool(
    'get_file_relationship',
    'Query a specific relationship type for a file with pagination support.',
    GetFileRelationshipArgsSchema.shape,
    async (args) => handleGetFileRelationship(args as any)
  );

  server.tool(
    'get_ip_report',
    'Get a comprehensive IP address analysis report including geolocation, reputation data, and key relationships.',
    GetIpReportArgsSchema.shape,
    async (args) => handleGetIpReport(args as any)
  );

  server.tool(
    'get_ip_relationship',
    'Query a specific relationship type for an IP address with pagination support.',
    GetIpRelationshipArgsSchema.shape,
    async (args) => handleGetIpRelationship(args as any)
  );

  server.tool(
    'get_domain_report',
    'Get a comprehensive domain analysis report including DNS records, WHOIS data, and key relationships.',
    GetDomainReportArgsSchema.shape,
    async (args) => handleGetDomainReport(args as any)
  );

  server.tool(
    'get_domain_relationship',
    'Query a specific relationship type for a domain with pagination support.',
    GetDomainRelationshipArgsSchema.shape,
    async (args) => handleGetDomainRelationship(args as any)
  );

  server.tool(
    'search_vt',
    'Search the VirusTotal corpus for files, URLs, domains, IPs, or comments matching a query.',
    SearchArgsSchema.shape,
    async (args) => handleSearch(args as any)
  );

  server.tool(
    'get_file_behaviour_summary',
    'Get a consolidated sandbox behaviour summary for a file (MD5/SHA-1/SHA-256).',
    GetFileBehaviourSummaryArgsSchema.shape,
    async (args) => handleGetFileBehaviourSummary(args as any)
  );

  server.tool(
    'get_collection',
    'Retrieve a VirusTotal collection by ID.',
    GetCollectionArgsSchema.shape,
    async (args) => handleGetCollection(args as any)
  );

  return server;
}

// Info endpoint
app.get('/', (c) => {
  const keys = getKeyPool().getKeys();
  return c.json({
    name: 'virustotal-mcp-cf',
    status: 'running',
    configuredKeysCount: keys.length,
    endpoints: {
      sse: '/sse',
      message: '/message',
      mcp: '/mcp',
    },
  });
});

// SSE handshake endpoint
app.get('/sse', async (c) => {
  const keys = getKeysFromEnv(c.env);
  if (!keys) return c.text('VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEYS is not configured', 500);

  initVirusTotalClient(keys);

  const transport = new WebSSEServerTransport('/message');
  sseTransports.set(transport.sessionId, transport);
  transport.onclose = () => {
    sseTransports.delete(transport.sessionId);
  };

  const server = createMcpServer();
  await server.connect(transport);

  return transport.createStreamResponse();
});

// Message endpoint
app.post('/message', async (c) => {
  const sessionId = c.req.query('sessionId');
  if (!sessionId || !sseTransports.has(sessionId)) {
    return c.text('Session not found', 404);
  }

  const transport = sseTransports.get(sessionId)!;
  const message = await c.req.json();
  await transport.handlePostMessage(message);
  return c.text('Accepted', 202);
});

// Streamable HTTP endpoint (stateless for serverless worker environments)
app.all('/mcp', async (c) => {
  const keys = getKeysFromEnv(c.env);
  if (!keys) return c.text('VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEYS is not configured', 500);

  initVirusTotalClient(keys);

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  const server = createMcpServer();
  await server.connect(transport);
  return transport.handleRequest(c.req.raw);
});

export default app;
