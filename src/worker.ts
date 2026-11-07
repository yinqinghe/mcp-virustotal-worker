import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { initVirusTotalClient, getKeyPool, RELATIONSHIPS } from './utils/api.js';
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

// Global in-memory map for active SSE sessions within the isolate
const sseSessions = new Map<string, WritableStreamDefaultWriter<Uint8Array>>();

// Tool definitions for MCP tools/list
function getToolsDefinition() {
  return [
    {
      name: 'get_url_report',
      description:
        'Get a comprehensive URL analysis report including security scan results and key relationships (communicating files, contacted domains/IPs, downloaded files, redirects, threat actors).',
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'The URL to analyze' },
        },
        required: ['url'],
      },
    },
    {
      name: 'get_url_relationship',
      description: 'Query a specific relationship type for a URL with pagination support.',
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'The URL to get relationships for' },
          relationship: { type: 'string', enum: RELATIONSHIPS.url, description: 'Type of relationship to query' },
          limit: { type: 'integer', minimum: 1, maximum: 40, default: 10, description: 'Number of items to return' },
          cursor: { type: 'string', description: 'Continuation cursor for pagination' },
        },
        required: ['url', 'relationship'],
      },
    },
    {
      name: 'get_file_report',
      description: 'Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256).',
      inputSchema: {
        type: 'object',
        properties: {
          hash: { type: 'string', description: 'MD5, SHA-1 or SHA-256 hash of the file' },
        },
        required: ['hash'],
      },
    },
    {
      name: 'get_file_relationship',
      description: 'Query a specific relationship type for a file with pagination support.',
      inputSchema: {
        type: 'object',
        properties: {
          hash: { type: 'string', description: 'MD5, SHA-1 or SHA-256 hash of the file' },
          relationship: { type: 'string', enum: RELATIONSHIPS.file, description: 'Type of relationship to query' },
          limit: { type: 'integer', minimum: 1, maximum: 40, default: 10, description: 'Number of items to return' },
          cursor: { type: 'string', description: 'Continuation cursor for pagination' },
        },
        required: ['hash', 'relationship'],
      },
    },
    {
      name: 'get_ip_report',
      description:
        'Get a comprehensive IP address analysis report including geolocation, reputation data, and key relationships.',
      inputSchema: {
        type: 'object',
        properties: {
          ip: { type: 'string', description: 'IP address to analyze' },
        },
        required: ['ip'],
      },
    },
    {
      name: 'get_ip_relationship',
      description: 'Query a specific relationship type for an IP address with pagination support.',
      inputSchema: {
        type: 'object',
        properties: {
          ip: { type: 'string', description: 'IP address to analyze' },
          relationship: { type: 'string', enum: RELATIONSHIPS.ip, description: 'Type of relationship to query' },
          limit: { type: 'integer', minimum: 1, maximum: 40, default: 10, description: 'Number of items to return' },
          cursor: { type: 'string', description: 'Continuation cursor for pagination' },
        },
        required: ['ip', 'relationship'],
      },
    },
    {
      name: 'get_domain_report',
      description:
        'Get a comprehensive domain analysis report including DNS records, WHOIS data, and key relationships.',
      inputSchema: {
        type: 'object',
        properties: {
          domain: { type: 'string', description: 'Domain name to analyze' },
          relationships: {
            type: 'array',
            items: { type: 'string', enum: RELATIONSHIPS.domain },
            description: 'Optional array of relationships to include in the report',
          },
        },
        required: ['domain'],
      },
    },
    {
      name: 'get_domain_relationship',
      description: 'Query a specific relationship type for a domain with pagination support.',
      inputSchema: {
        type: 'object',
        properties: {
          domain: { type: 'string', description: 'Domain name to analyze' },
          relationship: { type: 'string', enum: RELATIONSHIPS.domain, description: 'Type of relationship to query' },
          limit: { type: 'integer', minimum: 1, maximum: 40, default: 10, description: 'Number of items to return' },
          cursor: { type: 'string', description: 'Continuation cursor for pagination' },
        },
        required: ['domain', 'relationship'],
      },
    },
    {
      name: 'search_vt',
      description:
        'Search the VirusTotal corpus for files, URLs, domains, IPs, or comments matching a query.',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Search query' },
          limit: { type: 'integer', minimum: 1, maximum: 300, default: 20, description: 'Number of results to return' },
          cursor: { type: 'string', description: 'Continuation cursor for pagination' },
        },
        required: ['query'],
      },
    },
    {
      name: 'get_file_behaviour_summary',
      description: 'Get a consolidated sandbox behaviour summary for a file (MD5/SHA-1/SHA-256).',
      inputSchema: {
        type: 'object',
        properties: {
          hash: { type: 'string', description: 'MD5, SHA-1 or SHA-256 hash of the file' },
        },
        required: ['hash'],
      },
    },
    {
      name: 'get_collection',
      description: 'Retrieve a VirusTotal collection by ID.',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'Collection ID' },
          relationships: {
            type: 'array',
            items: { type: 'string', enum: RELATIONSHIPS.collection },
            description: 'Optional list of relationships to include',
          },
        },
        required: ['id'],
      },
    },
  ];
}

// Tool executor
async function executeVirusTotalTool(name: string, args: any): Promise<{ content: any[]; isError?: boolean }> {
  switch (name) {
    case 'get_url_report':
      return handleGetUrlReport(args);
    case 'get_url_relationship':
      return handleGetUrlRelationship(args);
    case 'get_file_report':
      return handleGetFileReport(args);
    case 'get_file_relationship':
      return handleGetFileRelationship(args);
    case 'get_ip_report':
      return handleGetIpReport(args);
    case 'get_ip_relationship':
      return handleGetIpRelationship(args);
    case 'get_domain_report':
      return handleGetDomainReport(args);
    case 'get_domain_relationship':
      return handleGetDomainRelationship(args);
    case 'search_vt':
      return handleSearch(args);
    case 'get_file_behaviour_summary':
      return handleGetFileBehaviourSummary(args);
    case 'get_collection':
      return handleGetCollection(args);
    default:
      return {
        content: [{ type: 'text', text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
}

// JSON-RPC Dispatcher
async function handleJsonRpc(rpcReq: any): Promise<any | null> {
  if (!rpcReq || typeof rpcReq !== 'object') {
    return {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Invalid Request' },
    };
  }

  const { id, method, params } = rpcReq;
  const isNotification = id === undefined || id === null;

  switch (method) {
    case 'initialize': {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
          },
          serverInfo: {
            name: 'virustotal-mcp-server',
            version: '1.0.25',
          },
        },
      };
    }

    case 'notifications/initialized':
    case 'initialized': {
      return isNotification ? null : { jsonrpc: '2.0', id, result: {} };
    }

    case 'ping': {
      return {
        jsonrpc: '2.0',
        id,
        result: {},
      };
    }

    case 'tools/list': {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          tools: getToolsDefinition(),
        },
      };
    }

    case 'tools/call': {
      const toolName = params?.name;
      const toolArgs = params?.arguments ?? {};
      try {
        const result = await executeVirusTotalTool(toolName, toolArgs);
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: result.content,
            isError: Boolean(result.isError),
          },
        };
      } catch (err: any) {
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: `Error executing tool ${toolName}: ${err.message || String(err)}`,
              },
            ],
            isError: true,
          },
        };
      }
    }

    default: {
      if (isNotification) return null;
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32601,
          message: `Method not found: ${method}`,
        },
      };
    }
  }
}

const app = new Hono<{ Bindings: Env }>();

// Global CORS headers
app.use(
  '*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'mcp-session-id', 'Last-Event-ID', 'mcp-protocol-version', 'Key'],
    exposeHeaders: ['mcp-session-id', 'mcp-protocol-version'],
  })
);

function getKeysFromEnv(env: Env): string | undefined {
  return env.VIRUSTOTAL_API_KEYS || env.VIRUSTOTAL_API_KEY;
}

// Ensure key pool is updated for every incoming request
app.use('*', async (c, next) => {
  const keys = getKeysFromEnv(c.env);
  if (keys) {
    try {
      initVirusTotalClient(keys);
    } catch {}
  }
  await next();
});

// Format MCP HTTP response respecting client Accept header
function formatMcpResponse(responseRpc: any, accept: string | null): Response {
  if (responseRpc === null) {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
      },
    });
  }
  if (accept && accept.includes('text/event-stream')) {
    const sseBody = `event: message\ndata: ${JSON.stringify(responseRpc)}\n\n`;
    return new Response(sseBody, {
      status: 200,
      headers: {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }
  return new Response(JSON.stringify(responseRpc, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

// SSE stream response creator with absolute callback URL
function createSseStreamResponse(c: any): Response {
  const keys = getKeyPool().getKeys();
  if (keys.length === 0) {
    return c.text('VIRUSTOTAL_API_KEYS (or VIRUSTOTAL_API_KEY) is not configured', 500);
  }

  const sessionId = crypto.randomUUID();
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();

  sseSessions.set(sessionId, writer);

  const url = new URL(c.req.url);
  const endpointUrl = `${url.origin}/message?sessionId=${sessionId}`;
  const initEvent = `event: endpoint\ndata: ${endpointUrl}\n\n`;
  writer.write(encoder.encode(initEvent));

  const keepAlive = setInterval(async () => {
    try {
      await writer.write(encoder.encode(': ping\n\n'));
    } catch {
      clearInterval(keepAlive);
      sseSessions.delete(sessionId);
    }
  }, 15000);

  c.req.raw.signal.addEventListener('abort', () => {
    clearInterval(keepAlive);
    sseSessions.delete(sessionId);
    try {
      writer.close();
    } catch {}
  });

  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'Mcp-Session-Id': sessionId,
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    },
  });
}

// JSON-RPC POST processor for Streamable HTTP / direct RPC
async function processRpcRequest(c: any): Promise<Response> {
  const keys = getKeyPool().getKeys();
  if (keys.length === 0) {
    return c.json(
      {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32000, message: 'VIRUSTOTAL_API_KEYS (or VIRUSTOTAL_API_KEY) is not configured' },
      },
      500
    );
  }

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error: Invalid JSON' },
      },
      400
    );
  }

  const acceptHeader = c.req.header('Accept') || '';

  if (Array.isArray(body)) {
    const responses = (await Promise.all(body.map((item) => handleJsonRpc(item)))).filter(Boolean);
    return c.json(responses);
  }

  const responseRpc = await handleJsonRpc(body);
  return formatMcpResponse(responseRpc, acceptHeader);
}

// --- Route 1: GET / and GET /health ---
app.get('/', (c) => {
  const acceptHeader = c.req.header('Accept') || '';
  // If client connects to / with EventSource, serve SSE stream directly!
  if (acceptHeader.includes('text/event-stream')) {
    return createSseStreamResponse(c);
  }

  const keys = getKeyPool().getKeys();
  const url = new URL(c.req.url);
  return c.json({
    name: 'virustotal-mcp-cf',
    version: '1.0.25',
    status: 'healthy',
    configuredKeysCount: keys.length,
    endpoints: {
      sse: `${url.origin}/sse`,
      message: `${url.origin}/message?sessionId=:sessionId`,
      mcp: `${url.origin}/mcp`,
    },
    tools: getToolsDefinition().map((t) => ({ name: t.name, description: t.description })),
  });
});

app.get('/health', (c) => {
  return c.json({ status: 'ok', keysCount: getKeyPool().getKeys().length });
});

// --- Route 2: GET /sse ---
app.get('/sse', (c) => {
  return createSseStreamResponse(c);
});

// --- Route 3: GET /mcp ---
app.get('/mcp', (c) => {
  const acceptHeader = c.req.header('Accept') || '';
  if (acceptHeader.includes('text/event-stream')) {
    return createSseStreamResponse(c);
  }
  return c.json({
    status: 'ready',
    description: 'Post JSON-RPC requests to this endpoint or connect with SSE',
  });
});

// --- Route 4: POST /message (SSE Message Endpoint) ---
app.post('/message', async (c) => {
  const sessionId = c.req.query('sessionId') || c.req.header('mcp-session-id');
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.text('Invalid JSON body', 400);
  }

  // Process RPC message
  const responseRpc = await handleJsonRpc(body);

  // If active SSE writer exists in this isolate, notify it
  if (sessionId && sseSessions.has(sessionId) && responseRpc) {
    const writer = sseSessions.get(sessionId)!;
    const encoder = new TextEncoder();
    try {
      const sseData = `event: message\ndata: ${JSON.stringify(responseRpc)}\n\n`;
      writer.write(encoder.encode(sseData));
    } catch {
      sseSessions.delete(sessionId);
    }
  }

  // Return response directly (Stateless fallback ensures NO 404 across isolates!)
  return formatMcpResponse(responseRpc, c.req.header('Accept') || '');
});

// --- Route 5: Streamable HTTP / Direct JSON-RPC POST endpoints ---
app.post('/mcp', async (c) => processRpcRequest(c));
app.post('/', async (c) => processRpcRequest(c));
app.post('/sse', async (c) => processRpcRequest(c));

export default app;
