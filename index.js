#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import https from "https";
import http from "http";
import tls from "tls";
import { URL } from "url";

const server = new Server(
  { name: "security-headers", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// ── HTTP helper ────────────────────────────────────────────────
function fetchUrl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === "https:" ? https : http;
    const req = mod.request(
      u,
      { method: options.method || "GET", headers: options.headers || {}, timeout: 10000, rejectUnauthorized: false },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf-8"),
          });
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")); });
    if (options.body) req.write(options.body);
    req.end();
  });
}

// ── SSL Certificate Check ──────────────────────────────────────
async function checkSSL(hostname) {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 10000 }, () => {
        const cert = socket.getPeerCertificate(true);
        const now = Date.now();
        const validFrom = new Date(cert.valid_from).getTime();
        const validTo = new Date(cert.valid_to).getTime();
        const daysLeft = Math.floor((validTo - now) / 86400000);
        const results = {
          subject: cert.subject?.CN || "N/A",
          issuer: cert.issuer?.CN || "N/A",
          issuerOrg: cert.issuer?.O || "N/A",
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysRemaining: daysLeft,
          expired: daysLeft < 0,
          expiringSoon: daysLeft >= 0 && daysLeft < 30,
          serialNumber: cert.serialNumber,
          fingerprint: cert.fingerprint,
          subjectAltName: cert.subjectaltname,
          bits: cert.bits || socket.getCipher()?.bits || 0,
        };
        socket.end();
        resolve(results);
      });
      socket.on("error", (e) => resolve({ error: e.message }));
      socket.on("timeout", () => { socket.destroy(); resolve({ error: "Connection timeout" }); });
    } catch (e) {
      resolve({ error: e.message });
    }
  });
}

// ── Security Headers Check ─────────────────────────────────────
const SECURITY_HEADERS = {
  "strict-transport-security": {
    name: "HTTP Strict Transport Security (HSTS)",
    severity: "high",
    description: "Forces HTTPS connections. Missing = MITM risk.",
    recommendation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
  },
  "content-security-policy": {
    name: "Content Security Policy (CSP)",
    severity: "high",
    description: "Prevents XSS and data injection attacks.",
    recommendation: "Add CSP header defining allowed script/style sources.",
  },
  "x-content-type-options": {
    name: "X-Content-Type-Options",
    severity: "medium",
    description: "Prevents MIME-type sniffing.",
    recommendation: "Add: X-Content-Type-Options: nosniff",
  },
  "x-frame-options": {
    name: "X-Frame-Options",
    severity: "medium",
    description: "Prevents clickjacking attacks.",
    recommendation: "Add: X-Frame-Options: DENY or SAMEORIGIN",
  },
  "x-xss-protection": {
    name: "X-XSS-Protection",
    severity: "low",
    description: "Legacy XSS filter for older browsers.",
    recommendation: "Add: X-XSS-Protection: 1; mode=block",
  },
  "referrer-policy": {
    name: "Referrer-Policy",
    severity: "low",
    description: "Controls referrer information leakage.",
    recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
  },
  "permissions-policy": {
    name: "Permissions-Policy",
    severity: "low",
    description: "Restricts browser features (camera, mic, etc.).",
    recommendation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
  },
  "cross-origin-opener-policy": {
    name: "Cross-Origin-Opener-Policy (COOP)",
    severity: "medium",
    description: "Prevents cross-origin attacks via window.opener.",
    recommendation: "Add: Cross-Origin-Opener-Policy: same-origin",
  },
  "cross-origin-resource-policy": {
    name: "Cross-Origin-Resource-Policy (CORP)",
    severity: "medium",
    description: "Restricts which origins can load resources.",
    recommendation: "Add: Cross-Origin-Resource-Policy: same-origin",
  },
  "cross-origin-embedder-policy": {
    name: "Cross-Origin-Embedder-Policy (COEP)",
    severity: "low",
    description: "Required for SharedArrayBuffer and high-precision timers.",
    recommendation: "Add: Cross-Origin-Embedder-Policy: require-corp",
  },
};

async function checkHeaders(url) {
  try {
    const res = await fetchUrl(url);
    const headers = res.headers;
    const results = [];
    const missing = [];
    const present = [];
    let score = 100;

    for (const [key, info] of Object.entries(SECURITY_HEADERS)) {
      const value = headers[key];
      if (value) {
        present.push({ header: key, value: Array.isArray(value) ? value.join(", ") : value, ...info });
      } else {
        missing.push({ header: key, ...info });
        if (info.severity === "high") score -= 20;
        else if (info.severity === "medium") score -= 10;
        else score -= 5;
      }
      results.push({ header: key, present: !!value, value: value || null, ...info });
    }

    // Check cookies
    const setCookie = headers["set-cookie"];
    const cookies = Array.isArray(setCookie) ? setCookie : (setCookie ? [setCookie] : []);
    const cookieAnalysis = cookies.map((c) => {
      const issues = [];
      if (!/secure/i.test(c)) issues.push("Missing Secure flag");
      if (!/httponly/i.test(c)) issues.push("Missing HttpOnly flag");
      if (!/samesite/i.test(c)) issues.push("Missing SameSite attribute");
      return { cookie: c.substring(0, 100) + (c.length > 100 ? "..." : ""), issues };
    });

    return {
      url,
      statusCode: res.status,
      score: Math.max(0, score),
      grade: score >= 90 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : score >= 30 ? "D" : "F",
      headersTotal: Object.keys(headers).length,
      securityHeaders: { present: present.length, missing: missing.length },
      details: results,
      cookies: cookieAnalysis,
      server: headers["server"] || "Not disclosed",
      poweredBy: headers["x-powered-by"] || "Not disclosed",
    };
  } catch (e) {
    return { error: e.message };
  }
}

// ── CORS Check ─────────────────────────────────────────────────
async function checkCORS(url, origin = "https://evil.example.com") {
  try {
    const res = await fetchUrl(url, {
      method: "OPTIONS",
      headers: { Origin: origin, "Access-Control-Request-Method": "GET" },
    });
    const h = res.headers;
    const allowOrigin = h["access-control-allow-origin"];
    const allowMethods = h["access-control-allow-methods"];
    const allowHeaders = h["access-control-allow-headers"];
    const allowCreds = h["access-control-allow-credentials"];
    const maxAge = h["access-control-max-age"];

    const issues = [];
    if (!allowOrigin) issues.push({ severity: "info", msg: "No CORS headers — cross-origin requests blocked" });
    else if (allowOrigin === "*") {
      if (allowCreds === "true") issues.push({ severity: "critical", msg: "ACAO: * with ACAC: true — credentials exposed to any origin" });
      else issues.push({ severity: "warning", msg: "ACAO: * — allows any origin (no credentials)" });
    } else if (allowOrigin === origin) {
      issues.push({ severity: "critical", msg: `ACAO reflects request origin — allows arbitrary origins` });
    }

    return {
      url,
      originTested: origin,
      allowOrigin: allowOrigin || "(not set)",
      allowMethods: allowMethods || "(not set)",
      allowHeaders: allowHeaders || "(not set)",
      allowCredentials: allowCreds || "(not set)",
      maxAge: maxAge || "(not set)",
      issues,
      verdict: issues.filter((i) => i.severity === "critical").length > 0
        ? "VULNERABLE" : issues.length === 0 ? "SECURE" : "REVIEW_NEEDED",
    };
  } catch (e) {
    return { error: e.message };
  }
}

// ── Tools ──────────────────────────────────────────────────────
const tools = [
  {
    name: "audit_security_headers",
    description: "Audit security headers of a website. Returns score (A-F), missing/present headers, cookie analysis, and recommendations.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Website URL to audit (e.g. https://example.com)" },
      },
      required: ["url"],
    },
  },
  {
    name: "check_ssl",
    description: "Check SSL/TLS certificate details: issuer, expiry, days remaining, cipher strength.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: { type: "string", description: "Hostname to check (e.g. example.com, without https://)" },
      },
      required: ["hostname"],
    },
  },
  {
    name: "check_cors",
    description: "Test CORS configuration for cross-origin vulnerabilities.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to test CORS on" },
        origin: { type: "string", description: "Origin to test with (default: https://evil.example.com)" },
      },
      required: ["url"],
    },
  },
  {
    name: "full_audit",
    description: "Complete security audit: SSL + headers + CORS in one call.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Full URL to audit (e.g. https://example.com)" },
      },
      required: ["url"],
    },
  },
];

// ── Handlers ───────────────────────────────────────────────────
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    let result;
    switch (name) {
      case "audit_security_headers": {
        result = await checkHeaders(args.url);
        break;
      }
      case "check_ssl": {
        result = await checkSSL(args.hostname);
        break;
      }
      case "check_cors": {
        result = await checkCORS(args.url, args.origin);
        break;
      }
      case "full_audit": {
        const url = args.url;
        const u = new URL(url);
        const [headers, ssl, cors] = await Promise.all([
          checkHeaders(url),
          checkSSL(u.hostname),
          checkCORS(url),
        ]);
        result = {
          url,
          timestamp: new Date().toISOString(),
          ssl,
          headers,
          cors,
          overallRisk: [
            ssl?.expired ? "CRITICAL: SSL expired" : ssl?.expiringSoon ? "WARNING: SSL expiring soon" : null,
            headers?.grade === "F" ? "CRITICAL: Security headers grade F" : headers?.grade === "D" ? "HIGH: Security headers grade D" : null,
            cors?.verdict === "VULNERABLE" ? "HIGH: CORS vulnerable" : null,
          ].filter(Boolean),
        };
        break;
      }
      default:
        return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    }
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (e) {
    return { content: [{ type: "text", text: JSON.stringify({ error: e.message }, null, 2) }], isError: true };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);

