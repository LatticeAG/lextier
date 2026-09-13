/**
 * Development/local HTTP server for the gateway. Production deploys run the
 * same Router inside the platform worker; this server exists for local runs,
 * the CLI smoke path, and tests.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { Router, type HttpReq } from "./router.ts";
import { toErrorBody } from "../core/errors.ts";

export function serve(router: Router, host: string, port: number): Promise<{ server: Server; port: number }> {
  const server = createServer((ireq: IncomingMessage, ires: ServerResponse) => {
    const chunks: Buffer[] = [];
    let size = 0;
    ireq.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 128 * 1024) { ireq.destroy(); return; }
      chunks.push(c);
    });
    ireq.on("end", async () => {
      const u = new URL(ireq.url ?? "/", `http://${host}:${port}`);
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(ireq.headers)) {
        if (typeof v === "string") headers[k.toLowerCase()] = v;
      }
      const req: HttpReq = {
        method: ireq.method ?? "GET",
        path: u.pathname,
        query: u.searchParams,
        headers,
        body: chunks.length ? Buffer.concat(chunks) : null,
      };
      let out;
      try {
        out = await router.handle(req);
      } catch (e) {
        const { status, body } = toErrorBody(e);
        out = { status, body, headers: { "content-type": "application/json" } };
      }
      ires.writeHead(out.status, out.headers);
      ires.end(JSON.stringify(out.body));
    });
    ireq.on("error", () => { try { ires.destroy(); } catch { } });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const addr = server.address();
      resolve({ server, port: typeof addr === "object" && addr ? addr.port : port });
    });
  });
}
