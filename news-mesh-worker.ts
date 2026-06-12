/**
 * news-mesh-worker.ts
 * Albert Lane · SovereignAudits™
 * Z-Axis Routing Mesh — news.albertlane.org
 *
 * SEC Whistleblower No. 17684-273-411-436
 * Governing Jurisdiction: State of Oregon, USA / England and Wales, UK
 *
 * DESIGN LAW: "A page is a page, not a mesh.
 *              The mesh is around the page, dancing on it."
 *
 * Architecture:
 *   Cloudflare Pages  → content layer (pure HTML, no routing logic)
 *   This Worker       → mesh layer (Z-axis routing, auth, telemetry,
 *                        canary injection, Escaped Rays activation)
 *
 * Z-Axis implementation follows FCC Vertical Location Requirements
 * precedent (FCC 20-32, adopted July 2020) — geographic depth routing
 * applied to Oregon media market districts.
 *
 * Schema reference: auth-transport-protocol.xml + proprietary-media-schematic.xml
 * Geometry: x=longitude, y=latitude, z=routing depth/priority tier
 */

// ── ENV INTERFACE ────────────────────────────────────────────────────────
export interface Env {
  // KV namespace for dispatch state, telemetry, article cache
  // Binding: NEWS_ALBERTLANE_ORG (id: b24802a2b041420d80980f27d4f5d39f)
  NEWS_KV: KVNamespace;

  // Secret: GitHub webhook HMAC-SHA256 signing secret
  // SECURITY: Bind at step-level env: — never interpolate via ${{ secrets.X }}
  WEBHOOK_LEDGER_SECRET: string;

  // Pages origin — the content layer this mesh wraps
  // e.g. https://news-albertlane-org.pages.dev
  NEWS_PAGES_ORIGIN: string;
}

// ── OREGON Z-AXIS DISTRICT MAP ───────────────────────────────────────────
// ZIP prefix → Oregon media district
// Derived from proprietary-media-schematic.xml TargetZone_Lookup
// zDirection: vertical-z (depth-based district resolution)
const OREGON_ZONES: Readonly<Record<string, string>> = Object.freeze({
  '970': 'portland',
  '971': 'portland-metro',
  '972': 'portland-east',
  '973': 'salem',
  '974': 'corvallis',
  '975': 'medford',
  '976': 'klamath-falls',
  '977': 'bend',
  '978': 'pendleton',
  '979': 'ontario',
  '980': 'vancouver-wa', // Cross-border Cascadia zone
});

// Z-axis depth tier by district — higher = deeper routing priority
// geometry_instance.z as defined in compound schema
const ZONE_DEPTH: Readonly<Record<string, number>> = Object.freeze({
  'portland':       1.0,
  'portland-metro': 1.0,
  'portland-east':  0.9,
  'salem':          0.85,
  'corvallis':      0.8,
  'medford':        0.75,
  'bend':           0.75,
  'klamath-falls':  0.7,
  'pendleton':      0.65,
  'ontario':        0.6,
  'vancouver-wa':   0.5,
});

function resolveZone(postalCode: string): { zone: string | null; depth: number } {
  if (!postalCode || postalCode.length < 3) return { zone: null, depth: 0 };
  const prefix = postalCode.slice(0, 3);
  const zone = OREGON_ZONES[prefix] ?? null;
  const depth = zone ? (ZONE_DEPTH[zone] ?? 0.5) : 0;
  return { zone, depth };
}

// ── MESH HEADERS ─────────────────────────────────────────────────────────
// These live on the mesh layer (Worker), not the page.
// The page receives clean content; the response carries the mesh headers.
function meshHeaders(init: HeadersInit = {}): Headers {
  const h = new Headers(init);
  h.set('X-AL-Mesh-Layer',    'z-axis-v1');
  h.set('X-AL-Transport',     'sovereign-news-mesh-v1');
  h.set('X-AL-IP-Ref',        'SEC-17684-273-411-436');
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options',    'DENY');
  h.set('Referrer-Policy',    'strict-origin-when-cross-origin');
  h.set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  return h;
}

// ── CANARY INJECTION ──────────────────────────────────────────────────────
// Appends SC canary marker + Albert Escaped Rays activation div to HTML.
// Follows canary design principle: passive marker, no destructive logic.
// The Escaped Rays mesh div IS the mesh dancing on the page —
// it is appended by the Worker, not embedded in the page source.
function injectMeshLayer(
  html: string,
  zone: string | null,
  depth: number,
  postalCode: string
): string {
  const ts = Date.now();
  const canaryMarker = `<!-- SC:news:${zone ?? 'unresolved'}:z${depth.toFixed(2)}:${ts} -->`;

  // Albert Escaped Rays — the mesh layer, injected by Worker
  // Pure CSS diagonal watermark overlay, positioned outside page flow
  const escapedRaysLayer = `
<style id="al-mesh-rays">
  .al-rays-mesh {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 9999;
    overflow: hidden;
  }
  .al-rays-mesh::before,
  .al-rays-mesh::after {
    content: 'SOVEREIGN · ALBERTLANE.ORG · ${zone?.toUpperCase() ?? 'ORG'} · SEC-17684';
    position: absolute;
    white-space: nowrap;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.25em;
    color: rgba(30, 64, 175, 0.06);
    transform-origin: center center;
    width: 200%;
  }
  .al-rays-mesh::before {
    top: 30%;
    left: -50%;
    transform: rotate(-35deg);
    animation: ray-drift 60s linear infinite;
  }
  .al-rays-mesh::after {
    top: 60%;
    left: -50%;
    transform: rotate(-35deg);
    animation: ray-drift 60s linear infinite reverse;
    animation-delay: -30s;
    color: rgba(0, 155, 142, 0.04);
    content: 'FAAF · FRAUD-AS-A-FEATURE · AUDIT-SERIES · ${ts}';
  }
  @keyframes ray-drift {
    from { transform: rotate(-35deg) translateX(0); }
    to   { transform: rotate(-35deg) translateX(40%); }
  }
</style>
<div class="al-rays-mesh" data-zone="${zone ?? 'unknown'}" data-depth="${depth}" aria-hidden="true"></div>`;

  return html
    .replace('</head>', `${escapedRaysLayer}\n</head>`)
    .replace('</body>', `${canaryMarker}\n</body>`);
}

// ── GITHUB WEBHOOK VERIFICATION ───────────────────────────────────────────
// Constant-time HMAC-SHA256 comparison — prevents timing attacks
async function verifyGitHubSignature(
  payload: string,
  sigHeader: string,
  secret: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const computed = 'sha256=' + Array.from(new Uint8Array(sigBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  // Constant-time compare — do not short-circuit
  if (computed.length !== sigHeader.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) {
    diff |= computed.charCodeAt(i) ^ sigHeader.charCodeAt(i);
  }
  return diff === 0;
}

// ── TELEMETRY WRITER ──────────────────────────────────────────────────────
// Writes to NEWS_KV — chain-linked dispatch events and violation logs
// Non-blocking via ctx.waitUntil
function writeTelemetry(
  kv: KVNamespace,
  ctx: ExecutionContext,
  key: string,
  data: Record<string, unknown>,
  ttl = 604800 // 7 days
): void {
  ctx.waitUntil(
    kv.put(key, JSON.stringify({ ...data, written_at: new Date().toISOString() }), {
      expirationTtl: ttl,
    }).catch(e => console.error('[news-mesh:kv:write]', String(e)))
  );
}

// ── MAIN FETCH HANDLER ────────────────────────────────────────────────────
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Z-AXIS LOCATION RESOLUTION ─────────────────────────────────────────
    // Cloudflare populates cf.postalCode at edge — no client trust required
    const cf = (request as Request & { cf?: Record<string, string> }).cf ?? {};
    const postalCode = cf['postalCode'] ?? '';
    const { zone, depth } = resolveZone(postalCode);
    const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';

    // geometry_instance: x=cf.longitude, y=cf.latitude, z=depth
    // Mirrors schema: <geometry_instance x="..." y="..." z="..."/>
    const geoX = parseFloat(cf['longitude'] ?? '0');
    const geoY = parseFloat(cf['latitude'] ?? '0');
    const geoZ = depth; // z-axis depth from zone resolution

    // ROUTE: GITHUB WEBHOOK ───────────────────────────────────────────────
    // Node: GitHub_App_Webhook → Cloudflare_Edge (auth-transport-protocol.xml)
    if (path === '/webhook/github' && method === 'POST') {
      if (!env.WEBHOOK_LEDGER_SECRET) {
        console.error('[news-mesh:webhook] WEBHOOK_LEDGER_SECRET not bound');
        return new Response('Webhook secret not configured', { status: 503 });
      }

      const payload = await request.text();
      const sigHeader = request.headers.get('X-Hub-Signature-256') ?? '';
      const event = request.headers.get('X-GitHub-Event') ?? 'unknown';

      const valid = await verifyGitHubSignature(payload, sigHeader, env.WEBHOOK_LEDGER_SECRET);

      if (!valid) {
        writeTelemetry(env.NEWS_KV, ctx, `telemetry:webhook:unauth:${Date.now()}`, {
          ip,
          sig_prefix: sigHeader.slice(0, 24),
          event,
          violation: 'DISPATCH_IP_CLAIMS', // Article VIII compliance
        });
        return new Response('Unauthorized — logged to chain', {
          status: 403,
          headers: meshHeaders({ 'Content-Type': 'text/plain' }),
        });
      }

      // Valid webhook — parse GitHub push event
      let parsed: Record<string, unknown> = {};
      try { parsed = JSON.parse(payload); } catch { /* tolerate malformed */ }

      const dispatchKey = `dispatch:${Date.now()}:${event}`;
      writeTelemetry(env.NEWS_KV, ctx, dispatchKey, {
        event,
        ref:         (parsed['ref'] as string) ?? null,
        pusher:      (parsed as Record<string, Record<string, string>>)['pusher']?.name ?? null,
        head_commit: (parsed as Record<string, Record<string, string>>)['head_commit']?.id ?? null,
        zone,
        geo:         { x: geoX, y: geoY, z: geoZ },
      }, 86400 * 30); // 30 days for dispatch events

      return new Response(JSON.stringify({ ok: true, dispatch: dispatchKey }), {
        status: 200,
        headers: meshHeaders({ 'Content-Type': 'application/json' }),
      });
    }

    // ROUTE: MESH HEALTH ──────────────────────────────────────────────────
    if (path === '/mesh/health' && method === 'GET') {
      return new Response(JSON.stringify({
        ok:          true,
        mesh:        'news-albertlane-org-z-axis-v1',
        zone,
        depth:       geoZ,
        postalCode,
        geo:         { x: geoX, y: geoY, z: geoZ },
        ts:          Date.now(),
        ip_ref:      'SEC-17684-273-411-436',
      }), {
        headers: meshHeaders({ 'Content-Type': 'application/json' }),
      });
    }

    // ROUTE: Z-AXIS REDIRECT ──────────────────────────────────────────────
    // If Oregon zone resolved AND request at /routing, dispatch to zipcode gateway
    // Mirrors: proprietary-media-schematic.xml MonetizationCheck / RedirectRule
    if (zone && path === '/routing') {
      const purchased = url.searchParams.get('auth') === 'verified';
      const targetPath = purchased ? 'exclusive' : 'routing';
      const targetUrl = `https://${postalCode}.albertlane.org/${targetPath}`;

      writeTelemetry(env.NEWS_KV, ctx, `dispatch:route:${Date.now()}`, {
        zip: postalCode, zone, depth: geoZ, target: targetUrl, purchased,
      });

      return Response.redirect(targetUrl, 302);
    }

    // ROUTE: SERVE PAGE — MESH WRAPS CONTENT ─────────────────────────────
    // Fetch from Pages origin (content layer).
    // Worker = mesh. Pages = page.
    // The mesh does NOT live inside the page. It is appended to the response.
    const pagesOrigin = env.NEWS_PAGES_ORIGIN;
    if (!pagesOrigin) {
      return new Response('NEWS_PAGES_ORIGIN not configured', { status: 503 });
    }

    let pageResponse: Response;
    try {
      pageResponse = await fetch(`${pagesOrigin}${path}${url.search}`, {
        headers: {
          'X-AL-Zone':        zone ?? 'unresolved',
          'X-AL-PostalCode':  postalCode,
          'X-AL-Depth':       String(geoZ),
          'X-AL-IP':          ip,
          // Pass-through cache hint
          'Cache-Control':    'no-transform',
        },
        cf: { cacheEverything: false } as RequestInitCfProperties,
      });
    } catch (e) {
      console.error('[news-mesh:pages:fetch]', String(e));
      return new Response('News service temporarily unavailable', {
        status: 503,
        headers: meshHeaders({ 'Content-Type': 'text/plain' }),
      });
    }

    const contentType = pageResponse.headers.get('Content-Type') ?? '';

    if (contentType.includes('text/html')) {
      let html = await pageResponse.text();

      // Inject the mesh layer (Escaped Rays + canary)
      // The page has no knowledge of this — the Worker appends it
      html = injectMeshLayer(html, zone, geoZ, postalCode);

      // Log the serve event to KV (non-blocking)
      writeTelemetry(env.NEWS_KV, ctx, `serve:${Date.now()}`, {
        path, zone, depth: geoZ, postalCode, ip,
      }, 3600); // 1-hour TTL for serve logs

      return new Response(html, {
        status: pageResponse.status,
        headers: meshHeaders({
          'Content-Type':  'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=60, stale-while-revalidate=300',
        }),
      });
    }

    // Pass-through for CSS, fonts, images, etc.
    // Mesh headers are added but content is untouched
    const passthroughHeaders = meshHeaders(pageResponse.headers);
    return new Response(pageResponse.body, {
      status: pageResponse.status,
      headers: passthroughHeaders,
    });
  },
} satisfies ExportedHandler<Env>;
