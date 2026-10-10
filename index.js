/**
 * dsh-cookie-sync — Sync cookies from Edge browser to DSH sidebar browser.
 *
 * When the sidebar browser navigates to a supported domain, this plugin
 * reads the corresponding cookies from the Edge browser's cookie store
 * and injects them into the sidebar browser's cookie jar, so the user
 * does not need to log in again.
 *
 * Security:
 * - Cookies are read from Edge's local SQLite cookie database.
 * - Only cookies for whitelisted domains are synced.
 * - Cookie values are never logged or persisted to disk.
 * - The sync happens in-process; no network transmission.
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Edge cookie store location ──────────────────────────────────────

function defaultEdgeProfilePath() {
  const localAppData = process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local");
  const base = join(localAppData, "Microsoft", "Edge", "User Data", "Default");
  // Newer Edge versions store cookies in Network\Cookies
  const networkCookies = join(base, "Network", "Cookies");
  if (existsSync(networkCookies)) return networkCookies;
  // Fallback: older Edge versions
  return join(base, "Cookies");
}

// ── Cookie extraction from Edge SQLite ───────────────────────────────

/**
 * Read cookies for a given host from Edge's SQLite cookie database.
 * Uses a minimal SQLite reader — no external dependencies.
 *
 * Edge cookie database schema (simplified):
 *   cookies table: host_key, name, value, encrypted_value, path, expires_utc, ...
 *
 * Note: Edge encrypts cookie values with DPAPI on Windows.
 * We use the Windows DPAPI via a small native call to decrypt.
 */
async function readEdgeCookiesForHost(cookieDbPath, host) {
  if (!existsSync(cookieDbPath)) {
    throw new Error(`Edge cookie database not found at: ${cookieDbPath}`);
  }

  // Use the built-in node:sqlite if available (Node 22+)
  let DatabaseSync;
  try {
    ({ DatabaseSync } = await import("node:sqlite"));
  } catch {
    throw new Error("node:sqlite is not available. This plugin requires Node 22+.");
  }

  const db = new DatabaseSync(cookieDbPath, { readOnly: true });
  try {
    const rows = db.prepare(
      "SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies WHERE host_key = ? OR host_key LIKE ?"
    ).all(host, `%.${host}`);

    const cookies = [];
    for (const row of rows) {
      let value = row.value || "";
      if (!value && row.encrypted_value && row.encrypted_value.length > 0) {
        // Try DPAPI decrypt
        try {
          value = await decryptDpapi(row.encrypted_value);
        } catch {
          // Skip cookies we can't decrypt
          continue;
        }
      }
      if (!value) continue;

      cookies.push({
        domain: row.host_key,
        name: row.name,
        value,
        path: row.path || "/",
        secure: !!row.is_secure,
        httpOnly: !!row.is_httponly,
        // Convert Edge's Chrome timestamp (microseconds since 1601-01-01) to seconds
        expirationDate: row.expires_utc > 0
          ? Math.floor((row.expires_utc / 1000000) - 11644473600)
          : Math.floor(Date.now() / 1000) + 3600,
      });
    }
    return cookies;
  } finally {
    db.close();
  }
}

/**
 * Decrypt a DPAPI-encrypted buffer.
 * Uses a small PowerShell call to invoke Windows DPAPI.
 */
async function decryptDpapi(encryptedBuffer) {
  const { spawn } = await import("node:child_process");

  return new Promise((resolve, reject) => {
    const base64 = Buffer.from(encryptedBuffer).toString("base64");
    const psScript = `
      $bytes = [Convert]::FromBase64String("${base64}")
      $unprotected = [Security.Cryptography.ProtectedData]::Unprotect(
        $bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser
      )
      [Console]::Out.Write([Text.Encoding]::UTF8.GetString($unprotected))
    `;
    const child = spawn("pwsh", ["-NoProfile", "-Command", psScript], {
      timeout: 10000,
      windowsHide: true,
      encoding: "utf-8",
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => {
      if (code === 0 && stdout.trim()) {
        resolve(stdout.trim());
      } else {
        reject(new Error(`DPAPI decrypt failed: ${stderr || "exit code " + code}`));
      }
    });
    child.on("error", reject);
  });
}

// ── Domain matching ──────────────────────────────────────────────────

function domainMatches(cookieDomain, targetDomain) {
  // Remove leading dot
  const cd = cookieDomain.replace(/^\./, "");
  return cd === targetDomain || cd.endsWith(`.${targetDomain}`);
}

// ── Plugin entry ─────────────────────────────────────────────────────

const name = "dsh-cookie-sync";

function apply(ctx, config = {}) {
  const logger = ctx.logger || console;

  const edgeProfilePath = config.edgeProfilePath || defaultEdgeProfilePath();
  const autoSyncDomains = config.autoSyncDomains || [
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "localhost",
    "127.0.0.1",
  ];
  const syncOnNavigate = config.syncOnNavigate !== false;
  const maxCookiesPerDomain = config.maxCookiesPerDomain ?? 50;

  // Register a sidebar-right tool that the browser half can call
  ctx.declareTools([
    {
      name: "cookie_sync_status",
      description: "Check the cookie sync status: which domains have synced cookies and how many.",
      parameters: {
        type: "object",
        properties: {},
      },
      async execute() {
        return `Cookie sync plugin is active.
Edge cookie store: ${edgeProfilePath}
Auto-sync domains: ${autoSyncDomains.join(", ")}
Sync on navigate: ${syncOnNavigate}
Max cookies per domain: ${maxCookiesPerDomain}`;
      },
    },
  ]);

  // Register a route that the sidebar browser can call to request cookies
  if (ctx.webServer) {
    const handler = async (req, res) => {
      const url = new URL(req.url, "http://localhost");
      const host = url.searchParams.get("host") || "";

      if (!host) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "host parameter is required" }));
        return;
      }

      // Check if this host is in the auto-sync list
      const shouldSync = autoSyncDomains.some((d) =>
        domainMatches(host, d) || host === d || host.endsWith(`.${d}`)
      );

      if (!shouldSync) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ cookies: [], synced: false, reason: "domain not in auto-sync list" }));
        return;
      }

      try {
        const cookies = await readEdgeCookiesForHost(edgeProfilePath, host);
        const limited = cookies.slice(0, maxCookiesPerDomain);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ cookies: limited, synced: true, count: limited.length }));
      } catch (err) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: err.message, synced: false }));
      }
    };

    // Register the cookie sync endpoint
    const disposer = ctx.webServer.register({
      kind: "exact",
      path: "/api/cookie-sync/cookies",
      handler,
    });

    ctx.effect(() => () => {
      disposer();
    });

    logger.info?.(`${name}: cookie sync endpoint registered at /api/cookie-sync/cookies`);
  }

  // Inject a script into the sidebar browser that auto-syncs on navigation
  if (syncOnNavigate && ctx.webServer) {
    const scriptHandler = async (req, res) => {
      res.writeHead(200, { "content-type": "application/javascript" });
      res.end(`
(function() {
  if (window.__cookieSyncInjected) return;
  window.__cookieSyncInjected = true;

  const SYNC_API = '/api/cookie-sync/cookies';

  async function syncCookies(host) {
    try {
      const resp = await fetch(SYNC_API + '?host=' + encodeURIComponent(host), {
        credentials: 'include',
      });
      const data = await resp.json();
      if (!data.synced || !data.cookies || data.cookies.length === 0) return false;

      // Set each cookie via document.cookie (non-httponly ones)
      // For httponly cookies, we rely on the sidebar browser's fetch interceptor
      let setCount = 0;
      for (const c of data.cookies) {
        if (c.httpOnly) continue; // cannot set via JS
        const parts = [
          c.name + '=' + encodeURIComponent(c.value),
          'path=' + (c.path || '/'),
          'domain=' + c.domain,
        ];
        if (c.expirationDate) {
          parts.push('expires=' + new Date(c.expirationDate * 1000).toUTCString());
        }
        if (c.secure) parts.push('secure');
        document.cookie = parts.join('; ');
        setCount++;
      }

      // For httponly cookies, inject a fetch interceptor that adds them
      const httponlyCookies = data.cookies.filter(c => c.httpOnly);
      if (httponlyCookies.length > 0) {
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
          const [resource, options = {}] = args;
          const url = typeof resource === 'string' ? resource : resource.url;
          if (url && url.includes(location.hostname)) {
            const cookieStr = httponlyCookies
              .filter(c => location.hostname.endsWith(c.domain.replace(/^\\./, '')))
              .map(c => c.name + '=' + c.value)
              .join('; ');
            if (cookieStr) {
              options.headers = options.headers || {};
              if (options.headers instanceof Headers) {
                options.headers.set('Cookie', cookieStr);
              } else {
                options.headers['Cookie'] = cookieStr;
              }
            }
          }
          return originalFetch.apply(this, args);
        };
      }

      return setCount > 0 || httponlyCookies.length > 0;
    } catch (e) {
      // Silent fail — sync is best-effort
      return false;
    }
  }

  // Run on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => syncCookies(location.hostname));
  } else {
    syncCookies(location.hostname);
  }

  // Re-sync on navigation (SPA)
  const originalPushState = history.pushState;
  const originalReplaceState = history.replaceState;
  history.pushState = function(...args) {
    const result = originalPushState.apply(this, args);
    setTimeout(() => syncCookies(location.hostname), 100);
    return result;
  };
  history.replaceState = function(...args) {
    const result = originalReplaceState.apply(this, args);
    setTimeout(() => syncCookies(location.hostname), 100);
    return result;
  };
  window.addEventListener('popstate', () => {
    setTimeout(() => syncCookies(location.hostname), 100);
  });
})();
`);
    };

    const scriptDisposer = ctx.webServer.register({
      kind: "exact",
      path: "/api/cookie-sync/inject.js",
      handler: scriptHandler,
    });

    ctx.effect(() => () => {
      scriptDisposer();
    });

    logger.info?.(`${name}: auto-sync script endpoint registered at /api/cookie-sync/inject.js`);
  }

  logger.info?.(`${name}: plugin activated. Edge profile: ${edgeProfilePath}`);
}

export default apply;
