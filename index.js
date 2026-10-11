/**
 * dsh-cookie-sync — Sync cookies from Edge browser to DSH sidebar browser.
 *
 * Host-only plugin: registers loopback-guarded HTTP routes that let the DSH
 * web GUI fetch Edge's cookies for whitelisted domains. Cookie values are
 * decrypted in-process via Windows DPAPI and never logged or persisted.
 *
 * Cordis plugin contract: named exports `name`, `inject`, `apply`.
 */

import { copyFileSync, existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

// ── Edge cookie store location ──────────────────────────────────────

function defaultEdgeCookiePath() {
  const localAppData = process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local");
  const base = join(localAppData, "Microsoft", "Edge", "User Data", "Default");
  // Newer Edge/Chromium versions store cookies under Network\Cookies
  const networkCookies = join(base, "Network", "Cookies");
  if (existsSync(networkCookies)) return networkCookies;
  return join(base, "Cookies");
}

// ── loopback / same-origin guard ────────────────────────────────────

function isLoopbackAddress(address) {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function isTrustedRequest(req) {
  // Accept any request from loopback socket (127.0.0.1, ::1, etc.)
  // The DSH webserver only serves internal pages (web GUI + sidebar browser),
  // so loopback access is safe without extra origin checking.
  if (!isLoopbackAddress(req.socket?.remoteAddress)) return false;
  return true;
}

function writeJson(res, status, body) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}

// ── DPAPI decrypt ───────────────────────────────────────────────────

function decryptDpapi(encryptedBuffer) {
  return new Promise((resolvePromise, rejectPromise) => {
    const base64 = Buffer.from(encryptedBuffer).toString("base64");
    const psScript =
      "$b=[Convert]::FromBase64String('" + base64 + "');" +
      "$u=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);" +
      "[Console]::Out.Write([Text.Encoding]::UTF8.GetString($u))";
    const child = spawn("pwsh", ["-NoProfile", "-Command", psScript], {
      timeout: 10000,
      windowsHide: true,
    });
    const chunks = [];
    child.stdout.on("data", (d) => chunks.push(d));
    child.stderr.on("data", () => {});
    child.on("close", (code) => {
      if (code === 0 && chunks.length > 0) {
        resolvePromise(Buffer.concat(chunks).toString("utf-8"));
      } else {
        rejectPromise(new Error("DPAPI decrypt failed (exit " + code + ")"));
      }
    });
    child.on("error", rejectPromise);
  });
}

// ── cookie extraction from Edge SQLite ───────────────────────────────

// ── locked-file snapshot ─────────────────────────────────────────────
//
// Edge holds its cookie database with FILE_SHARE_NONE while running, so neither
// copyFileSync nor DatabaseSync(readOnly) can touch it (EBUSY / "unable to open
// database file"). Windows allows a handle to be opened with an explicit share
// mask, and Chromium relaxes that mask when a browser is shutting down, so try
// increasingly permissive readers: Node's fs, then a pwsh FileShare.ReadWrite
// copy, then a plain copy. Whatever wins, we read a throwaway snapshot which is
// deleted in the caller's finally block, so no cookie data lands on disk.
function snapshotViaPwsh(src, dest) {
  return new Promise((resolvePromise, rejectPromise) => {
    const ps =
      "$ErrorActionPreference='Stop';" +
      "$s=[IO.File]::Open(" + psQuote(src) + ",[IO.FileMode]::Open,[IO.FileAccess]::Read," +
      "[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete);" +
      "try{$d=[IO.File]::Create(" + psQuote(dest) + ");" +
      "try{$b=New-Object byte[] 1048576;" +
      "while(($n=$s.Read($b,0,$b.Length)) -gt 0){$d.Write($b,0,$n)}}finally{$d.Close()}}finally{$s.Close()}";
    const child = spawn("pwsh", ["-NoProfile", "-NonInteractive", "-Command", ps], {
      timeout: 20000,
      windowsHide: true,
    });
    const err = [];
    let settled = false;
    child.stdout.on("data", () => {});
    child.stderr.on("data", (d) => err.push(d));
    child.on("close", (code) => {
      settled = true;
      if (code === 0) resolvePromise(true);
      else rejectPromise(new Error(Buffer.concat(err).toString().trim() || "pwsh copy failed"));
    });
    // a late 'error' after 'close' must not re-reject an already-settled promise
    child.on("error", (e) => {
      if (settled) return;
      settled = true;
      rejectPromise(e);
    });
  });
}

function psQuote(value) {
  return "'" + String(value).replace(/'/g, "''") + "'";
}

async function snapshotLockedFile(src, dest) {
  try {
    copyFileSync(src, dest);
    return statSync(dest).size;
  } catch {
    /* Edge locks the file; fall through to the more permissive readers */
  }
  try {
    await snapshotViaPwsh(src, dest);
    return statSync(dest).size;
  } catch {
    /* still locked; fall through to the last resort below */
  }
  try {
    copyFileSync(src, dest);
    return statSync(dest).size;
  } catch (err) {
    const e = new Error(
      "Edge is running and holds an exclusive lock on its cookie database. " +
        "Quit Edge (or its background processes) and retry, or set edgeCookiePath " +
        "to a browser profile that is not currently open. Underlying error: " +
        (err?.message ?? err)
    );
    e.code = "EDGE_DB_LOCKED";
    throw e;
  }
}

async function readEdgeCookiesForHost(cookieDbPath, host) {
  if (!existsSync(cookieDbPath)) {
    throw new Error("Edge cookie database not found at: " + cookieDbPath);
  }
  let DatabaseSync;
  try {
    ({ DatabaseSync } = await import("node:sqlite"));
  } catch {
    throw new Error("node:sqlite is not available; this plugin requires Node 22+");
  }

  // Snapshot the live cookie store (and any WAL sidecar) into a temp dir so
  // SQLite never touches the file Edge has locked. The snapshot is deleted in
  // the finally block, so no cookie data is ever left on disk.
  const snapshotDir = mkdtempSync(join(tmpdir(), "cookie-sync-"));
  const snapshotPath = join(snapshotDir, "Cookies");
  try {
    await snapshotLockedFile(cookieDbPath, snapshotPath);
    // WAL may hold rows not yet checkpointed into the main file.
    const walPath = cookieDbPath + "-wal";
    if (existsSync(walPath)) {
      try {
        await snapshotLockedFile(walPath, snapshotPath + "-wal");
      } catch {
        /* checkpointed already; the main snapshot is sufficient */
      }
    }
  } catch (err) {
    rmSync(snapshotDir, { recursive: true, force: true });
    if (err?.code === "EDGE_DB_LOCKED") throw err; // keep the classification
    const e = new Error("failed to snapshot Edge cookie database: " + (err?.message ?? err));
    e.code = "SNAPSHOT_FAILED";
    throw e;
  }

  let db;
  try {
    db = new DatabaseSync(snapshotPath, { readOnly: true });
  } catch (err) {
    rmSync(snapshotDir, { recursive: true, force: true });
    // SQLite cannot open even the snapshot (antivirus/indexer holding it, or a
    // truncated copy from a browser writing mid-read). Classify as a lock so
    // the route reports "retry later" rather than a hard failure.
    const e = new Error(
      "cookie snapshot could not be opened (file busy or incomplete); retry once Edge finishes writing. " +
        "Underlying error: " + (err?.message ?? err)
    );
    e.code = "EDGE_DB_LOCKED";
    throw e;
  }
  try {
    // Two 64-bit columns break node:sqlite's JS number conversion:
    //  - encrypted_value is a BLOB that can exceed Number.MAX_SAFE_INTEGER
    //  - expires_utc is a microsecond timestamp in the same range
    // Read both as text in SQL and convert explicitly.
    const rows = db
      .prepare(
        "SELECT host_key, name, value, " +
          "hex(encrypted_value) AS enc_hex, length(encrypted_value) AS enc_len, " +
          "path, CAST(expires_utc AS TEXT) AS expires_text, is_secure, is_httponly " +
          "FROM cookies WHERE host_key = ? OR host_key LIKE ?"
      )
      .all(host, "%." + host);
    const cookies = [];
    let locked = 0;
    for (const row of rows) {
      let value = row.value || "";
      if (!value && row.enc_hex && row.enc_len > 0) {
        try {
          value = await decryptDpapi(Buffer.from(row.enc_hex, "hex"));
        } catch {
          // Chromium 127+ stores cookies with app-bound encryption: the
          // ciphertext is bound to the Edge binary and Windows DPAPI refuses it
          // for every other process. That is a browser security boundary we
          // cannot and must not circumvent.
          locked++;
          continue;
        }
      }
      if (!value) continue;
      const expiresUtc = Number(row.expires_text ?? 0);
      cookies.push({
        domain: row.host_key,
        name: row.name,
        value,
        path: row.path || "/",
        secure: !!row.is_secure,
        httpOnly: !!row.is_httponly,
        expirationDate:
          Number.isFinite(expiresUtc) && expiresUtc > 0
            ? Math.floor(expiresUtc / 1000000 - 11644473600)
            : Math.floor(Date.now() / 1000) + 3600,
      });
    }
    if (cookies.length === 0 && locked > 0) {
      const e = new Error(
        "All " + locked + " matching cookies are protected by Chromium app-bound encryption " +
          "(Edge 127+). Their values can only be decrypted by Edge itself, so external " +
          "processes cannot read them. Use the plugin with a browser/profile that stores " +
          "unencrypted cookies, or sign in to the target site inside the DSH sidebar."
      );
      e.code = "APP_BOUND_ENCRYPTION";
      throw e;
    }
    return cookies;
  } finally {
    db.close();
    // never leave decrypted-adjacent copies of the cookie store on disk
    rmSync(snapshotDir, { recursive: true, force: true });
  }
}

// ── plugin contract ──────────────────────────────────────────────────

export const name = "dsh-cookie-sync";

/** Only webServer gates this fiber; everything else is optional. */
export const inject = ["webServer"];

export function apply(ctx, config = {}) {
  const logger = ctx.logger || console;

  const edgeCookiePath = config.edgeCookiePath || defaultEdgeCookiePath();
  const autoSyncDomains = config.autoSyncDomains || [
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
  ];
  const maxCookiesPerDomain = config.maxCookiesPerDomain ?? 50;

  const domainAllowed = (host) =>
    typeof host === "string" &&
    host.length > 0 &&
    autoSyncDomains.some((d) => host === d || host.endsWith("." + d));

  const cookiesHandler = async (req, res) => {
    if (!isTrustedRequest(req)) {
      writeJson(res, 403, { error: "forbidden" });
      return;
    }
    let host = "";
    try {
      host = new URL(req.url, "http://dsh.local").searchParams.get("host") || "";
    } catch {
      /* leave empty */
    }
    if (!host) {
      writeJson(res, 400, { error: "host parameter is required" });
      return;
    }
    if (!domainAllowed(host)) {
      writeJson(res, 200, { cookies: [], synced: false, reason: "domain not in auto-sync list" });
      return;
    }
    try {
      const cookies = await readEdgeCookiesForHost(edgeCookiePath, host);
      const limited = cookies.slice(0, maxCookiesPerDomain);
      writeJson(res, 200, { cookies: limited, synced: true, count: limited.length });
    } catch (err) {
      // A running Edge locks its cookie store with FILE_SHARE_NONE. That is a
      // browser security boundary, not a plugin fault, so report it as a normal
      // "nothing to sync yet" outcome instead of a server error.
      if (err?.code === "EDGE_DB_LOCKED") {
        writeJson(res, 200, {
          cookies: [],
          synced: false,
          code: "EDGE_DB_LOCKED",
          reason: "Edge is running; quit Edge to allow cookie sync.",
        });
        return;
      }
      if (err?.code === "APP_BOUND_ENCRYPTION") {
        writeJson(res, 200, {
          cookies: [],
          synced: false,
          code: "APP_BOUND_ENCRYPTION",
          reason: err.message,
        });
        return;
      }
      writeJson(res, 500, { error: err?.message ?? String(err), synced: false });
    }
  };

  const scriptHandler = async (req, res) => {
    if (!isTrustedRequest(req)) {
      res.writeHead(403, { "content-type": "text/plain" });
      res.end("forbidden");
      return;
    }
    res.writeHead(200, { "content-type": "application/javascript; charset=utf-8" });
    res.end(
      "(function(){" +
        "if(window.__cookieSyncInjected)return;window.__cookieSyncInjected=true;" +
        "async function sync(){try{" +
        "const r=await fetch('/api/cookie-sync/cookies?host='+encodeURIComponent(location.hostname));" +
        "const d=await r.json();if(!d.synced||!d.cookies||!d.cookies.length)return;" +
        "for(const c of d.cookies){if(c.httpOnly)continue;" +
        "const p=[c.name+'='+encodeURIComponent(c.value),'path='+(c.path||'/'),'domain='+c.domain.replace(/^\\./,'')];" +
        "if(c.expirationDate)p.push('expires='+new Date(c.expirationDate*1000).toUTCString());" +
        "if(c.secure)p.push('secure');" +
        "document.cookie=p.join('; ');}" +
        "console.info('dsh-cookie-sync: applied',d.cookies.length,'cookie(s) from Edge');" +
        "}catch(e){console.warn('dsh-cookie-sync: sync failed',e)}}" +
        "if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',sync);}else{sync();}" +
        "})();"
    );
  };

  const disposers = [];
  disposers.push(
    ctx.webServer.register({ kind: "exact", path: "/api/cookie-sync/cookies", handler: cookiesHandler })
  );
  disposers.push(
    ctx.webServer.register({ kind: "exact", path: "/api/cookie-sync/inject.js", handler: scriptHandler })
  );
  ctx.effect(() => () => {
    for (const dispose of disposers) {
      try {
        dispose();
      } catch {}
    }
  });

  logger.info?.("dsh-cookie-sync: activated. Edge cookie store: " + edgeCookiePath);
}
