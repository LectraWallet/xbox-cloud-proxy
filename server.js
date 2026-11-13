// Xbox Cloud Gaming proxy — Scramjet + Bare, locked to Xbox/Microsoft hosts.
// Same proven architecture as the kmqv08 hub proxy (server.js), minus the
// game-hub routes, plus: a PIN gate, an Xbox-only Bare allowlist, and
// host-scoped User-Agent alignment (done client-side in the transport
// wrapper, see public/app.js).
import http from "node:http";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import express from "express";
import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { createBareServer } from "@tomphttp/bare-server-node";
import ipaddr from "ipaddr.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const dirOf = (specifier) => path.dirname(require.resolve(specifier));

const app = express();
app.use(express.json({ limit: "4kb" }));

// ---- PIN gate ----
// PIN from env SITE_PIN, default "1234". The cookie is an HMAC of a fixed
// string keyed by the PIN, so any serverless instance can verify it with
// no shared state.
const PIN = process.env.SITE_PIN || "1234";
const gateToken = () =>
  crypto.createHmac("sha256", PIN).update("xcp-gate").digest("hex");
const authed = (req) => {
  const m = (req.headers.cookie || "").match(/(?:^|;\s*)xcp=([a-f0-9]{64})/);
  if (!m) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(m[1]), Buffer.from(gateToken()));
  } catch {
    return false;
  }
};

app.post("/api/auth", (req, res) => {
  const pin = String(req.body?.pin || "");
  let ok = false;
  try {
    ok =
      pin.length === PIN.length &&
      crypto.timingSafeEqual(Buffer.from(pin), Buffer.from(PIN));
  } catch {
    ok = false;
  }
  if (!ok) {
    res.status(401).json({ ok: false });
    return;
  }
  const secure = process.env.VERCEL ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `xcp=${gateToken()}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax${secure}`
  );
  res.json({ ok: true });
});

// Everything except the gate page + auth endpoint requires the cookie,
// so the Bare endpoint can't be used as an open proxy.
app.use((req, res, next) => {
  const p = req.path || "";
  if (p === "/gate.html" || p === "/api/auth" || p === "/favicon.ico") {
    next();
    return;
  }
  if (!authed(req)) {
    if (p === "/" || p === "/index.html") {
      res.redirect("/gate.html");
    } else {
      res.status(401).end("locked");
    }
    return;
  }
  next();
});

// Cross-origin isolation (SharedArrayBuffer): needed by Scramjet.
app.use((req, res, next) => {
  const p = req.path || "";
  if (
    p === "/" ||
    p === "/index.html" ||
    p === "/sw.js" ||
    p.startsWith("/scram/") ||
    p.startsWith("/controller/") ||
    p.startsWith("/utils/") ||
    p.startsWith("/baremod/") ||
    p.startsWith("/bare/")
  ) {
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  }
  next();
});

// Scramjet browser bundles
app.use("/scram/", express.static(scramjetPath));
app.use("/utils/", express.static(dirOf("@mercuryworkshop/scramjet-utils")));
app.use(
  "/controller/",
  express.static(dirOf("@mercuryworkshop/scramjet-controller"))
);
app.use("/baremod/", express.static(dirOf("@mercuryworkshop/bare-transport")));
// Static site (index.html, app.js, sw.js, gate.html)
app.use(express.static(path.join(__dirname, "public")));

// ---- Xbox-only Bare allowlist ----
// Xbox pages, Microsoft sign-in, Xbox Live services, and the CDNs Xbox
// pages pull assets from. Everything else is refused, keeping this proxy
// Xbox-only. (Game streaming itself is WebRTC direct from the browser;
// it never touches Bare, so TURN hosts don't need to be listed.)
const XBOX_SUFFIXES = [
  "xbox.com",
  "xboxlive.com",
  "xboxservices.com",
  "xboxab.com",
  "gamepass.com",
  "live.com",
  "microsoftonline.com",
  "microsoft.com",
  "msauth.net",
  "msftauth.net",
  "windows.net",
  "gfx.ms",
  "s-microsoft.com",
  "msecnd.net",
  "azureedge.net",
  "aspnetcdn.com",
];

const bareServer = createBareServer("/bare/", {
  connectionLimiter: {
    maxConnectionsPerIP: 2000,
    windowDuration: 60,
    blockDuration: 10,
  },
  filterRemote(url) {
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    if (ipaddr.isValid(hostname) && ipaddr.parse(hostname).range() !== "unicast") {
      throw new RangeError("Forbidden IP");
    }
    const host = hostname.toLowerCase();
    const ok = XBOX_SUFFIXES.some((s) => host === s || host.endsWith("." + s));
    if (!ok) throw new RangeError("Host not allowed (Xbox only)");
  },
});

const handleRequest = (req, res) => {
  if (bareServer.shouldRoute(req)) {
    // The Bare transport fetches with credentials:omit, so the gate cookie
    // never reaches /bare/ — gating it on the cookie would break ALL
    // proxied traffic. Instead: block requests referred from OTHER sites
    // (hotlinking), and rely on the Xbox-only host allowlist. The PIN gate
    // still guards the UI itself.
    const ref = req.headers.referer || req.headers.origin || "";
    if (ref) {
      try {
        const refHost = new URL(ref).host;
        if (refHost !== req.headers.host) {
          res.statusCode = 403;
          res.end("forbidden");
          return;
        }
      } catch {
        /* unparseable referer: allow, allowlist still applies */
      }
    }
    bareServer.routeRequest(req, res);
    return;
  }
  app(req, res);
};

export default handleRequest;

if (!process.env.VERCEL) {
  http.createServer(handleRequest).listen(process.env.PORT || 3000);
  console.log("xbox proxy listening on :" + (process.env.PORT || 3000));
}
