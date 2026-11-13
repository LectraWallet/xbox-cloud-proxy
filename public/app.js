// Xbox Cloud Gaming proxy client.
// Same Scramjet + Bare setup as the kmqv08 hub proxy, locked to one site,
// plus: host-scoped User-Agent alignment on the transport, and the
// OAuth PKCE split-IP sign-in handoff (login-fix modal).
const $ = (id) => document.getElementById(id);
const XBOX_URL = "https://www.xbox.com/en-US/play";
const statusEl = $("status");

function setStatus(t, err) {
  statusEl.style.display = "";
  statusEl.textContent = t;
  statusEl.className = err ? "err" : "";
}

const loadScript = (src) =>
  new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error("failed to load " + src));
    document.head.append(s);
  });

// Decode the real URL from a Scramjet rewritten src:
// /~/sj/<cid>/<fid>/<encoded>
function realUrl(rewritten) {
  try {
    const m = String(rewritten).match(/\/~\/sj\/[^/]+\/[^/]+\/(.+)/);
    return m ? decodeURIComponent(m[1]) : rewritten;
  } catch (e) {
    return rewritten;
  }
}

// ---- User-Agent handling ----
// The browser's REAL User-Agent is used on every host. An earlier build
// sent a desktop Edge UA to Xbox hosts for a quality boost, but the UA
// mismatch between the sign-in (real UA) and Xbox API calls (Edge UA)
// broke the session and caused a black-screen reload loop after login.
// Consistency beats the boost; the stream may top out at 720p.
function alignHeaders(remote, headers) {
  const pairs = Array.isArray(headers) ? headers.slice() : [];
  const hasUA = pairs.some(([k]) => String(k).toLowerCase() === "user-agent");
  if (!hasUA) pairs.push(["user-agent", navigator.userAgent]);
  return pairs;
}
function wrapTransport(bare) {
  const origRequest = bare.request.bind(bare);
  bare.request = (remote, method, body, headers, signal) =>
    origRequest(remote, method, body, alignHeaders(remote, headers), signal);
  if (typeof bare.connect === "function") {
    const origConnect = bare.connect.bind(bare);
    bare.connect = (url, protocols, requestHeaders, ...rest) =>
      origConnect(
        url,
        protocols,
        alignHeaders(url, requestHeaders || []),
        ...rest
      );
  }
  return bare;
}

// ---- Frame + URL watcher ----
let controller = null;
let frame = null;
let iframe = null;
let lastRealUrl = "";
let capturedAuthUrl = "";

function inspectFrameUrl() {
  if (!iframe) return;
  let raw = "";
  try {
    raw = iframe.contentWindow.location.href || "";
  } catch (e) {
    raw = "";
  }
  if (!raw || raw.startsWith("about:")) raw = iframe.src || "";
  const u = realUrl(raw);
  if (!u || u.startsWith("about:")) return;
  lastRealUrl = u;
  // Capture Microsoft OAuth authorize URLs (PKCE flow) for the handoff.
  try {
    const parsed = new URL(u);
    const host = parsed.hostname.toLowerCase();
    const isAuthHost =
      host === "login.live.com" ||
      host.endsWith(".login.live.com") ||
      host === "login.microsoftonline.com" ||
      host.endsWith(".login.microsoftonline.com");
    const isAuthorize =
      parsed.pathname.includes("oauth20_authorize") ||
      (parsed.pathname.includes("/oauth2/") &&
        parsed.pathname.includes("/authorize"));
    if (isAuthHost && isAuthorize && parsed.searchParams.get("client_id")) {
      if (capturedAuthUrl !== u) {
        capturedAuthUrl = u;
        updateAuthCaptureUI();
      }
    }
  } catch (e) {
    /* ignore unparseable urls */
  }
}

// ---- Login-fix modal ----
const modal = $("loginModal");
const loginFixBtn = $("loginFixBtn");
const openAuthBtn = $("openAuthBtn");
const authUrlInput = $("authUrlInput");
const callbackInput = $("callbackInput");
const callbackMsg = $("callbackMsg");
const capturedState = $("capturedState");

function updateAuthCaptureUI() {
  if (capturedAuthUrl) {
    capturedState.textContent = "Captured: " + capturedAuthUrl.slice(0, 120) + "…";
    capturedState.className = "captured";
    openAuthBtn.disabled = false;
    loginFixBtn.classList.add("ready");
    loginFixBtn.textContent = "🔑 Login Fix • link ready";
  } else {
    capturedState.textContent =
      "No sign-in link captured yet — tap Sign In in the Xbox page first.";
    capturedState.className = "captured none";
    openAuthBtn.disabled = !authUrlInput.value.trim();
  }
}

function authUrlFromInput() {
  const v = (authUrlInput.value || "").trim();
  if (!v) return "";
  try {
    const u = new URL(v);
    const host = u.hostname.toLowerCase();
    const okHost =
      host === "login.live.com" ||
      host.endsWith(".login.live.com") ||
      host === "login.microsoftonline.com" ||
      host.endsWith(".login.microsoftonline.com");
    if (!okHost) return "";
    return u.href;
  } catch (e) {
    return "";
  }
}

authUrlInput.addEventListener("input", updateAuthCaptureUI);
loginFixBtn.onclick = () => modal.classList.add("open");
$("closeModal").onclick = () => modal.classList.remove("open");
modal.addEventListener("click", (e) => {
  if (e.target === modal) modal.classList.remove("open");
});

openAuthBtn.onclick = () => {
  const url = capturedAuthUrl || authUrlFromInput();
  if (!url) {
    capturedState.textContent =
      "That doesn't look like a Microsoft sign-in link.";
    capturedState.className = "captured none";
    return;
  }
  window.open(url, "_blank", "noopener");
  setStatus("sign in on the real Microsoft tab, then paste its final address in step 2");
};

// Strictly validate an Xbox OAuth callback URL pasted by the user.
// Must be an official xbox.com /auth callback carrying a one-time code.
function parseStrictXboxOAuthCallback(input) {
  const u = new URL(String(input || "").trim());
  const host = u.hostname.toLowerCase();
  if (host !== "play.xbox.com" && host !== "www.xbox.com") return null;
  if (!u.pathname.includes("/auth")) return null;
  const frag = new URLSearchParams(u.hash.slice(1));
  const code = frag.get("code");
  const state = frag.get("state");
  if (!code || !state) return null;
  return u.href;
}

$("completeBtn").onclick = () => {
  callbackMsg.textContent = "";
  callbackMsg.className = "";
  let href = null;
  try {
    href = parseStrictXboxOAuthCallback(callbackInput.value);
  } catch (e) {
    href = null;
  }
  if (!href) {
    callbackMsg.textContent =
      "That URL isn't a valid Xbox sign-in callback. It should look like play.xbox.com/auth/msa#code=...&state=...";
    callbackMsg.className = "err";
    return;
  }
  if (!frame) {
    callbackMsg.textContent = "Proxy isn't ready yet — wait a few seconds and try again.";
    callbackMsg.className = "err";
    return;
  }
  callbackMsg.textContent = "Handing the sign-in back to the game page…";
  callbackMsg.className = "ok";
  frame.go(href);
  setStatus("completing sign-in inside Xbox…");
  setTimeout(() => modal.classList.remove("open"), 800);
};

// ---- Toolbar ----
$("reloadBtn").onclick = () => {
  if (frame) frame.go(lastRealUrl || XBOX_URL);
};
$("resetBtn").onclick = async () => {
  if (!confirm("Reset the proxy? This clears the saved sign-in and reloads.")) return;
  try {
    const regs = await navigator.serviceWorker.getRegistrations();
    await Promise.all(regs.map((r) => r.unregister()));
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => caches.delete(k)));
    localStorage.clear();
    sessionStorage.clear();
  } catch (e) {
    /* best effort */
  }
  location.reload();
};
$("fsBtn").onclick = () => {
  if (!iframe) return;
  if (document.fullscreenElement) document.exitFullscreen();
  else if (iframe.requestFullscreen) iframe.requestFullscreen();
  else if (iframe.webkitRequestFullscreen) iframe.webkitRequestFullscreen();
};

// ---- Init (same flow as the hub proxy) ----
async function init() {
  try {
    setStatus("registering worker...");
    const reg = await navigator.serviceWorker.register("/sw.js", {
      scope: "/",
      updateViaCache: "none",
    });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise((res) =>
        navigator.serviceWorker.addEventListener("controllerchange", res, {
          once: true,
        })
      );
    }
    const sw = navigator.serviceWorker.controller || reg.active;
    if (!sw) throw new Error("worker failed");

    setStatus("loading engine...");
    for (const src of [
      "/scram/scramjet.js",
      "/controller/controller.api.js",
      "/utils/scramjet-utils.js",
    ]) {
      await loadScript(src);
    }

    const { default: BareClient } = await import("/baremod/index.mjs");
    const transport = wrapTransport(
      new BareClient(new URL("/bare/", location.href))
    );

    setStatus("connecting...");
    const api = window.$scramjetController;
    controller = new api.Controller({
      serviceworker: sw,
      transport,
      config: {
        scramjetPath: "/scram/scramjet.js",
        wasmPath: "/scram/scramjet.wasm",
        injectPath: "/controller/controller.inject.js",
      },
    });
    await controller.wait();
    setInterval(
      () => navigator.serviceWorker.controller?.postMessage("keepalive"),
      15000
    );

    iframe = document.createElement("iframe");
    iframe.setAttribute(
      "allow",
      "fullscreen; autoplay; encrypted-media; gamepad; microphone; camera"
    );
    $("frames").appendChild(iframe);
    frame = controller.createFrame(iframe);
    iframe.addEventListener("load", inspectFrameUrl);
    setInterval(inspectFrameUrl, 500);

    setStatus("loading Xbox Cloud Gaming…");
    frame.go(XBOX_URL);
    statusEl.style.display = "none";
  } catch (e) {
    setStatus("failed: " + e.message, true);
  }
}

init();
