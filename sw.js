// 서비스 워커: 비밀번호로 만든 키가 있으면 <경로>.enc 를 받아 복호화해서 원래 파일처럼 돌려준다.
// 키가 없으면 네트워크 그대로 (각 페이지 자리에는 비밀번호 입력 화면이 있다).
const ROOT = new URL("./", self.location).pathname;
const MIME = {
  html: "text/html; charset=utf-8", js: "text/javascript; charset=utf-8", mjs: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8", json: "application/json; charset=utf-8", svg: "image/svg+xml",
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp",
  woff2: "font/woff2", woff: "font/woff", md: "text/markdown; charset=utf-8", rsc: "text/x-component", txt: "text/plain; charset=utf-8",
};
const PLAIN = new Set(["sw.js", "check.enc"]);

function idb(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("hana1q-ux-hub", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("kv");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction("kv", mode);
      const req = fn(tx.objectStore("kv"));
      tx.oncomplete = () => resolve(req && req.result);
      tx.onerror = () => reject(tx.error);
    };
  });
}

let key = null;
async function getKey() {
  if (key) return key;
  const rec = await idb("readonly", s => s.get("key")).catch(() => null);
  if (!rec) return null;
  if (rec.exp && rec.exp < Date.now()) { await idb("readwrite", s => s.delete("key")); return null; }
  key = await crypto.subtle.importKey("raw", rec.bytes, "AES-GCM", false, ["decrypt"]);
  return key;
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));

self.addEventListener("message", e => {
  const d = e.data || {};
  e.waitUntil((async () => {
    if (d.type === "setKey") {
      await idb("readwrite", s => s.put({ bytes: d.bytes, exp: d.exp }, "key"));
      key = null;
    } else if (d.type === "lock") {
      await idb("readwrite", s => s.delete("key"));
      key = null;
    }
    const has = !!(await getKey());
    e.source && e.source.postMessage({ type: "state", hasKey: has });
  })());
});

self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(ROOT)) return;
  const rel = url.pathname.slice(ROOT.length);
  if (PLAIN.has(rel) || rel.endsWith(".enc")) return;
  e.respondWith(serve(req, url));
});

async function serve(req, url) {
  const k = await getKey();
  if (!k) return fetch(req);
  let path = decodeURIComponent(url.pathname);
  if (path.endsWith("/")) path += "index.html";
  let res = await fetch(encodeURI(path) + ".enc", { cache: "no-cache" });
  if (!res.ok && !path.endsWith("/index.html")) {
    // 폴더 주소에 / 가 빠진 경우 (writing.component.label 처럼 점이 든 이름 포함): / 를 붙인 주소로 보낸다
    const dir = await fetch(encodeURI(path) + "/index.html.enc", { method: "HEAD", cache: "no-cache" });
    if (dir.ok) return Response.redirect(url.pathname + "/" + url.search, 301);
    // 확장자 없이 내보낸 앱 페이지 (/audit → audit.html)
    const html = await fetch(encodeURI(path) + ".html.enc", { cache: "no-cache" });
    if (html.ok) { res = html; path += ".html"; }
  }
  if (!res.ok) {
    if (req.mode === "navigate") return missingPage(url);
    return fetch(req);
  }
  const buf = new Uint8Array(await res.arrayBuffer());
  try {
    let plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, k, buf.slice(12));
    // 빌드에서 gzip 으로 줄인 텍스트 파일 (1f 8b 로 시작)
    const head = new Uint8Array(plain, 0, 2);
    if (head[0] === 0x1f && head[1] === 0x8b) plain = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer();
    const ext = (path.split(".").pop() || "").toLowerCase();
    return new Response(plain, { headers: { "content-type": MIME[ext] || "application/octet-stream", "cache-control": "no-store" } });
  } catch (x) {
    return fetch(req);
  }
}

// 정적 사이트에 없는 페이지 (예: ux-writing 의 자동 편입 화면 8천여 건은 용량 때문에 상세 페이지를 만들지 않았다)
function missingPage(url) {
  const site = url.pathname.slice(ROOT.length).split("/")[0];
  const isScreen = /\/ux-writing\/screens\/[^/]+\/?$/.test(url.pathname);
  const isQuestion = /\/ux-writing\/knowledge\/questions\/[^/]+\/?$/.test(url.pathname);
  const back = isScreen ? `${ROOT}ux-writing/screens/` : isQuestion ? `${ROOT}ux-writing/knowledge/questions/` : (site ? `${ROOT}${site}/` : ROOT);
  const msg = isScreen
    ? "이 화면은 원본에서 자동으로 편입된 화면이라 정적 사이트에는 상세 페이지가 없습니다. 화면 목록에서 모듈별로 확인할 수 있습니다."
    : isQuestion
    ? "확인 요청 항목은 원본 사이트에도 개별 페이지가 없습니다. 확인 요청 목록에서 볼 수 있습니다."
    : "요청한 페이지가 이 사이트에 없습니다.";
  const html = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>페이지 없음</title>
<style>:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;font:15px/1.6 "Apple SD Gothic Neo",system-ui,sans-serif;background:Canvas;color:CanvasText;padding:0 16px}
main{max-width:440px}h1{font-size:20px;margin:0 0 8px}p{margin:0 0 16px;opacity:.8}a{color:#00787a}</style></head>
<body><main><h1>상세 페이지가 없습니다</h1><p>${msg}</p><p><code>${url.pathname.replace(/[<>&]/g, "")}</code></p>
<a href="${back}">목록으로 돌아가기</a> · <a href="javascript:history.back()">이전 페이지</a></main></body></html>`;
  return new Response(html, { status: 404, headers: { "content-type": "text/html; charset=utf-8" } });
}
