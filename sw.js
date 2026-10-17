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
  // 확장자 없는 주소(/audit)는 audit.html 로 내보낸 앱 페이지
  if (!res.ok && !/\.[a-z0-9]+$/i.test(path)) {
    path += ".html";
    res = await fetch(encodeURI(path) + ".enc", { cache: "no-cache" });
  }
  if (!res.ok) return fetch(req);
  const buf = new Uint8Array(await res.arrayBuffer());
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, k, buf.slice(12));
    const ext = (path.split(".").pop() || "").toLowerCase();
    return new Response(plain, { headers: { "content-type": MIME[ext] || "application/octet-stream", "cache-control": "no-store" } });
  } catch (x) {
    return fetch(req);
  }
}
