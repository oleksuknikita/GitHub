// Р›Р°Р±РѕСЂР°С‚РѕСЂРЅРёР№ HTTP-СЃРµСЂРІРµСЂ РґРѕ РїСЂР°РєС‚РёС‡РЅРѕС— СЂРѕР±РѕС‚Рё в„– 3 В«РђРЅР°Р»С–Р· HTTP-РІР·Р°С”РјРѕРґС–С—В».
// Р‘РµР· СЃС‚РѕСЂРѕРЅРЅС–С… Р·Р°Р»РµР¶РЅРѕСЃС‚РµР№: Р»РёС€Рµ РІР±СѓРґРѕРІР°РЅС– РјРѕРґСѓР»С– Node.js.
// Р—Р°РїСѓСЃРє: npm start  в†’  API С– СЃС‚РѕСЂС–РЅРєР°: http://localhost:3000
//                       В«С‡СѓР¶РёР№В» СЃР°Р№С‚ РґР»СЏ CORS: http://localhost:5500
import http from "node:http";
import { readFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { gzipSync } from "node:zlib";
import { extname, join } from "node:path";

const API_PORT = Number(process.env.PORT ?? 3000);
const FOREIGN_PORT = Number(process.env.FOREIGN_PORT ?? 5500);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const root = import.meta.dirname;
const users = JSON.parse(readFileSync(join(root, "data", "users.json"), "utf8"));
let tickets = JSON.parse(readFileSync(join(root, "data", "tickets.json"), "utf8"));
let nextId = Math.max(...tickets.map((t) => t.id)) + 1;

// РќР°РІС‡Р°Р»СЊРЅС– РѕР±Р»С–РєРѕРІС– Р·Р°РїРёСЃРё (Р»РёС€Рµ РґР»СЏ Р»Р°Р±РѕСЂР°С‚РѕСЂРЅРѕС— СЂРѕР±РѕС‚Рё!)
const PASSWORDS = { "a.petrenko@college.example.ua": "student123", "m.koval@college.example.ua": "teacher123", "o.shevchuk@college.example.ua": "admin123" };
const sessions = new Map(); // token в†’ userId

const STATUSES = ["open", "in_progress", "resolved", "closed"];
const PRIORITIES = ["low", "medium", "high", "critical"];
const TRANSITIONS = { open: ["in_progress", "closed"], in_progress: ["open", "resolved"], resolved: ["closed", "in_progress"], closed: [] };

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml" };

// ---------------------------------------------------------------- РґРѕРїРѕРјС–Р¶РЅС–
function etagOf(body) {
  return `"${createHash("sha1").update(body).digest("base64url").slice(0, 20)}"`;
}

function send(req, res, status, body, headers = {}) {
  let payload = body === undefined ? "" : typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body, null, 2);
  const h = { ...headers };
  const prevVary = res.getHeader("Vary");
  if (prevVary && h.Vary) h.Vary = `${prevVary}, ${h.Vary}`;
  if (body !== undefined && !h["Content-Type"]) h["Content-Type"] = "application/json; charset=utf-8";
  const accepts = String(req.headers["accept-encoding"] ?? "");
  if (payload.length > 512 && /\bgzip\b/.test(accepts) && status !== 304) {
    payload = gzipSync(payload);
    h["Content-Encoding"] = "gzip";
    const base = h["Vary"] ?? res.getHeader("Vary");
    h["Vary"] = base ? `${base}, Accept-Encoding` : "Accept-Encoding";
  }
  if (payload.length && status !== 204 && status !== 304) h["Content-Length"] = Buffer.byteLength(payload);
  res.writeHead(status, h);
  res.end(status === 204 || status === 304 || req.method === "HEAD" ? undefined : payload);
}

/** Р’С–РґРїРѕРІС–РґСЊ Р· РѕРїРёСЃРѕРј РїРѕРјРёР»РєРё Р·Р° RFC 9457 (Problem Details). */
function problem(req, res, status, title, detail, extra = {}, headers = {}) {
  send(req, res, status, { type: "about:blank", title, status, detail, instance: req.url, ...extra }, { "Content-Type": "application/problem+json; charset=utf-8", ...headers });
}

async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return undefined;
  return JSON.parse(text);
}

function currentUser(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
  if (!m) return undefined;
  const id = sessions.get(m[1]);
  return users.find((u) => u.id === id);
}

function requireUser(req, res) {
  const user = currentUser(req);
  if (!user) {
    problem(req, res, 401, "РџРѕС‚СЂС–Р±РЅР° Р°РІС‚РµРЅС‚РёС„С–РєР°С†С–СЏ", "Р”РѕРґР°Р№С‚Рµ Р·Р°РіРѕР»РѕРІРѕРє Authorization: Bearer <С‚РѕРєРµРЅ>. РўРѕРєРµРЅ РІРёРґР°С” POST /api/auth/login.", {}, { "WWW-Authenticate": 'Bearer realm="helpdesk"' });
  }
  return user;
}

function validateTicket(data, partial) {
  const errors = [];
  const has = (k) => data[k] !== undefined;
  if (!partial || has("title")) {
    if (typeof data.title !== "string" || data.title.trim() === "") errors.push({ field: "title", message: "РїРѕР»Рµ РѕР±РѕРІ'СЏР·РєРѕРІРµ" });
    else if (data.title.length > 80) errors.push({ field: "title", message: "РґРѕРІР¶РёРЅР° РЅРµ Р±С–Р»СЊС€Рµ 80 СЃРёРјРІРѕР»С–РІ" });
  }
  if (!partial || has("priority")) {
    if (!PRIORITIES.includes(data.priority)) errors.push({ field: "priority", message: `РґРѕРїСѓСЃС‚РёРјС– Р·РЅР°С‡РµРЅРЅСЏ: ${PRIORITIES.join(", ")}` });
  }
  if (has("description") && typeof data.description !== "string") errors.push({ field: "description", message: "РјР°С” Р±СѓС‚Рё СЂСЏРґРєРѕРј" });
  if (has("tags") && !(Array.isArray(data.tags) && data.tags.every((t) => typeof t === "string"))) errors.push({ field: "tags", message: "РјР°С” Р±СѓС‚Рё РјР°СЃРёРІРѕРј СЂСЏРґРєС–РІ" });
  if (has("assigneeId") && !(data.assigneeId === null || users.some((u) => u.id === data.assigneeId))) errors.push({ field: "assigneeId", message: "РєРѕСЂРёСЃС‚СѓРІР°С‡Р° РЅРµ Р·РЅР°Р№РґРµРЅРѕ" });
  if (has("status")) errors.push({ field: "status", message: "СЃС‚Р°РЅ Р·РјС–РЅСЋС”С‚СЊСЃСЏ Р»РёС€Рµ С‡РµСЂРµР· POST /api/tickets/{id}/status" });
  if (has("id")) errors.push({ field: "id", message: "С–РґРµРЅС‚РёС„С–РєР°С‚РѕСЂ РїСЂРёР·РЅР°С‡Р°С” СЃРµСЂРІРµСЂ" });
  return errors;
}

function toCsv(items) {
  const cols = ["id", "title", "status", "priority", "authorId", "assigneeId", "createdAt"];
  const esc = (v) => (v === null || v === undefined ? "" : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
  return [cols.join(","), ...items.map((t) => cols.map((c) => esc(t[c])).join(","))].join("\n") + "\n";
}

function corsHeaders(req) {
  const origin = req.headers.origin;
  if (!origin || !ALLOWED_ORIGINS.includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Expose-Headers": "Location, ETag, X-Request-Id, Retry-After",
    Vary: "Origin",
  };
}

// РѕР±РјРµР¶РµРЅРЅСЏ С‡Р°СЃС‚РѕС‚Рё РґР»СЏ /api/limited: 5 Р·Р°РїРёС‚С–РІ Р·Р° 10 СЃ Р· РѕРґРЅС–С”С— Р°РґСЂРµСЃРё
const hits = new Map();
function rateLimit(req) {
  const key = req.socket.remoteAddress;
  const now = Date.now();
  const list = (hits.get(key) ?? []).filter((t) => now - t < 10_000);
  list.push(now);
  hits.set(key, list);
  const remaining = Math.max(0, 5 - list.length);
  const retry = Math.ceil((10_000 - (now - list[0])) / 1000);
  return { allowed: list.length <= 5, remaining, retry };
}

// ---------------------------------------------------------------- РјР°СЂС€СЂСѓС‚Рё API
async function api(req, res, url) {
  const path = url.pathname;
  const m = req.method;

  if (path === "/api/health" && (m === "GET" || m === "HEAD")) {
    return send(req, res, 200, { status: "ok", uptime: Math.round(process.uptime()), node: process.version }, { "Cache-Control": "no-store" });
  }

  if (path === "/api/auth/login") {
    if (m !== "POST") return problem(req, res, 405, "РњРµС‚РѕРґ РЅРµ РґРѕР·РІРѕР»РµРЅРѕ", `${m} РЅРµ РїС–РґС‚СЂРёРјСѓС”С‚СЊСЃСЏ`, {}, { Allow: "POST" });
    const body = (await readJson(req)) ?? {};
    if (!body.email || !body.password) return problem(req, res, 400, "РќРµРєРѕСЂРµРєС‚РЅРёР№ Р·Р°РїРёС‚", "РџРѕС‚СЂС–Р±РЅС– РїРѕР»СЏ email С– password");
    const user = users.find((u) => u.email === body.email);
    if (!user || PASSWORDS[user.email] !== body.password) return problem(req, res, 401, "РќРµРІС–СЂРЅС– РѕР±Р»С–РєРѕРІС– РґР°РЅС–", "Email Р°Р±Рѕ РїР°СЂРѕР»СЊ РЅРµРїСЂР°РІРёР»СЊРЅС–", {}, { "WWW-Authenticate": 'Bearer realm="helpdesk"' });
    const token = randomUUID();
    sessions.set(token, user.id);
    return send(req, res, 200, { accessToken: token, tokenType: "Bearer", expiresIn: 3600, user: { id: user.id, fullName: user.fullName, role: user.role } }, { "Cache-Control": "no-store" });
  }

  if (path === "/api/old-tickets") {
    return send(req, res, 301, undefined, { Location: `/api/tickets${url.search}` });
  }

  if (path === "/api/slow") {
    const ms = Math.min(Number(url.searchParams.get("ms") ?? 1500) || 0, 10_000);
    await new Promise((r) => setTimeout(r, ms));
    return send(req, res, 200, { waitedMs: ms });
  }

  if (path === "/api/error") {
    return problem(req, res, 500, "Р’РЅСѓС‚СЂС–С€РЅСЏ РїРѕРјРёР»РєР° СЃРµСЂРІРµСЂР°", "Р†РјС–С‚Р°С†С–СЏ Р·Р±РѕСЋ РґР»СЏ РЅР°РІС‡Р°Р»СЊРЅРёС… С†С–Р»РµР№");
  }

  if (path === "/api/limited") {
    const r = rateLimit(req);
    const h = { "RateLimit-Limit": "5", "RateLimit-Remaining": String(r.remaining) };
    if (!r.allowed) return problem(req, res, 429, "Р—Р°Р±Р°РіР°С‚Рѕ Р·Р°РїРёС‚С–РІ", `Р›С–РјС–С‚ вЂ“ 5 Р·Р°РїРёС‚С–РІ Р·Р° 10 СЃРµРєСѓРЅРґ. РџРѕРІС‚РѕСЂС–С‚СЊ С‡РµСЂРµР· ${r.retry} СЃ.`, {}, { ...h, "Retry-After": String(r.retry) });
    return send(req, res, 200, { ok: true, remaining: r.remaining }, h);
  }

  if (path === "/api/tickets") {
    if (m === "GET" || m === "HEAD") {
      const status = url.searchParams.get("status");
      const priority = url.searchParams.get("priority");
      const page = Number(url.searchParams.get("page") ?? 1);
      const pageSize = Number(url.searchParams.get("pageSize") ?? 10);
      if (!Number.isInteger(page) || page < 1 || !Number.isInteger(pageSize) || pageSize < 1 || pageSize > 50) {
        return problem(req, res, 400, "РќРµРєРѕСЂРµРєС‚РЅС– РїР°СЂР°РјРµС‚СЂРё", "page в‰Ґ 1, 1 в‰¤ pageSize в‰¤ 50 вЂ“ С†С–Р»С– С‡РёСЃР»Р°");
      }
      if (status && !STATUSES.includes(status)) return problem(req, res, 400, "РќРµРєРѕСЂРµРєС‚РЅС– РїР°СЂР°РјРµС‚СЂРё", `status: ${STATUSES.join(", ")}`);
      let list = tickets.filter((t) => (!status || t.status === status) && (!priority || t.priority === priority));
      const total = list.length;
      list = list.slice((page - 1) * pageSize, page * pageSize);
      const accept = String(req.headers.accept ?? "*/*");
      let body;
      let type;
      if (/application\/json|\*\/\*|application\/\*/.test(accept)) {
        body = JSON.stringify({ items: list, page, pageSize, total }, null, 2);
        type = "application/json; charset=utf-8";
      } else if (/text\/csv/.test(accept)) {
        body = toCsv(list);
        type = "text/csv; charset=utf-8";
      } else {
        return problem(req, res, 406, "Р¤РѕСЂРјР°С‚ РЅРµ РїС–РґС‚СЂРёРјСѓС”С‚СЊСЃСЏ", "Р”РѕСЃС‚СѓРїРЅС– С„РѕСЂРјР°С‚Рё: application/json, text/csv", {}, { Vary: "Accept" });
      }
      const etag = etagOf(body);
      const headers = { "Content-Type": type, ETag: etag, "Cache-Control": "private, no-cache", Vary: "Accept" };
      if (req.headers["if-none-match"] === etag) return send(req, res, 304, undefined, headers);
      return send(req, res, 200, body, headers);
    }
    if (m === "POST") {
      const user = requireUser(req, res);
      if (!user) return;
      if (!/^application\/json/.test(req.headers["content-type"] ?? "")) return problem(req, res, 415, "РќРµРїС–РґС‚СЂРёРјСѓРІР°РЅРёР№ С‚РёРї РІРјС–СЃС‚Сѓ", "РћС‡С–РєСѓС”С‚СЊСЃСЏ Content-Type: application/json");
      let data;
      try {
        data = (await readJson(req)) ?? {};
      } catch {
        return problem(req, res, 400, "РќРµРєРѕСЂРµРєС‚РЅРёР№ JSON", "РўС–Р»Рѕ Р·Р°РїРёС‚Сѓ РЅРµ С” РєРѕСЂРµРєС‚РЅРёРј JSON");
      }
      const errors = validateTicket(data, false);
      if (errors.length) return problem(req, res, 422, "РџРѕРјРёР»РєР° РІР°Р»С–РґР°С†С–С—", "Р”Р°РЅС– Р·Р°СЏРІРєРё РЅРµ РІС–РґРїРѕРІС–РґР°СЋС‚СЊ РІРёРјРѕРіР°Рј", { errors });
      if (data.priority === "critical" && user.role === "student") return problem(req, res, 403, "Р”РѕСЃС‚СѓРї Р·Р°Р±РѕСЂРѕРЅРµРЅРѕ", "РљСЂРёС‚РёС‡РЅРёР№ РїСЂС–РѕСЂРёС‚РµС‚ РІСЃС‚Р°РЅРѕРІР»СЋС” Р»РёС€Рµ РІРёРєР»Р°РґР°С‡ Р°Р±Рѕ Р°РґРјС–РЅС–СЃС‚СЂР°С‚РѕСЂ");
      const ticket = { id: nextId++, title: data.title.trim(), ...(data.description ? { description: data.description } : {}), status: "open", priority: data.priority, authorId: user.id, assigneeId: null, createdAt: new Date().toISOString(), tags: data.tags ?? [] };
      tickets.push(ticket);
      return send(req, res, 201, ticket, { Location: `/api/tickets/${ticket.id}` });
    }
    return problem(req, res, 405, "РњРµС‚РѕРґ РЅРµ РґРѕР·РІРѕР»РµРЅРѕ", `${m} /api/tickets РЅРµ РїС–РґС‚СЂРёРјСѓС”С‚СЊСЃСЏ`, {}, { Allow: "GET, HEAD, POST" });
  }

  const one = /^\/api\/tickets\/([^/]+)(\/status)?$/.exec(path);
  if (one) {
    const id = Number(one[1]);
    if (!Number.isInteger(id) || id < 1) return problem(req, res, 400, "РќРµРєРѕСЂРµРєС‚РЅРёР№ С–РґРµРЅС‚РёС„С–РєР°С‚РѕСЂ", `В«${one[1]}В» РЅРµ С” С†С–Р»РёРј РґРѕРґР°С‚РЅРёРј С‡РёСЃР»РѕРј`);
    const index = tickets.findIndex((t) => t.id === id);

    if (one[2]) {
      if (m !== "POST") return problem(req, res, 405, "РњРµС‚РѕРґ РЅРµ РґРѕР·РІРѕР»РµРЅРѕ", `${m} РЅРµ РїС–РґС‚СЂРёРјСѓС”С‚СЊСЃСЏ`, {}, { Allow: "POST" });
      const user = requireUser(req, res);
      if (!user) return;
      if (index === -1) return problem(req, res, 404, "Р—Р°СЏРІРєСѓ РЅРµ Р·РЅР°Р№РґРµРЅРѕ", `Р—Р°СЏРІРєРё Р· id=${id} РЅРµ С–СЃРЅСѓС”`);
      const body = (await readJson(req).catch(() => undefined)) ?? {};
      if (!STATUSES.includes(body.status)) return problem(req, res, 422, "РџРѕРјРёР»РєР° РІР°Р»С–РґР°С†С–С—", `status: ${STATUSES.join(", ")}`);
      const current = tickets[index];
      if (!TRANSITIONS[current.status].includes(body.status)) return problem(req, res, 409, "РљРѕРЅС„Р»С–РєС‚ СЃС‚Р°РЅСѓ", `РџРµСЂРµС…С–Рґ ${current.status} в†’ ${body.status} РЅРµРґРѕРїСѓСЃС‚РёРјРёР№`, { allowed: TRANSITIONS[current.status] });
      tickets[index] = { ...current, status: body.status };
      return send(req, res, 200, tickets[index]);
    }

    if (m === "GET" || m === "HEAD") {
      if (index === -1) return problem(req, res, 404, "Р—Р°СЏРІРєСѓ РЅРµ Р·РЅР°Р№РґРµРЅРѕ", `Р—Р°СЏРІРєРё Р· id=${id} РЅРµ С–СЃРЅСѓС”`);
      const body = JSON.stringify(tickets[index], null, 2);
      const etag = etagOf(body);
      const headers = { "Content-Type": "application/json; charset=utf-8", ETag: etag, "Cache-Control": "private, no-cache" };
      if (req.headers["if-none-match"] === etag) return send(req, res, 304, undefined, headers);
      return send(req, res, 200, body, headers);
    }
    if (m === "PATCH") {
      const user = requireUser(req, res);
      if (!user) return;
      if (index === -1) return problem(req, res, 404, "Р—Р°СЏРІРєСѓ РЅРµ Р·РЅР°Р№РґРµРЅРѕ", `Р—Р°СЏРІРєРё Р· id=${id} РЅРµ С–СЃРЅСѓС”`);
      let data;
      try {
        data = (await readJson(req)) ?? {};
      } catch {
        return problem(req, res, 400, "РќРµРєРѕСЂРµРєС‚РЅРёР№ JSON", "РўС–Р»Рѕ Р·Р°РїРёС‚Сѓ РЅРµ С” РєРѕСЂРµРєС‚РЅРёРј JSON");
      }
      const errors = validateTicket(data, true);
      if (errors.length) return problem(req, res, 422, "РџРѕРјРёР»РєР° РІР°Р»С–РґР°С†С–С—", "Р”Р°РЅС– Р·Р°СЏРІРєРё РЅРµ РІС–РґРїРѕРІС–РґР°СЋС‚СЊ РІРёРјРѕРіР°Рј", { errors });
      tickets[index] = { ...tickets[index], ...data, id };
      return send(req, res, 200, tickets[index]);
    }
    if (m === "DELETE") {
      const user = requireUser(req, res);
      if (!user) return;
      if (user.role !== "admin") return problem(req, res, 403, "Р”РѕСЃС‚СѓРї Р·Р°Р±РѕСЂРѕРЅРµРЅРѕ", "Р’РёРґР°Р»СЏС‚Рё Р·Р°СЏРІРєРё РјРѕР¶Рµ Р»РёС€Рµ Р°РґРјС–РЅС–СЃС‚СЂР°С‚РѕСЂ");
      if (index === -1) return problem(req, res, 404, "Р—Р°СЏРІРєСѓ РЅРµ Р·РЅР°Р№РґРµРЅРѕ", `Р—Р°СЏРІРєРё Р· id=${id} РЅРµ С–СЃРЅСѓС”`);
      tickets.splice(index, 1);
      return send(req, res, 204);
    }
    return problem(req, res, 405, "РњРµС‚РѕРґ РЅРµ РґРѕР·РІРѕР»РµРЅРѕ", `${m} РЅРµ РїС–РґС‚СЂРёРјСѓС”С‚СЊСЃСЏ`, {}, { Allow: "GET, HEAD, PATCH, DELETE" });
  }

  return problem(req, res, 404, "Р РµСЃСѓСЂСЃ РЅРµ Р·РЅР°Р№РґРµРЅРѕ", `РњР°СЂС€СЂСѓС‚ ${m} ${path} РЅРµ С–СЃРЅСѓС”`);
}

// ---------------------------------------------------------------- СЃС‚Р°С‚РёС‡РЅС– С„Р°Р№Р»Рё
function serveStatic(req, res, dir, path, cache) {
  const file = path === "/" ? "/index.html" : path;
  if (file.includes("..")) return problem(req, res, 400, "РќРµРєРѕСЂРµРєС‚РЅРёР№ С€Р»СЏС…", "");
  let body;
  try {
    body = readFileSync(join(dir, file));
  } catch {
    return problem(req, res, 404, "Р¤Р°Р№Р» РЅРµ Р·РЅР°Р№РґРµРЅРѕ", `${file} РЅРµ С–СЃРЅСѓС”`);
  }
  const etag = etagOf(body);
  const headers = { "Content-Type": MIME[extname(file)] ?? "application/octet-stream", ETag: etag, "Cache-Control": cache(file) };
  if (file === "/index.html" && dir.endsWith("public")) {
    headers["Set-Cookie"] = `helpdesk_visit=${Date.now()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`;
  }
  if (req.headers["if-none-match"] === etag) return send(req, res, 304, undefined, headers);
  return send(req, res, 200, body, headers);
}

// ---------------------------------------------------------------- СЃРµСЂРІРµСЂРё
const apiServer = http.createServer(async (req, res) => {
  const started = performance.now();
  const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
  const requestId = randomUUID();
  res.setHeader("X-Request-Id", requestId);
  for (const [k, v] of Object.entries(corsHeaders(req))) res.setHeader(k, v);

  const origWriteHead = res.writeHead.bind(res);
  res.writeHead = (status, headers) => {
    res.setHeader("Server-Timing", `app;desc="handler";dur=${(performance.now() - started).toFixed(1)}`);
    return origWriteHead(status, headers);
  };
  res.on("finish", () => {
    console.log(`${new Date().toISOString().slice(11, 19)}  ${req.method.padEnd(7)} ${url.pathname}${url.search}  в†’ ${res.statusCode}  ${(performance.now() - started).toFixed(0)} РјСЃ${req.headers.origin ? `  [Origin: ${req.headers.origin}]` : ""}`);
  });

  try {
    // РїРѕРїРµСЂРµРґРЅС–Р№ Р·Р°РїРёС‚ CORS (preflight)
    if (req.method === "OPTIONS") {
      const cors = corsHeaders(req);
      if (!cors["Access-Control-Allow-Origin"]) return send(req, res, 204, undefined, { Allow: "GET, HEAD, POST, PATCH, DELETE, OPTIONS" });
      return send(req, res, 204, undefined, {
        "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Max-Age": "600",
      });
    }
    if (url.pathname.startsWith("/api/")) return await api(req, res, url);
    return serveStatic(req, res, join(root, "public"), url.pathname, (f) =>
      f === "/index.html" ? "no-cache" : f.endsWith(".svg") ? "public, max-age=3600" : "public, max-age=60",
    );
  } catch (error) {
    console.error(error);
    if (!res.headersSent) problem(req, res, 500, "Р’РЅСѓС‚СЂС–С€РЅСЏ РїРѕРјРёР»РєР° СЃРµСЂРІРµСЂР°", "РќРµРїРµСЂРµРґР±Р°С‡РµРЅР° РїРѕРјРёР»РєР°");
  }
});

const foreignServer = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  serveStatic(req, res, join(root, "foreign"), url.pathname, () => "no-cache");
});

apiServer.listen(API_PORT, () => {
  console.log(`API С– СЃС‚РѕСЂС–РЅРєР° СЃР»СѓР¶Р±Рё РїС–РґС‚СЂРёРјРєРё: http://localhost:${API_PORT}`);
  console.log(`Р”РѕР·РІРѕР»РµРЅС– РґР¶РµСЂРµР»Р° CORS (ALLOWED_ORIGINS): ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(", ") : "(Р¶РѕРґРЅРѕРіРѕ)"}`);
});
foreignServer.listen(FOREIGN_PORT, () => console.log(`В«Р§СѓР¶РёР№В» СЃР°Р№С‚ РґР»СЏ РїРµСЂРµРІС–СЂРєРё CORS: http://localhost:${FOREIGN_PORT}\n`));

