var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var __defProp2 = Object.defineProperty;
var __name2 = /* @__PURE__ */ __name((target, value) => __defProp2(target, "name", { value, configurable: true }), "__name");
var SESSION_COOKIE_NAME = "veltrix_admin_session";
var SESSION_TTL_MS = 8 * 60 * 60 * 1e3;
var PRO_PLAN_ID = "PRO-9F4D7B2A-6C1E-3A9B-8D4F-7E2C1B0A5D6F";
var SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
};
function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: Object.assign(
      { "Content-Type": "application/json; charset=UTF-8" },
      SECURITY_HEADERS,
      extraHeaders
    )
  });
}
__name(jsonResponse, "jsonResponse");
__name2(jsonResponse, "jsonResponse");
function htmlResponse(html, extraHeaders = {}) {
  return new Response(html, {
    headers: Object.assign(
      {
        "Content-Type": "text/html; charset=UTF-8",
        // No cache for the admin panel: guarantees fresh JS after every deploy.
        "Cache-Control": "no-store",
        // CSP يمنع تحميل أي سكربت/ستايل خارجي، مناسب لأن كل شيء هنا inline
        "Content-Security-Policy": "default-src 'self'; connect-src 'self' https://cbc8926536289c168ea904769aaada16.r2.cloudflarestorage.com; style-src 'unsafe-inline'; script-src 'unsafe-inline'"
      },
      SECURITY_HEADERS,
      extraHeaders
    )
  });
}
__name(htmlResponse, "htmlResponse");
__name2(htmlResponse, "htmlResponse");
function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
__name(bufferToBase64Url, "bufferToBase64Url");
__name2(bufferToBase64Url, "bufferToBase64Url");
function hexEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(hexEncode, "hexEncode");
__name2(hexEncode, "hexEncode");
async function sha256Hex(data) {
  return hexEncode(await crypto.subtle.digest("SHA-256", data));
}
__name(sha256Hex, "sha256Hex");
__name2(sha256Hex, "sha256Hex");
function uriEncode(str) {
  return str.replace(/[^A-Za-z0-9\-_.~]/g, function (c) {
    return "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0");
  });
}
__name(uriEncode, "uriEncode");
__name2(uriEncode, "uriEncode");
function generateUUID() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  arr[6] = (arr[6] & 0x0f) | 0x40;
  arr[8] = (arr[8] & 0x3f) | 0x80;
  return Array.from(arr, function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}
__name(generateUUID, "generateUUID");
__name2(generateUUID, "generateUUID");
function safeTruncate(str, max) {
  if (typeof str !== "string") return str;
  return str.length > max ? str.slice(0, max) + "...<truncated>" : str;
}
__name(safeTruncate, "safeTruncate");
__name2(safeTruncate, "safeTruncate");
function base64UrlToBuffer(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
__name(base64UrlToBuffer, "base64UrlToBuffer");
__name2(base64UrlToBuffer, "base64UrlToBuffer");
async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bufferToBase64Url(sig);
}
__name(hmacSign, "hmacSign");
__name2(hmacSign, "hmacSign");
async function verifyToken(token, env) {
  const signingKeys = env.SESSION_SIGNING_KEYS ? JSON.parse(env.SESSION_SIGNING_KEYS) : null;
  const activeKid = env.SESSION_ACTIVE_KID;
  if (!signingKeys || !activeKid) return null;
  const secret = signingKeys[activeKid];
  if (!secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts;
  const expected = hmacSign(secret, `${encodedHeader}.${encodedPayload}`);
  if (!timingSafeEqual(signature, expected)) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBuffer(encodedPayload)));
    if (payload.exp < Math.floor(Date.now() / 1e3)) return null;
    return payload;
  } catch {
    return null;
  }
}
__name(verifyToken, "verifyToken");
__name2(verifyToken, "verifyToken");
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
__name(timingSafeEqual, "timingSafeEqual");
__name2(timingSafeEqual, "timingSafeEqual");
function getClientIp(request) {
  const header = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "";
  return header.split(",")[0].trim();
}
__name(getClientIp, "getClientIp");
__name2(getClientIp, "getClientIp");
function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const parts = header.split(";").map((p) => p.trim());
  for (const part of parts) {
    const [k, ...rest] = part.split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}
__name(getCookie, "getCookie");
__name2(getCookie, "getCookie");
async function createSessionToken(env) {
  const expiry = Date.now() + SESSION_TTL_MS;
  const payload = `admin.${expiry}`;
  const signature = await hmacSign(env.ADMIN_PASSWORD, payload);
  return `${payload}.${signature}`;
}
__name(createSessionToken, "createSessionToken");
__name2(createSessionToken, "createSessionToken");
async function isValidSession(env, token) {
  if (!token) return false;
  const lastDot = token.lastIndexOf(".");
  if (lastDot === -1) return false;
  const payload = token.slice(0, lastDot);
  const signature = token.slice(lastDot + 1);
  const [role, expiryStr] = payload.split(".");
  if (role !== "admin") return false;
  const expiry = Number(expiryStr);
  if (!expiry || Date.now() > expiry) return false;
  const expectedSignature = await hmacSign(env.ADMIN_PASSWORD, payload);
  return timingSafeEqual(signature, expectedSignature);
}
__name(isValidSession, "isValidSession");
__name2(isValidSession, "isValidSession");
function sessionCookieHeader(token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1e3);
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(
    token
  )}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
__name(sessionCookieHeader, "sessionCookieHeader");
__name2(sessionCookieHeader, "sessionCookieHeader");
function clearCookieHeader() {
  return `${SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}
__name(clearCookieHeader, "clearCookieHeader");
__name2(clearCookieHeader, "clearCookieHeader");
async function requireAuth(request, env) {
  const token = getCookie(request, SESSION_COOKIE_NAME);
  return isValidSession(env, token);
}
__name(requireAuth, "requireAuth");
__name2(requireAuth, "requireAuth");
async function isValidAffiliateProductId(env, id) {
  if (typeof id !== "string" || !id) return false;
  const row = await env.DB.prepare("SELECT id FROM affiliate_products WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidAffiliateProductId, "isValidAffiliateProductId");
__name2(isValidAffiliateProductId, "isValidAffiliateProductId");
async function isValidGameId(env, id) {
  if (id === void 0 || id === null) return false;
  const row = await env.DB.prepare("SELECT id FROM games WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidGameId, "isValidGameId");
__name2(isValidGameId, "isValidGameId");
async function isValidLicenseId(env, id) {
  if (typeof id !== "string" || !id) return false;
  const row = await env.DB.prepare("SELECT id FROM licenses WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidLicenseId, "isValidLicenseId");
__name2(isValidLicenseId, "isValidLicenseId");
async function isValidLiveStreamId(env, id) {
  if (typeof id !== "string" || !id) return false;
  const row = await env.DB.prepare("SELECT id FROM live_streams WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidLiveStreamId, "isValidLiveStreamId");
__name2(isValidLiveStreamId, "isValidLiveStreamId");
async function isValidMovieId(env, id) {
  if (typeof id !== "string" || !id) return false;
  const row = await env.DB.prepare("SELECT id FROM movies WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidMovieId, "isValidMovieId");
__name2(isValidMovieId, "isValidMovieId");
async function isValidPcAppId(env, id) {
  if (id === void 0 || id === null) return false;
  const row = await env.DB.prepare("SELECT id FROM pc_apps WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidPcAppId, "isValidPcAppId");
__name2(isValidPcAppId, "isValidPcAppId");
async function isValidPluginId(env, id) {
  if (id === void 0 || id === null) return false;
  const row = await env.DB.prepare("SELECT id FROM plugins WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidPluginId, "isValidPluginId");
__name2(isValidPluginId, "isValidPluginId");
async function isValidSeriesId(env, id) {
  if (typeof id !== "string" || !id) return false;
  const row = await env.DB.prepare("SELECT id FROM series WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidSeriesId, "isValidSeriesId");
__name2(isValidSeriesId, "isValidSeriesId");
async function isValidUpdateId(env, id) {
  if (typeof id !== "string" || !id) return false;
  const row = await env.DB.prepare("SELECT id FROM updates WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidUpdateId, "isValidUpdateId");
__name2(isValidUpdateId, "isValidUpdateId");
async function isValidConfigId(env, id) {
  if (typeof id !== "string" || !id) return false;
  const row = await env.DB.prepare("SELECT id FROM config WHERE id = ?").bind(id).first();
  return !!row;
}
__name(isValidConfigId, "isValidConfigId");
__name2(isValidConfigId, "isValidConfigId");
async function handleAdminLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400);
  }
  const password = body && body.password;
  if (typeof password !== "string" || !password) {
    return jsonResponse({ error: "missing_password" }, 400);
  }
  if (!timingSafeEqual(password, env.ADMIN_PASSWORD)) {
    return jsonResponse({ error: "invalid_credentials" }, 401);
  }
  const token = await createSessionToken(env);
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Set-Cookie": sessionCookieHeader(token)
    }
  });
}
__name(handleAdminLogin, "handleAdminLogin");
__name2(handleAdminLogin, "handleAdminLogin");
function handleAdminLogout() {
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Set-Cookie": clearCookieHeader()
    }
  });
}
__name(handleAdminLogout, "handleAdminLogout");
__name2(handleAdminLogout, "handleAdminLogout");
async function handleList(env, tableName, searchableColumns, search = "", page = 1, pageSize = 50) {
  const offset = (page - 1) * pageSize;
  let whereClause = "";
  const searchParams = [];
  if (search && searchableColumns.length > 0) {
    whereClause = "WHERE " + searchableColumns.map((c) => `${c} LIKE ?`).join(" OR ");
    const searchParam = `%${search}%`;
    for (let i = 0; i < searchableColumns.length; i++) searchParams.push(searchParam);
  }
  const countQuery = `SELECT COUNT(*) as total FROM ${tableName} ${whereClause}`;
  const dataQuery = `SELECT * FROM ${tableName} ${whereClause} ORDER BY id LIMIT ? OFFSET ?`;
  const dataParams = [...searchParams, pageSize, offset];
  const [countResult, dataResult] = await Promise.all([
    env.DB.prepare(countQuery).bind(...searchParams).all(),
    env.DB.prepare(dataQuery).bind(...dataParams).all()
  ]);
  const total = countResult.results[0]?.total || 0;
  return jsonResponse({
    items: dataResult.results,
    total,
    page,
    pageSize,
    totalPages: Math.ceil(total / pageSize)
  });
}
__name(handleList, "handleList");
__name2(handleList, "handleList");
async function handleGet(env, tableName, id, validFn) {
  if (!await validFn(env, id)) {
    return jsonResponse({ error: "not_found" }, 404);
  }
  const row = await env.DB.prepare(`SELECT * FROM ${tableName} WHERE id = ?`).bind(id).first();
  return jsonResponse(row);
}
__name(handleGet, "handleGet");
__name2(handleGet, "handleGet");
async function handleCreate(request, env, tableName, columns, validFn) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400);
  }
  const values = columns.map((c) => body[c]);
  if (values.some((v) => v === void 0 || v === null || v === "")) {
    return jsonResponse({ error: "missing_required_fields" }, 400);
  }
  const id = body.id;
  if (id && await validFn(env, id)) {
    return jsonResponse({ error: "id_already_exists" }, 409);
  }
  const placeholders = columns.map(() => "?").join(", ");
  const result = await env.DB.prepare(
    `INSERT INTO ${tableName} (${columns.join(", ")}) VALUES (${placeholders})`
  ).bind(...values).run();
  if (!result.success) {
    return jsonResponse({ error: "insert_failed" }, 500);
  }
  return jsonResponse({ success: true, id: body.id || result.meta.last_row_id });
}
__name(handleCreate, "handleCreate");
__name2(handleCreate, "handleCreate");
async function handleUpdate(request, env, tableName, columns, validFn) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400);
  }
  const id = body.id;
  if (!id || !await validFn(env, id)) {
    return jsonResponse({ error: "not_found" }, 404);
  }
  const updates = columns.filter((c) => c !== "id" && body[c] !== void 0);
  if (updates.length === 0) {
    return jsonResponse({ error: "no_fields_to_update" }, 400);
  }
  const setClause = updates.map((c) => `${c} = ?`).join(", ");
  const values = updates.map((c) => body[c]);
  values.push(id);
  const result = await env.DB.prepare(
    `UPDATE ${tableName} SET ${setClause} WHERE id = ?`
  ).bind(...values).run();
  if (result.meta.changes === 0) {
    return jsonResponse({ error: "not_found" }, 404);
  }
  return jsonResponse({ success: true, id });
}
__name(handleUpdate, "handleUpdate");
__name2(handleUpdate, "handleUpdate");
async function handleDelete(env, tableName, id, validFn) {
  if (!id || !await validFn(env, id)) {
    return jsonResponse({ error: "not_found" }, 404);
  }
  const result = await env.DB.prepare(`DELETE FROM ${tableName} WHERE id = ?`).bind(id).run();
  if (result.meta.changes === 0) {
    return jsonResponse({ error: "not_found" }, 404);
  }
  return jsonResponse({ success: true });
}
__name(handleDelete, "handleDelete");
__name2(handleDelete, "handleDelete");
async function handleListMovies(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "movies", ["id", "name"], search, page, pageSize);
}
__name(handleListMovies, "handleListMovies");
__name2(handleListMovies, "handleListMovies");
async function handleGetMovie(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "movies", id, isValidMovieId);
}
__name(handleGetMovie, "handleGetMovie");
__name2(handleGetMovie, "handleGetMovie");
async function handleCreateMovie(request, env) {
  return handleCreate(request, env, "movies", ["id", "name"], isValidMovieId);
}
__name(handleCreateMovie, "handleCreateMovie");
__name2(handleCreateMovie, "handleCreateMovie");
async function handleUpdateMovie(request, env) {
  return handleUpdate(request, env, "movies", ["id", "name"], isValidMovieId);
}
__name(handleUpdateMovie, "handleUpdateMovie");
__name2(handleUpdateMovie, "handleUpdateMovie");
async function handleDeleteMovie(env, id) {
  return handleDelete(env, "movies", id, isValidMovieId);
}
__name(handleDeleteMovie, "handleDeleteMovie");
__name2(handleDeleteMovie, "handleDeleteMovie");
async function handleListSeries(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "series", ["id", "name"], search, page, pageSize);
}
__name(handleListSeries, "handleListSeries");
__name2(handleListSeries, "handleListSeries");
async function handleGetSeries(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "series", id, isValidSeriesId);
}
__name(handleGetSeries, "handleGetSeries");
__name2(handleGetSeries, "handleGetSeries");
async function handleCreateSeries(request, env) {
  return handleCreate(request, env, "series", ["id", "name"], isValidSeriesId);
}
__name(handleCreateSeries, "handleCreateSeries");
__name2(handleCreateSeries, "handleCreateSeries");
async function handleUpdateSeries(request, env) {
  return handleUpdate(request, env, "series", ["id", "name"], isValidSeriesId);
}
__name(handleUpdateSeries, "handleUpdateSeries");
__name2(handleUpdateSeries, "handleUpdateSeries");
async function handleDeleteSeries(env, id) {
  return handleDelete(env, "series", id, isValidSeriesId);
}
__name(handleDeleteSeries, "handleDeleteSeries");
__name2(handleDeleteSeries, "handleDeleteSeries");
async function handleListGames(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "games", ["steamId", "exeName"], search, page, pageSize);
}
__name(handleListGames, "handleListGames");
__name2(handleListGames, "handleListGames");
async function handleGetGame(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "games", id, isValidGameId);
}
__name(handleGetGame, "handleGetGame");
__name2(handleGetGame, "handleGetGame");
// ─── Autofill game metadata from Steam (admin panel button) ────────────
// Body: { steamId }. Fills the FORM (panel saves via normal PUT).
// Steam key is read ONLY from the server secret (wrangler secret put
// STEAM_API_KEY) — never from code, never from the client.
function cleanSteamText(s) {
  return String(s || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}
__name(cleanSteamText, "cleanSteamText");
__name2(cleanSteamText, "cleanSteamText");
async function fetchSteamCatalogName(env, steamId) {
  // Single-id lookup via paging trick: first app above (steamId-1).
  const key = env.STEAM_API_KEY;
  if (!key) return null;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 12000);
    const res = await fetch(
      "https://api.steampowered.com/IStoreService/GetAppList/v1/?key=" + encodeURIComponent(key) +
      "&include_games=1&max_results=1&last_appid=" + (Number(steamId) - 1),
      { signal: ctrl.signal, headers: { Accept: "application/json" } }
    ).finally(() => clearTimeout(t));
    if (!res.ok) return null;
    const body = await res.json();
    const first = body?.response?.apps?.[0];
    if (first && String(first.appid) === String(steamId)) return first.name || null;
    return null;
  } catch {
    return null;
  }
}
__name(fetchSteamCatalogName, "fetchSteamCatalogName");
__name2(fetchSteamCatalogName, "fetchSteamCatalogName");
async function handleAutofillGame(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400);
  }
  const steamIdRaw = String(body?.steamId || "").trim();
  // Accept Arabic-Indic / Persian / fullwidth digits too (admin keyboards).
  const steamIdNorm = steamIdRaw
    .replace(/[٠-٩]/g, d => '0123456789'['٠١٢٣٤٥٦٧٨٩'.indexOf(d)])
    .replace(/[۰-۹]/g, d => '0123456789'['۰۱۲۳۴۵۶۷۸۹'.indexOf(d)])
    .replace(/[０-９]/g, d => String('０１２３４５６７８９'.indexOf(d)));
  const steamIdDigits = (steamIdNorm.match(/\d+/g) || []).join("");
  const steamId = steamIdDigits;
  if (!/^\d+$/.test(steamId)) {
    return jsonResponse({ error: "invalid_steam_id" }, 400);
  }
  let d = null;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    const res = await fetch(
      "https://store.steampowered.com/api/appdetails?appids=" + encodeURIComponent(steamId) + "&l=en",
      { signal: ctrl.signal, headers: { Accept: "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" } }
    ).finally(() => clearTimeout(t));
    if (res.ok) {
      const payload = await res.json();
      const app = payload?.[steamId];
      if (app && app.success === true && app.data) d = app.data;
    }
  } catch {
    d = null;
  }
  if (!d) {
    return jsonResponse({ error: "steam_unavailable" }, 502);
  }
  let name = d.name || null;
  if (!name) {
    name = await fetchSteamCatalogName(env, steamId);
  }
  if (!name) {
    return jsonResponse({ error: "steam_refused" }, 502);
  }
  const minReq = d.pc_requirements?.minimum || "";
  const sizeMatch = minReq.match(/(\d+)\s*GB/i);
  const fields = {
    name,
    cover: d.header_image || "",
    short_desc: cleanSteamText(d.short_description),
    genres: JSON.stringify((d.genres || []).map((g) => g.description)),
    developers: JSON.stringify(d.developers || []),
    publishers: JSON.stringify(d.publishers || []),
    released: d.release_date?.date || "",
    metacritic: d.metacritic?.score ?? null,
    screenshots: JSON.stringify((d.screenshots || []).slice(0, 5).map((s) => s.path_full)),
    pc_min: cleanSteamText(d.pc_requirements?.minimum),
    pc_rec: cleanSteamText(d.pc_requirements?.recommended),
    size_text: sizeMatch ? sizeMatch[1] + " GB" : "",
    logo: "https://cdn.akamai.steamstatic.com/steam/apps/" + steamId + "/logo.png",
    hero: "https://cdn.akamai.steamstatic.com/steam/apps/" + steamId + "/hero_capsule.jpg",
    page_bg: d.background_raw || d.background || "",
  };
  return jsonResponse({ success: true, fields });
}
__name(handleAutofillGame, "handleAutofillGame");
__name2(handleAutofillGame, "handleAutofillGame");
async function handleCreateGame(request, env) {
  return handleCreate(request, env, "games", ["steamId", "bypass", "onlineFix", "steamtools", "gameplay", "exeName", "download"], isValidGameId);
}
__name(handleCreateGame, "handleCreateGame");
__name2(handleCreateGame, "handleCreateGame");
async function handleUpdateGame(request, env) {
  return handleUpdate(request, env, "games", ["id", "steamId", "bypass", "onlineFix", "steamtools", "gameplay", "exeName", "download", "name", "cover", "short_desc", "genres", "developers", "publishers", "released", "metacritic", "screenshots", "pc_min", "pc_rec", "size_text", "trailer", "logo", "hero", "page_bg", "steam_synced_at"], isValidGameId);
}
__name(handleUpdateGame, "handleUpdateGame");
__name2(handleUpdateGame, "handleUpdateGame");
async function handleDeleteGame(env, id) {
  return handleDelete(env, "games", id, isValidGameId);
}
__name(handleDeleteGame, "handleDeleteGame");
__name2(handleDeleteGame, "handleDeleteGame");
async function handleListLiveStreams(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "live_streams", ["id", "name", "url"], search, page, pageSize);
}
__name(handleListLiveStreams, "handleListLiveStreams");
__name2(handleListLiveStreams, "handleListLiveStreams");
async function handleGetLiveStream(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "live_streams", id, isValidLiveStreamId);
}
__name(handleGetLiveStream, "handleGetLiveStream");
__name2(handleGetLiveStream, "handleGetLiveStream");
async function handleCreateLiveStream(request, env) {
  return handleCreate(request, env, "live_streams", ["id", "name", "url"], isValidLiveStreamId);
}
__name(handleCreateLiveStream, "handleCreateLiveStream");
__name2(handleCreateLiveStream, "handleCreateLiveStream");
async function handleUpdateLiveStream(request, env) {
  return handleUpdate(request, env, "live_streams", ["id", "name", "url"], isValidLiveStreamId);
}
__name(handleUpdateLiveStream, "handleUpdateLiveStream");
__name2(handleUpdateLiveStream, "handleUpdateLiveStream");
async function handleDeleteLiveStream(env, id) {
  return handleDelete(env, "live_streams", id, isValidLiveStreamId);
}
__name(handleDeleteLiveStream, "handleDeleteLiveStream");
__name2(handleDeleteLiveStream, "handleDeleteLiveStream");
async function handleListPcApps(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "pc_apps", ["name", "description", "version", "exeName"], search, page, pageSize);
}
__name(handleListPcApps, "handleListPcApps");
__name2(handleListPcApps, "handleListPcApps");
async function handleGetPcApp(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "pc_apps", id, isValidPcAppId);
}
__name(handleGetPcApp, "handleGetPcApp");
__name2(handleGetPcApp, "handleGetPcApp");
async function handleCreatePcApp(request, env) {
  return handleCreate(request, env, "pc_apps", ["name", "description", "version", "images", "url", "fileSize"], isValidPcAppId);
}
__name(handleCreatePcApp, "handleCreatePcApp");
__name2(handleCreatePcApp, "handleCreatePcApp");
async function handleUpdatePcApp(request, env) {
  return handleUpdate(request, env, "pc_apps", ["id", "name", "description", "version", "images", "url", "fileSize"], isValidPcAppId);
}
__name(handleUpdatePcApp, "handleUpdatePcApp");
__name2(handleUpdatePcApp, "handleUpdatePcApp");
async function handleDeletePcApp(env, id) {
  return handleDelete(env, "pc_apps", id, isValidPcAppId);
}
__name(handleDeletePcApp, "handleDeletePcApp");
__name2(handleDeletePcApp, "handleDeletePcApp");
async function handleListPlugins(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "plugins", ["name", "description", "version", "exeName"], search, page, pageSize);
}
__name(handleListPlugins, "handleListPlugins");
__name2(handleListPlugins, "handleListPlugins");
async function handleGetPlugin(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "plugins", id, isValidPluginId);
}
__name(handleGetPlugin, "handleGetPlugin");
__name2(handleGetPlugin, "handleGetPlugin");
async function handleCreatePlugin(request, env) {
  return handleCreate(request, env, "plugins", ["name", "description", "version", "images", "url", "fileSize", "exeName"], isValidPluginId);
}
__name(handleCreatePlugin, "handleCreatePlugin");
__name2(handleCreatePlugin, "handleCreatePlugin");
async function handleUpdatePlugin(request, env) {
  return handleUpdate(request, env, "plugins", ["id", "name", "description", "version", "images", "url", "fileSize", "exeName"], isValidPluginId);
}
__name(handleUpdatePlugin, "handleUpdatePlugin");
__name2(handleUpdatePlugin, "handleUpdatePlugin");
async function handleDeletePlugin(env, id) {
  return handleDelete(env, "plugins", id, isValidPluginId);
}
__name(handleDeletePlugin, "handleDeletePlugin");
__name2(handleDeletePlugin, "handleDeletePlugin");
async function handleListAffiliateProducts(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "affiliate_products", ["id", "name", "url"], search, page, pageSize);
}
__name(handleListAffiliateProducts, "handleListAffiliateProducts");
__name2(handleListAffiliateProducts, "handleListAffiliateProducts");
async function handleGetAffiliateProduct(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "affiliate_products", id, isValidAffiliateProductId);
}
__name(handleGetAffiliateProduct, "handleGetAffiliateProduct");
__name2(handleGetAffiliateProduct, "handleGetAffiliateProduct");
async function handleCreateAffiliateProduct(request, env) {
  return handleCreate(request, env, "affiliate_products", ["id", "name", "url"], isValidAffiliateProductId);
}
__name(handleCreateAffiliateProduct, "handleCreateAffiliateProduct");
__name2(handleCreateAffiliateProduct, "handleCreateAffiliateProduct");
async function handleUpdateAffiliateProduct(request, env) {
  return handleUpdate(request, env, "affiliate_products", ["id", "name", "url"], isValidAffiliateProductId);
}
__name(handleUpdateAffiliateProduct, "handleUpdateAffiliateProduct");
__name2(handleUpdateAffiliateProduct, "handleUpdateAffiliateProduct");
async function handleDeleteAffiliateProduct(env, id) {
  return handleDelete(env, "affiliate_products", id, isValidAffiliateProductId);
}
__name(handleDeleteAffiliateProduct, "handleDeleteAffiliateProduct");
__name2(handleDeleteAffiliateProduct, "handleDeleteAffiliateProduct");
async function handleListLicenses(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "licenses", ["id", "username", "email", "key", "biosId"], search, page, pageSize);
}
__name(handleListLicenses, "handleListLicenses");
__name2(handleListLicenses, "handleListLicenses");
async function handleGetLicense(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "licenses", id, isValidLicenseId);
}
__name(handleGetLicense, "handleGetLicense");
__name2(handleGetLicense, "handleGetLicense");
async function handleCreateLicense(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400);
  }
  const { id, username, email, key, createdAt, expiryDate, devices, biosId } = body;
  if (!id || String(id).trim() === "" || !username || String(username).trim() === "" || !key || String(key).trim() === "" || !createdAt || String(createdAt).trim() === "" || !expiryDate || String(expiryDate).trim() === "" || devices === void 0 || devices === null) {
    return jsonResponse({ error: "missing_required_fields" }, 400);
  }
  if (!await isValidLicenseId(env, id)) {
    const existing = await env.DB.prepare("SELECT id FROM licenses WHERE id = ?").bind(id).first();
    if (existing) return jsonResponse({ error: "id_already_exists" }, 409);
  }
  const result = await env.DB.prepare(
    "INSERT INTO licenses (id, username, email, key, createdAt, expiryDate, devices, biosId) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(String(id), String(username), email ? String(email) : null, String(key), String(createdAt), String(expiryDate), Number(devices), biosId ? String(biosId) : null).run();
  if (!result.success) {
    return jsonResponse({ error: "insert_failed" }, 500);
  }
  return jsonResponse({ success: true, id });
}
__name(handleCreateLicense, "handleCreateLicense");
__name2(handleCreateLicense, "handleCreateLicense");
async function handleUpdateLicense(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400);
  }
  const id = body.id;
  if (!id || !await isValidLicenseId(env, id)) {
    return jsonResponse({ error: "not_found" }, 404);
  }
  const allowedFields = ["username", "email", "key", "createdAt", "expiryDate", "devices", "biosId"];
  const updates = allowedFields.filter((c) => body[c] !== void 0);
  if (updates.length === 0) {
    return jsonResponse({ error: "no_fields_to_update" }, 400);
  }
  const setClause = updates.map((c) => `${c} = ?`).join(", ");
  const values = updates.map((c) => body[c]);
  values.push(id);
  const result = await env.DB.prepare(
    `UPDATE licenses SET ${setClause} WHERE id = ?`
  ).bind(...values).run();
  if (result.meta.changes === 0) {
    return jsonResponse({ error: "not_found" }, 404);
  }
  return jsonResponse({ success: true, id });
}
__name(handleUpdateLicense, "handleUpdateLicense");
__name2(handleUpdateLicense, "handleUpdateLicense");
async function handleDeleteLicense(env, id) {
  return handleDelete(env, "licenses", id, isValidLicenseId);
}
__name(handleDeleteLicense, "handleDeleteLicense");
__name2(handleDeleteLicense, "handleDeleteLicense");
async function handleListUpdates(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "updates", ["id", "name", "version", "url"], search, page, pageSize);
}
__name(handleListUpdates, "handleListUpdates");
__name2(handleListUpdates, "handleListUpdates");
async function handleGetLatestUpdate(request, env) {
  const { results } = await env.DB.prepare(
    "SELECT id, name, version, url FROM updates ORDER BY version DESC LIMIT 1"
  ).all();
  const latest = results[0] || null;
  return jsonResponse({ latest });
}
__name(handleGetLatestUpdate, "handleGetLatestUpdate");
__name2(handleGetLatestUpdate, "handleGetLatestUpdate");
async function handleGetUpdate(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "updates", id, isValidUpdateId);
}
__name(handleGetUpdate, "handleGetUpdate");
__name2(handleGetUpdate, "handleGetUpdate");
async function handleCreateUpdate(request, env) {
  return handleCreate(request, env, "updates", ["id", "name", "version", "url"], isValidUpdateId);
}
__name(handleCreateUpdate, "handleCreateUpdate");
__name2(handleCreateUpdate, "handleCreateUpdate");
async function handleUpdateUpdate(request, env) {
  return handleUpdate(request, env, "updates", ["id", "name", "version", "url"], isValidUpdateId);
}
__name(handleUpdateUpdate, "handleUpdateUpdate");
__name2(handleUpdateUpdate, "handleUpdateUpdate");
async function handleDeleteUpdate(env, id) {
  return handleDelete(env, "updates", id, isValidUpdateId);
}
__name(handleDeleteUpdate, "handleDeleteUpdate");
__name2(handleDeleteUpdate, "handleDeleteUpdate");
async function handleListConfigs(request, env) {
  const url = new URL(request.url);
  const search = url.searchParams.get("search") || "";
  const page = parseInt(url.searchParams.get("page") || "1");
  const pageSize = parseInt(url.searchParams.get("pageSize") || "50");
  return handleList(env, "config", ["id", "github_url", "version"], search, page, pageSize);
}
__name(handleListConfigs, "handleListConfigs");
__name2(handleListConfigs, "handleListConfigs");
async function handleGetConfig(request, env) {
  const url = new URL(request.url);
  const id = url.pathname.split("/").pop();
  return handleGet(env, "config", id, isValidConfigId);
}
__name(handleGetConfig, "handleGetConfig");
__name2(handleGetConfig, "handleGetConfig");
async function handleCreateConfig(request, env) {
  return handleCreate(request, env, "config", ["id", "github_url", "version", "updated_at"], isValidConfigId);
}
__name(handleCreateConfig, "handleCreateConfig");
__name2(handleCreateConfig, "handleCreateConfig");
async function handleUpdateConfig(request, env) {
  return handleUpdate(request, env, "config", ["id", "github_url", "version", "updated_at"], isValidConfigId);
}
__name(handleUpdateConfig, "handleUpdateConfig");
__name2(handleUpdateConfig, "handleUpdateConfig");
async function handleDeleteConfig(env, id) {
  return handleDelete(env, "config", id, isValidConfigId);
}
__name(handleDeleteConfig, "handleDeleteConfig");
__name2(handleDeleteConfig, "handleDeleteConfig");
async function handleDashboardStats(env) {
  const tables = [
    "movies",
    "series",
    "games",
    "live_streams",
    "pc_apps",
    "plugins",
    "affiliate_products",
    "licenses",
    "updates",
    "config"
  ];
  const stats = {};
  for (const table of tables) {
    try {
      const { results } = await env.DB.prepare(`SELECT COUNT(*) as count FROM ${table}`).all();
      stats[table] = results[0]?.count || 0;
    } catch {
      stats[table] = 0;
    }
  }
  try {
    const { results: expired } = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM licenses WHERE expiryDate < datetime('now')"
    ).all();
    stats.expired_licenses = expired[0]?.count || 0;
  } catch {
    stats.expired_licenses = 0;
  }
  return jsonResponse({ stats });
}
__name(handleDashboardStats, "handleDashboardStats");
__name2(handleDashboardStats, "handleDashboardStats");
async function handlePaymentStats(request, env) {
  const url = new URL(request.url);
  const search = (url.searchParams.get("search") || "").trim();
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(url.searchParams.get("pageSize") || "20", 10) || 20));
  const offset = (page - 1) * pageSize;
  const whereClauses = [];
  const params = [];
  if (search) {
    whereClauses.push("(captureId LIKE ? OR orderId LIKE ? OR planKey LIKE ? OR buyerEmail LIKE ? OR license_id LIKE ?)");
    const like = `%${search}%`;
    params.push(like, like, like, like, like);
  }
  const whereSql = whereClauses.length ? `WHERE ${whereClauses.join(" AND ")}` : "";
  const totalRow = await env.DB.prepare(`SELECT COUNT(*) as total FROM payment_events ${whereSql}`).bind(...params).first();
  const total = totalRow?.total || 0;
  const rows = await env.DB.prepare(
    `SELECT captureId, orderId, planKey, amount, buyerEmail, license_id, status, createdAt
     FROM payment_events
     ${whereSql}
     ORDER BY datetime(createdAt) DESC
     LIMIT ? OFFSET ?`
  ).bind(...params, pageSize, offset).all();
  const summary = await env.DB.prepare(
    `SELECT 
      COUNT(*) as totalPayments,
      SUM(amount) as totalRevenue,
      AVG(amount) as avgOrderValue,
      COUNT(CASE WHEN status IN ('CAPTURED','VERIFIED','LICENSE_ISSUED') THEN 1 END) as successfulPayments,
      COUNT(CASE WHEN status IN ('CREATED','APPROVED') THEN 1 END) as pendingPayments,
      COUNT(CASE WHEN status IN ('FAILED','REFUNDED','REVERSED','DISPUTED') THEN 1 END) as failedPayments,
      COUNT(CASE WHEN date(createdAt) = date('now') THEN 1 END) as todayPayments,
      COUNT(CASE WHEN strftime('%Y-%m', createdAt) = strftime('%Y-%m', 'now') THEN 1 END) as monthPayments
    FROM payment_events`
  ).first();
  const byStatus = await env.DB.prepare(
    `SELECT status, COUNT(*) as count, SUM(amount) as revenue
     FROM payment_events
     GROUP BY status`
  ).all();
  const byPlan = await env.DB.prepare(
    `SELECT planKey, COUNT(*) as count, SUM(amount) as revenue
     FROM payment_events
     GROUP BY planKey
     ORDER BY revenue DESC`
  ).all();
  const topBuyers = await env.DB.prepare(
    `SELECT buyerEmail, COUNT(*) as count, SUM(amount) as totalSpent
     FROM payment_events
     WHERE buyerEmail IS NOT NULL
     GROUP BY buyerEmail
     ORDER BY totalSpent DESC
     LIMIT 20`
  ).all();
  return jsonResponse({
    summary,
    byStatus: byStatus.results || [],
    byPlan: byPlan.results || [],
    topBuyers: topBuyers.results || [],
    items: rows.results || [],
    total,
    page,
    pageSize,
    totalPages: Math.ceil(total / pageSize)
  });
}
__name(handlePaymentStats, "handlePaymentStats");
__name2(handlePaymentStats, "handlePaymentStats");
async function handleGetUploadUrl(request, env) {
  try {
    let body;
    try { body = await request.json(); } catch { return jsonResponse({ error: "invalid_body" }, 400); }
    const { filename, contentType } = body || {};
    if (!filename || typeof filename !== "string") {
      return jsonResponse({ error: "missing_filename" }, 400);
    }
    const safeFilename = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
    const key = new Date().toISOString().slice(0, 10) + "-" + generateUUID().slice(0, 8) + "-" + safeFilename;
    const accountId = env.R2_ACCOUNT_ID;
    const accessKeyId = env.R2_ACCESS_KEY_ID;
    const secretAccessKey = env.R2_SECRET_ACCESS_KEY;
    const publicBaseUrl = env.R2_PUBLIC_BASE_URL;
    if (!accountId || !accessKeyId || !secretAccessKey || !publicBaseUrl) {
      return jsonResponse({ error: "missing_r2_config" }, 500);
    }
    console.log("calling generatePresignedPutUrl:", { bucket: "veltrix32-assets", key });
    const presigned = await generatePresignedPutUrl("veltrix32-assets", key, env, contentType || "application/zip");
    return jsonResponse({ uploadUrl: presigned.uploadUrl, publicUrl: presigned.publicUrl, key: key }, 200, { "Cache-Control": "no-store" });
  } catch (e) {
    console.error("handleGetUploadUrl error:", e);
    return jsonResponse({ error: "internal_error", message: e.message || String(e) }, 500);
  }
}
__name(handleGetUploadUrl, "handleGetUploadUrl");
__name2(handleGetUploadUrl, "handleGetUploadUrl");
async function cryptoTest(request, env) {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode("hello world");
    const hash = await crypto.subtle.digest("SHA-256", data);
    const arr = Array.from(new Uint8Array(hash));
    const hex = arr.map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
    const key = await crypto.subtle.importKey('raw', encoder.encode('test-key'), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    const sigHex = Array.from(new Uint8Array(sig)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
    return jsonResponse({ sha256: hex, hmac: sigHex, status: 'ok' }, 200);
  } catch (e) {
    console.error("cryptoTest error:", e);
    return jsonResponse({ error: String(e) }, 500);
  }
}
__name(cryptoTest, "cryptoTest");
__name2(cryptoTest, "cryptoTest");

// HMAC returning raw bytes for intermediate derivation steps
async function hmacSha256(key, message) {
  let keyData = key;
  if (typeof key === 'string') { keyData = new TextEncoder().encode(key); }
  const cryptoKey = await crypto.subtle.importKey('raw', keyData, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  return await crypto.subtle.sign('HMAC', cryptoKey, message);
}

// HMAC returning hex string — final signature only
async function hmacSha256HexFromRaw(key, message) {
  const raw = await hmacSha256(key, message);
  return hexEncode(new Uint8Array(raw));
}
__name(hmacSha256, "hmacSha256");
__name2(hmacSha256, "hmacSha256");
__name(hmacSha256HexFromRaw, "hmacSha256HexFromRaw");
__name2(hmacSha256HexFromRaw, "hmacSha256HexFromRaw");

async function generatePresignedPutUrl(bucket, key, env, contentType) {
  try {
    const accountId = env.R2_ACCOUNT_ID;
    const accessKeyId = env.R2_ACCESS_KEY_ID;
    const secretAccessKey = env.R2_SECRET_ACCESS_KEY;
    console.log("env check:", { accountIdLen: accountId?.length, accessKeyLen: accessKeyId?.length, secretLen: secretAccessKey?.length });
    const region = "auto";
    const service = "s3";
    const expiry = 900;
    const now = new Date();
    const amzDate = now.toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
    const dateStamp = amzDate.slice(0, 8);
    const host = accountId + ".r2.cloudflarestorage.com";
    const endpoint = "https://" + host;
    const canonicalUri = "/" + uriEncode(bucket) + "/" + uriEncode(key);
    const ct = contentType || "application/octet-stream";
    const signedHeaders = "content-type;host";
    const payloadHash = "UNSIGNED-PAYLOAD";
    const queryParams = {
      "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
      "X-Amz-Credential": accessKeyId + "/" + dateStamp + "/" + region + "/" + service + "/aws4_request",
      "X-Amz-Date": amzDate,
      "X-Amz-Expires": expiry.toString(),
      "X-Amz-SignedHeaders": signedHeaders
    };
    const sortedKeys = Object.keys(queryParams).sort();
    const canonicalQueryString = sortedKeys.map(function (k) { return uriEncode(k) + "=" + uriEncode(queryParams[k]); }).join("&");
    const canonicalHeaders = "content-type:" + ct + "\nhost:" + host + "\n";
    const canonicalRequest = ["PUT", canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash].join("\n");
    const canonicalRequestHash = await sha256Hex(new TextEncoder().encode(canonicalRequest));
    const stringToSign = ["AWS4-HMAC-SHA256", amzDate, dateStamp + "/" + region + "/" + service + "/aws4_request", canonicalRequestHash].join("\n");

    // AWS Sig V4 key derivation — intermediate steps need raw bytes
    const kDate    = await hmacSha256(new TextEncoder().encode("AWS4" + secretAccessKey), new TextEncoder().encode(dateStamp));
    const kRegion  = await hmacSha256(kDate,  new TextEncoder().encode(region));
    const kService = await hmacSha256(kRegion, new TextEncoder().encode(service));
    const kSigning = await hmacSha256(kService, new TextEncoder().encode("aws4_request"));
    const signature = await hmacSha256HexFromRaw(kSigning, new TextEncoder().encode(stringToSign));

    const queryString = canonicalQueryString + "&X-Amz-Signature=" + uriEncode(signature);
    const uploadUrl = endpoint + canonicalUri + "?" + queryString;
    const publicUrl = env.R2_PUBLIC_BASE_URL + "/" + uriEncode(key);
    return { uploadUrl: uploadUrl, publicUrl: publicUrl };
  } catch (e) {
    console.error("generatePresignedPutUrl error at:", e.stack || e.message || String(e));
    throw e;
  }
}
__name(generatePresignedPutUrl, "generatePresignedPutUrl");
__name2(generatePresignedPutUrl, "generatePresignedPutUrl");
function adminPanelHtml() {
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex, nofollow" />
<title>Veltrix37 \u2014 Administration Panel</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, "Segoe UI", Tahoma, Arial, sans-serif;
    background: #0f1115; color: #e6e6e6; min-height: 100vh;
  }
  
  /* Login Screen */
  .login-screen {
    min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px;
  }
  .login-card {
    background: #171a21; border: 1px solid #262a33; border-radius: 12px;
    padding: 32px; width: 100%; max-width: 420px;
  }
  .login-card h1 { font-size: 20px; margin-bottom: 24px; text-align: center; }
  .login-card label { display: block; font-size: 13px; color: #9aa0aa; margin-bottom: 6px; }
  .login-card input {
    width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid #2c3038;
    background: #0f1115; color: #e6e6e6; font-size: 14px; margin-bottom: 16px;
  }
  .login-card button {
    width: 100%; padding: 10px 12px; border-radius: 8px; border: none;
    background: #4f7cff; color: white; font-size: 14px; cursor: pointer;
  }
  .login-card button:hover { background: #3d68e6; }
  .login-error { color: #ff6b6b; font-size: 13px; margin-bottom: 12px; min-height: 16px; text-align: center; }
  
  /* Main App Layout */
  .app { display: none; min-height: 100vh; }
  .app.active { display: flex; }
  
  /* Sidebar */
  .sidebar {
    width: 250px; background: #14161c; border-left: 1px solid #262a33;
    padding: 20px 0; flex-shrink: 0; height: 100vh; position: sticky; top: 0;
    overflow-y: auto;
  }
  .sidebar-header {
    padding: 0 20px 20px; border-bottom: 1px solid #262a33; margin-bottom: 20px;
  }
  .sidebar-header h2 { font-size: 16px; color: #4f7cff; }
  .sidebar-header p { font-size: 12px; color: #9aa0aa; margin-top: 4px; }
  .sidebar-nav { list-style: none; }
  .sidebar-nav li { margin: 2px 0; }
  .sidebar-nav a {
    display: flex; align-items: center; gap: 10px; padding: 10px 20px;
    color: #b0b0b0; text-decoration: none; font-size: 14px;
    border-right: 3px solid transparent; transition: all 0.15s;
  }
  .sidebar-nav a:hover { background: #1c1f27; color: #fff; }
  .sidebar-nav a.active { background: #1c1f27; color: #4f7cff; border-right-color: #4f7cff; }
  .sidebar-nav a .icon { font-size: 16px; width: 20px; text-align: center; }
  
  /* Main Content */
  .main { flex: 1; padding: 0; overflow-x: hidden; }
  .topbar {
    background: #14161c; border-bottom: 1px solid #262a33; padding: 16px 24px;
    display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 10;
  }
  .topbar h1 { font-size: 18px; }
  .topbar-actions { display: flex; gap: 10px; align-items: center; }
  .btn {
    padding: 8px 16px; border-radius: 6px; border: none; font-size: 13px;
    cursor: pointer; transition: all 0.15s; display: inline-flex; align-items: center; gap: 6px;
  }
  .btn-primary { background: #4f7cff; color: white; }
  .btn-primary:hover { background: #3d68e6; }
  .btn-secondary { background: #2c3038; color: #e6e6e6; }
  .btn-secondary:hover { background: #3a3f4a; }
  .btn-danger { background: #dc3545; color: white; }
  .btn-danger:hover { background: #c82333; }
  .btn-sm { padding: 5px 10px; font-size: 12px; }
  
  .content { padding: 24px; }
  
  /* Dashboard Cards */
  .stats-grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 16px; margin-bottom: 30px;
  }
  .stat-card {
    background: #171a21; border: 1px solid #262a33; border-radius: 10px;
    padding: 20px; transition: transform 0.15s;
  }
  .stat-card:hover { transform: translateY(-2px); }
  .stat-card .label { font-size: 12px; color: #9aa0aa; margin-bottom: 8px; text-transform: uppercase; }
  .stat-card .value { font-size: 28px; font-weight: bold; color: #4f7cff; }
  .stat-card.warning .value { color: #ff6b6b; }
  
  /* Data Table */
  .table-container {
    background: #171a21; border: 1px solid #262a33; border-radius: 10px;
    overflow-x: auto; margin-top: 16px;
  }
  .table-header {
    padding: 16px; display: flex; justify-content: space-between; align-items: center;
    border-bottom: 1px solid #262a33; gap: 12px; flex-wrap: wrap;
  }
  .table-header h3 { font-size: 15px; }
  .search-box {
    padding: 8px 12px; border-radius: 6px; border: 1px solid #2c3038;
    background: #0f1115; color: #e6e6e6; font-size: 13px; min-width: 200px;
  }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 12px 16px; text-align: right; font-size: 13px; border-bottom: 1px solid #232730; }
  td.cell-truncate {
    max-width: 280px; overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap; cursor: help;
  }
  th { background: #1c1f27; color: #9aa0aa; font-weight: 600; font-size: 12px; text-transform: uppercase; }
  tr:hover td { background: #1c1f27; }
  tr:last-child td { border-bottom: none; }
  .table-actions { display: flex; gap: 6px; }
  .table-empty { padding: 40px; text-align: center; color: #9aa0aa; }
  .table-loading { padding: 40px; text-align: center; color: #9aa0aa; }
  .table-error { padding: 20px; text-align: center; color: #ff6b6b; }
  .badge { padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .badge.success { background: rgba(53, 196, 107, 0.15); color: #35c46b; }
  .badge.danger { background: rgba(220, 53, 69, 0.15); color: #dc3545; }
  .badge.warning { background: rgba(255, 193, 7, 0.15); color: #ffc107; }
  .upload-field { border: 1px dashed #3b3f4a; border-radius: 8px; padding: 10px; margin-bottom: 8px; }
  .upload-mode-toggle { display: flex; gap: 12px; margin-bottom: 8px; font-size: 13px; }
  .upload-mode-toggle label { cursor: pointer; display: flex; align-items: center; gap: 4px; }
  .upload-url-wrap { display: flex; gap: 8px; align-items: center; }
  .upload-url-wrap input[type="text"] { flex: 1; }
  .upload-zip-wrap { display: none; gap: 8px; align-items: center; flex-wrap: wrap; }
  .upload-field.upload-zip-mode .upload-zip-wrap { display: flex; }
  .upload-field.upload-zip-mode .upload-url-wrap input[type="text"] { pointer-events: none; background: #1c1f27; }
  .select-file-btn { padding: 10px 14px; white-space: nowrap; }
  .upload-btn[disabled] { opacity: 0.5; cursor: not-allowed; }
  .upload-btn:not([disabled]) { cursor: pointer; }
  
  /* Pagination */
  .pagination {
    padding: 12px 16px; display: flex; justify-content: space-between; align-items: center;
    border-top: 1px solid #262a33; font-size: 13px; color: #9aa0aa;
  }
  .pagination-buttons { display: flex; gap: 6px; }
  .pagination button {
    padding: 5px 10px; border-radius: 4px; border: 1px solid #2c3038;
    background: #0f1115; color: #e6e6e6; cursor: pointer; font-size: 12px;
  }
  .pagination button:hover:not(:disabled) { background: #2c3038; }
  .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
  
  /* Modal */
  .modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100;
    display: none; align-items: center; justify-content: center; padding: 20px;
  }
  .modal-overlay.active { display: flex; }
  .modal {
    background: #171a21; border: 1px solid #262a33; border-radius: 12px;
    width: 100%; max-width: 500px; max-height: 90vh; overflow-y: auto;
  }
  .modal-header {
    padding: 20px; border-bottom: 1px solid #262a33;
    display: flex; justify-content: space-between; align-items: center;
  }
  .modal-header h3 { font-size: 16px; }
  .modal-close {
    background: none; border: none; color: #9aa0aa; font-size: 20px;
    cursor: pointer; padding: 0; line-height: 1;
  }
  .modal-body { padding: 20px; }
  .modal-footer {
    padding: 16px 20px; border-top: 1px solid #262a33;
    display: flex; justify-content: flex-end; gap: 10px;
  }
  
  /* Form */
  .form-group { margin-bottom: 16px; }
  .form-group label {
    display: block; font-size: 13px; color: #9aa0aa; margin-bottom: 6px;
  }
  .form-group input, .form-group select, .form-group textarea {
    width: 100%; padding: 10px 12px; border-radius: 6px; border: 1px solid #2c3038;
    background: #0f1115; color: #e6e6e6; font-size: 14px; font-family: inherit;
  }
  .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
    outline: none; border-color: #4f7cff;
  }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .required { color: #ff6b6b; }
  
  /* Toast */
  .toast-container {
    position: fixed; top: 20px; left: 20px; z-index: 200;
    display: flex; flex-direction: column; gap: 10px;
  }
  .toast {
    background: #171a21; border: 1px solid #262a33; border-radius: 8px;
    padding: 12px 20px; font-size: 14px; min-width: 250px;
    display: flex; align-items: center; gap: 10px;
    animation: slideIn 0.2s ease;
  }
  .toast.success { border-right: 3px solid #35c46b; }
  .toast.error { border-right: 3px solid #ff6b6b; }
  .toast.info { border-right: 3px solid #4f7cff; }
  @keyframes slideIn { from { transform: translateX(-100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
  
  /* Section */
  .section { display: none; }
  .section.active { display: block; }
  
  /* Responsive */
  @media (max-width: 768px) {
    .sidebar { width: 60px; }
    .sidebar-header h2, .sidebar-header p, .sidebar-nav a span:not(.icon) { display: none; }
    .form-row { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<!-- Login Screen -->
<div class="login-screen" id="loginScreen">
  <div class="login-card">
    <h1>Veltrix37 \u2014 \u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644</h1>
    <div class="login-error" id="loginError"></div>
    <label for="password">\u0643\u0644\u0645\u0629 \u0645\u0631\u0648\u0631 \u0627\u0644\u0625\u062F\u0627\u0631\u0629</label>
    <input type="password" id="password" autocomplete="current-password" />
    <button id="loginBtn">\u062F\u062E\u0648\u0644</button>
  </div>
</div>

<!-- Main App -->
<div class="app" id="mainApp">
  <aside class="sidebar">
    <div class="sidebar-header">
      <h2>Veltrix37</h2>
      <p>Administration Panel</p>
    </div>
    <ul class="sidebar-nav">
      <li><a href="#dashboard" class="nav-link active" data-section="dashboard"><span class="icon">\u{1F4CA}</span><span>Dashboard</span></a></li>
      <li><a href="#payment-stats" class="nav-link" data-section="payment-stats"><span class="icon">\u{1F4B3}</span><span>Payment Stats</span></a></li>
      <li><a href="#series" class="nav-link" data-section="series"><span class="icon">\u{1F4FA}</span><span>Series</span></a></li>
      <li><a href="#games" class="nav-link" data-section="games"><span class="icon">\u{1F3AE}</span><span>Games</span></a></li>
      <li><a href="#live-streams" class="nav-link" data-section="live-streams"><span class="icon">\u{1F4E1}</span><span>Live Streams</span></a></li>
      <li><a href="#pc-apps" class="nav-link" data-section="pc-apps"><span class="icon">\u{1F4BB}</span><span>PC Apps</span></a></li>
      <li><a href="#plugins" class="nav-link" data-section="plugins"><span class="icon">\u{1F50C}</span><span>Plugins</span></a></li>
      <li><a href="#affiliate" class="nav-link" data-section="affiliate"><span class="icon">\u{1F6D2}</span><span>Affiliate Products</span></a></li>
      <li><a href="#licenses" class="nav-link" data-section="licenses"><span class="icon">\u{1F511}</span><span>Licenses</span></a></li>
      <li><a href="#updates" class="nav-link" data-section="updates"><span class="icon">\u{1F504}</span><span>Updates</span></a></li>
      <li><a href="#config" class="nav-link" data-section="config"><span class="icon">\u26A1</span><span>Config</span></a></li>
    </ul>
  </aside>
  
  <main class="main">
    <div class="topbar">
      <h1 id="sectionTitle">Dashboard</h1>
      <div class="topbar-actions">
        <button class="btn btn-secondary" id="logoutBtn">\u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062E\u0631\u0648\u062C</button>
      </div>
    </div>
    
    <div class="content">
      <!-- Dashboard Section -->
      <div class="section active" id="section-dashboard">
        <div class="stats-grid" id="statsGrid">
          <div class="stat-card"><div class="label">Loading...</div><div class="value">\u2014</div></div>
        </div>
      </div>
      
      <!-- Generic CRUD Sections -->
      <div class="section" id="section-movies">
        <div class="table-container">
          <div class="table-header">
            <h3>Movies</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="movies" />
              <button class="btn btn-primary" data-action="add" data-section="movies">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-movies"></div>
        </div>
      </div>
      
      <div class="section" id="section-series">
        <div class="table-container">
          <div class="table-header">
            <h3>Series</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="series" />
              <button class="btn btn-primary" data-action="add" data-section="series">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-series"></div>
        </div>
      </div>
      
      <div class="section" id="section-games">
        <div class="table-container">
          <div class="table-header">
            <h3>Games</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="games" />
              <button class="btn btn-primary" data-action="add" data-section="games">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-games"></div>
        </div>
      </div>
      
      <div class="section" id="section-live-streams">
        <div class="table-container">
          <div class="table-header">
            <h3>Live Streams</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="live-streams" />
              <button class="btn btn-primary" data-action="add" data-section="live-streams">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-live-streams"></div>
        </div>
      </div>
      
      <div class="section" id="section-pc-apps">
        <div class="table-container">
          <div class="table-header">
            <h3>PC Apps</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="pc-apps" />
              <button class="btn btn-primary" data-action="add" data-section="pc-apps">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-pc-apps"></div>
        </div>
      </div>
      
      <div class="section" id="section-plugins">
        <div class="table-container">
          <div class="table-header">
            <h3>Plugins</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="plugins" />
              <button class="btn btn-primary" data-action="add" data-section="plugins">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-plugins"></div>
        </div>
      </div>
      
      <div class="section" id="section-affiliate">
        <div class="table-container">
          <div class="table-header">
            <h3>Affiliate Products</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="affiliate" />
              <button class="btn btn-primary" data-action="add" data-section="affiliate">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-affiliate"></div>
        </div>
      </div>
      
      <div class="section" id="section-licenses">
        <div class="table-container">
          <div class="table-header">
            <h3>Licenses</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="licenses" />
              <button class="btn btn-primary" data-action="add" data-section="licenses">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-licenses"></div>
        </div>
      </div>
      
      <div class="section" id="section-updates">
        <div class="table-container">
          <div class="table-header">
            <h3>Updates</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="updates" />
              <button class="btn btn-primary" data-action="add" data-section="updates">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-updates"></div>
        </div>
      </div>
      
      <div class="section" id="section-config">
        <div class="table-container">
          <div class="table-header">
            <h3>Config</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." data-search="config" />
              <button class="btn btn-primary" data-action="add" data-section="config">+ \u0625\u0636\u0627\u0641\u0629</button>
            </div>
          </div>
          <div id="table-config"></div>
        </div>
      </div>
      
      <!-- Payment Stats Section -->
      <div class="section" id="section-payment-stats">
        <div class="stats-grid" id="paymentStatsGrid"></div>
        
        <div class="table-container" style="margin-top: 20px;">
          <div class="table-header">
            <h3>By Status</h3>
          </div>
          <div id="paymentByStatus"></div>
        </div>
        
        <div class="table-container" style="margin-top: 20px;">
          <div class="table-header">
            <h3>By Plan</h3>
          </div>
          <div id="paymentByPlan"></div>
        </div>
        
        <div class="table-container" style="margin-top: 20px;">
          <div class="table-header">
            <h3>Top Buyers</h3>
          </div>
          <div id="paymentTopBuyers"></div>
        </div>
        
        <div class="table-container" style="margin-top: 20px;">
          <div class="table-header">
            <h3>Recent Payments</h3>
            <div style="display:flex; gap:8px;">
              <input type="text" class="search-box" placeholder="\u0628\u062D\u062B..." id="paymentSearch" />
            </div>
          </div>
          <div id="table-payment-stats"></div>
        </div>
      </div>
    </div>
  </main>
</div>

<!-- Modal -->
<div class="modal-overlay" id="modalOverlay">
  <div class="modal">
    <div class="modal-header">
      <h3 id="modalTitle">Form</h3>
      <button class="modal-close" id="modalClose">\xD7</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
    <div class="modal-footer">
      <button class="btn btn-secondary" id="modalCancel">\u0625\u0644\u063A\u0627\u0621</button>
      <button class="btn btn-primary" id="modalSave">\u062D\u0641\u0638</button>
    </div>
  </div>
</div>

<!-- Toast Container -->
<div class="toast-container" id="toastContainer"></div>

<script>
(function() {
  // ============ Configuration ============
  const SECTIONS = {
    'dashboard': { title: 'Dashboard', api: null },
    'movies': { title: 'Movies', api: 'movies', columns: ['id', 'name'], labels: { id: 'ID', name: '\u0627\u0644\u0627\u0633\u0645' } },
    'series': { title: 'Series', api: 'series', columns: ['id', 'name'], labels: { id: 'ID', name: '\u0627\u0644\u0627\u0633\u0645' } },
    'games': { title: 'Games', api: 'games', columns: ['id', 'steamId', 'name', 'cover', 'short_desc', 'genres', 'developers', 'publishers', 'released', 'metacritic', 'screenshots', 'pc_min', 'pc_rec', 'size_text', 'trailer', 'logo', 'hero', 'page_bg', 'bypass', 'onlineFix', 'steamtools', 'gameplay', 'exeName', 'download'], labels: { id: 'ID', steamId: 'Steam ID', name: 'الاسم', cover: 'الغلاف', short_desc: 'الوصف المختصر', genres: 'الأنواع', developers: 'المطور', publishers: 'الناشر', released: 'تاريخ الإصدار', metacritic: 'التقييم', screenshots: 'اللقطات', pc_min: 'الحد الأدنى', pc_rec: 'الموصى به', size_text: 'الحجم', trailer: 'التريلر', logo: 'الشعار', hero: 'البانر', page_bg: 'خلفية الصفحة', bypass: 'Bypass', onlineFix: 'Online Fix', steamtools: 'Steam Tools', gameplay: 'Gameplay', exeName: 'EXE Name', download: 'Download' } },
    'live-streams': { title: 'Live Streams', api: 'live-streams', columns: ['id', 'name', 'url'], labels: { id: 'ID', name: '\u0627\u0644\u0627\u0633\u0645', url: '\u0627\u0644\u0631\u0627\u0628\u0637' } },
    'pc-apps': { title: 'PC Apps', api: 'pc-apps', columns: ['id', 'name', 'description', 'version', 'images', 'url', 'fileSize'], labels: { id: 'ID', name: '\u0627\u0644\u0627\u0633\u0645', description: '\u0627\u0644\u0648\u0635\u0641', version: '\u0627\u0644\u0625\u0635\u062F\u0627\u0631', images: '\u0627\u0644\u0635\u0648\u0631', url: '\u0627\u0644\u0631\u0627\u0628\u0637', fileSize: '\u0627\u0644\u062D\u062C\u0645' } },
    'plugins': { title: 'Plugins', api: 'plugins', columns: ['id', 'name', 'description', 'version', 'images', 'url', 'fileSize', 'exeName'], labels: { id: 'ID', name: '\u0627\u0644\u0627\u0633\u0645', description: '\u0627\u0644\u0648\u0635\u0641', version: '\u0627\u0644\u0625\u0635\u062F\u0627\u0631', images: '\u0627\u0644\u0635\u0648\u0631', url: '\u0627\u0644\u0631\u0627\u0628\u0637', fileSize: '\u0627\u0644\u062D\u062C\u0645', exeName: 'EXE Name' } },
    'affiliate': { title: 'Affiliate Products', api: 'affiliate-products', columns: ['id', 'name', 'url'], labels: { id: 'ID', name: '\u0627\u0644\u0627\u0633\u0645', url: '\u0627\u0644\u0631\u0627\u0628\u0637' } },
    'licenses': { title: 'Licenses', api: 'licenses', columns: ['id', 'username', 'email', 'key', 'createdAt', 'expiryDate', 'devices', 'biosId'], labels: { id: 'ID', username: '\u0627\u0633\u0645 \u0627\u0644\u0645\u0633\u062A\u062E\u062F\u0645', email: '\u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A', key: '\u0627\u0644\u0645\u0641\u062A\u0627\u062D', createdAt: '\u062A\u0627\u0631\u064A\u062E \u0627\u0644\u0625\u0646\u0634\u0627\u0621', expiryDate: '\u062A\u0627\u0631\u064A\u062E \u0627\u0644\u0627\u0646\u062A\u0647\u0627\u0621', devices: '\u0627\u0644\u0623\u062C\u0647\u0632\u0629', biosId: 'BIOS ID' } },
    'updates': { title: 'Updates', api: 'updates', columns: ['id', 'name', 'version', 'url'], labels: { id: 'ID', name: '\u0627\u0644\u0627\u0633\u0645', version: '\u0627\u0644\u0625\u0635\u062F\u0627\u0631', url: '\u0627\u0644\u0631\u0627\u0628\u0637' } },
    'config': { title: 'Config', api: 'config', columns: ['id', 'github_url', 'version', 'updated_at'], labels: { id: 'ID', github_url: 'GitHub URL', version: '\u0627\u0644\u0625\u0635\u062F\u0627\u0631', updated_at: '\u0622\u062E\u0631 \u062A\u062D\u062F\u064A\u062B' } },
    'payment-stats': { title: 'Payment Stats', api: null }
  };
  const UPLOAD_FIELDS = { 'games': ['bypass', 'onlineFix', 'steamtools', 'download'], 'pc-apps': ['images', 'url'], 'plugins': ['images', 'url'], 'updates': ['url'] };
  
  const state = {
    currentSection: 'dashboard',
    data: {},
    pagination: {},
    search: {},
    plans: [],
    services: []
  };
  
  // ============ Utility Functions ============
  function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    const icon = type === 'success' ? '\u2713' : type === 'error' ? '\u2717' : '\u2139';
    toast.innerHTML = '<span>' + icon + '</span><span>' + escapeHtml(message) + '</span>';
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 200); }, 3000);
  }
  
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }
  
  function escapeAttr(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  
  async function api(path, options) {
    const res = await fetch(path, Object.assign({ credentials: 'same-origin' }, options || {}));
    if (res.status === 401) {
      showLogin();
      throw new Error('unauthorized');
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'HTTP ' + res.status);
    }
    return res.json();
  }
  
  // ============ Auth ============
  function showLogin() {
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('mainApp').classList.remove('active');
  }
  
  function showApp() {
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('mainApp').classList.add('active');
  }
  
  async function login() {
    document.getElementById('loginError').textContent = '';
    const password = document.getElementById('password').value;
    if (!password) return;
    try {
      const res = await fetch('/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
        credentials: 'same-origin'
      });
      if (res.ok) {
        document.getElementById('password').value = '';
        showApp();
        await init();
      } else {
        document.getElementById('loginError').textContent = '\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u063A\u064A\u0631 \u0635\u062D\u064A\u062D\u0629';
      }
    } catch (e) {
      document.getElementById('loginError').textContent = '\u062D\u062F\u062B \u062E\u0637\u0623';
    }
  }
  
  async function logout() {
    await fetch('/admin/logout', { method: 'POST', credentials: 'same-origin' });
    showLogin();
    document.getElementById('password').value = '';
  }
  
  // ============ Navigation ============
  function navigateTo(section) {
    state.currentSection = section;
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.querySelector('[data-section="' + section + '"]').classList.add('active');
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById('section-' + section).classList.add('active');
    document.getElementById('sectionTitle').textContent = SECTIONS[section].title;
    if (section === 'dashboard') loadDashboard();
    else if (section === 'payment-stats') loadPaymentStats();
    else loadSection(section);
  }
  
  // ============ Dashboard ============
  async function loadDashboard() {
    const grid = document.getElementById('statsGrid');
    grid.innerHTML = '<div class="stat-card"><div class="label">Loading...</div><div class="value">\u2014</div></div>';
    try {
      const data = await api('/api/admin/dashboard');
      const labels = {
        movies: 'Movies', series: 'Series', games: 'Games', live_streams: 'Live Streams',
        pc_apps: 'PC Apps', plugins: 'Plugins', affiliate_products: 'Affiliate Products',
        licenses: 'Licenses', updates: 'Updates', config: 'Config',
        expired_licenses: 'Expired Licenses'
      };
      grid.innerHTML = '';
      for (const [key, value] of Object.entries(data.stats)) {
        const card = document.createElement('div');
        card.className = 'stat-card' + (key === 'expired_licenses' && value > 0 ? ' warning' : '');
        card.innerHTML = '<div class="label">' + (labels[key] || key) + '</div><div class="value">' + value + '</div>';
        grid.appendChild(card);
      }
    } catch (e) {
      grid.innerHTML = '<div class="stat-card"><div class="label">Error</div><div class="value">!</div></div>';
    }
  }

  async function loadPaymentStats(search = '') {
    const grid = document.getElementById('paymentStatsGrid');
    const tableEl = document.getElementById('table-payment-stats');
    const byStatusEl = document.getElementById('paymentByStatus');
    const byPlanEl = document.getElementById('paymentByPlan');
    const topBuyersEl = document.getElementById('paymentTopBuyers');
    grid.innerHTML = '<div class="stat-card"><div class="label">Loading...</div><div class="value">\u2014</div></div>';
    tableEl.innerHTML = '<div class="table-loading">\u062C\u0627\u0631\u064A \u0627\u0644\u062A\u062D\u0645\u064A\u0644...</div>';
    byStatusEl.innerHTML = '<div class="table-loading">\u062C\u0627\u0631\u064A \u0627\u0644\u062A\u062D\u0645\u064A\u0644...</div>';
    byPlanEl.innerHTML = '<div class="table-loading">\u062C\u0627\u0631\u064A \u0627\u0644\u062A\u062D\u0645\u064A\u0644...</div>';
    topBuyersEl.innerHTML = '<div class="table-loading">\u062C\u0627\u0631\u064A \u0627\u0644\u062A\u062D\u0645\u064A\u0644...</div>';

    try {
      const data = await api('/api/admin/payment-stats?search=' + encodeURIComponent(search));
      const summary = data.summary || {};

      grid.innerHTML = '';
      const summaryCards = [
        { label: 'Total Payments', value: summary.totalPayments || 0 },
        { label: 'Total Revenue', value: '$' + ((summary.totalRevenue || 0).toFixed(2)) },
        { label: 'Avg Order', value: '$' + ((summary.avgOrderValue || 0).toFixed(2)) },
        { label: 'Successful', value: summary.successfulPayments || 0 },
        { label: 'Pending', value: summary.pendingPayments || 0 },
        { label: 'Failed', value: summary.failedPayments || 0 },
        { label: "Today's Payments", value: summary.todayPayments || 0 },
        { label: "This Month", value: summary.monthPayments || 0 }
      ];

      summaryCards.forEach(card => {
        const el = document.createElement('div');
        el.className = 'stat-card';
        el.innerHTML = '<div class="label">' + card.label + '</div><div class="value">' + card.value + '</div>';
        grid.appendChild(el);
      });

      const rows = (data.items || []).map(row => 
        '<tr>' +
          '<td>' + escapeHtml(row.captureId) + '</td>' +
          '<td>' + escapeHtml(row.orderId) + '</td>' +
          '<td>' + escapeHtml(row.planKey) + '</td>' +
          '<td>$' + Number(row.amount || 0).toFixed(2) + '</td>' +
          '<td>' + escapeHtml(row.buyerEmail || '-') + '</td>' +
          '<td>' + escapeHtml(row.license_id || '-') + '</td>' +
          '<td><span class="badge ' + (row.status === 'CAPTURED' || row.status === 'VERIFIED' || row.status === 'LICENSE_ISSUED' ? 'success' : row.status === 'FAILED' || row.status === 'REFUNDED' || row.status === 'REVERSED' || row.status === 'DISPUTED' ? 'danger' : 'warning') + '">' + escapeHtml(row.status) + '</span></td>' +
          '<td>' + escapeHtml(row.createdAt || '') + '</td>' +
        '</tr>'
      ).join('');

      tableEl.innerHTML = 
        '<table>' +
          '<thead>' +
            '<tr>' +
              '<th>Capture ID</th>' +
              '<th>Order ID</th>' +
              '<th>Plan</th>' +
              '<th>Amount</th>' +
              '<th>Buyer Email</th>' +
              '<th>License ID</th>' +
              '<th>Status</th>' +
              '<th>Date</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' + (rows || '<tr><td colspan="8" class="table-empty">No payments yet</td></tr>') + '</tbody>' +
        '</table>';

      const statusRows = (data.byStatus || []).map(row => 
        '<tr>' +
          '<td><span class="badge ' + (row.status === 'CAPTURED' || row.status === 'VERIFIED' || row.status === 'LICENSE_ISSUED' ? 'success' : row.status === 'FAILED' || row.status === 'REFUNDED' || row.status === 'REVERSED' || row.status === 'DISPUTED' ? 'danger' : 'warning') + '">' + escapeHtml(row.status) + '</span></td>' +
          '<td>' + (row.count || 0) + '</td>' +
          '<td>$' + (Number(row.revenue || 0)).toFixed(2) + '</td>' +
        '</tr>'
      ).join('');
      byStatusEl.innerHTML = 
        '<table>' +
          '<thead>' +
            '<tr>' +
              '<th>Status</th>' +
              '<th>Count</th>' +
              '<th>Revenue</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' + (statusRows || '<tr><td colspan="3" class="table-empty">No data</td></tr>') + '</tbody>' +
        '</table>';

      const planRows = (data.byPlan || []).map(row => 
        '<tr>' +
          '<td>' + escapeHtml(row.planKey || '-') + '</td>' +
          '<td>' + (row.count || 0) + '</td>' +
          '<td>$' + (Number(row.revenue || 0)).toFixed(2) + '</td>' +
        '</tr>'
      ).join('');
      byPlanEl.innerHTML = 
        '<table>' +
          '<thead>' +
            '<tr>' +
              '<th>Plan</th>' +
              '<th>Count</th>' +
              '<th>Revenue</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' + (planRows || '<tr><td colspan="3" class="table-empty">No data</td></tr>') + '</tbody>' +
        '</table>';

      const buyerRows = (data.topBuyers || []).map(row => 
        '<tr>' +
          '<td>' + escapeHtml(row.buyerEmail || '-') + '</td>' +
          '<td>' + (row.count || 0) + '</td>' +
          '<td>$' + (Number(row.totalSpent || 0)).toFixed(2) + '</td>' +
        '</tr>'
      ).join('');
      topBuyersEl.innerHTML = 
        '<table>' +
          '<thead>' +
            '<tr>' +
              '<th>Email</th>' +
              '<th>Purchases</th>' +
              '<th>Total Spent</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' + (buyerRows || '<tr><td colspan="3" class="table-empty">No data</td></tr>') + '</tbody>' +
        '</table>';
    } catch (e) {
      tableEl.innerHTML = '<div class="table-error">\u062E\u0637\u0623: ' + escapeHtml(e.message) + '</div>';
      byStatusEl.innerHTML = '<div class="table-error">\u062E\u0637\u0623: ' + escapeHtml(e.message) + '</div>';
      byPlanEl.innerHTML = '<div class="table-error">\u062E\u0637\u0623: ' + escapeHtml(e.message) + '</div>';
      topBuyersEl.innerHTML = '<div class="table-error">\u062E\u0637\u0623: ' + escapeHtml(e.message) + '</div>';
    }
  }
  
  // ============ Generic CRUD ============
  async function loadSection(section) {
    const config = SECTIONS[section];
    if (!config || !config.api) return;
    const tableEl = document.getElementById('table-' + section);
    tableEl.innerHTML = '<div class="table-loading">\u062C\u0627\u0631\u064A \u0627\u0644\u062A\u062D\u0645\u064A\u0644...</div>';
    
    try {
      const search = state.search[section] || '';
      const page = state.pagination[section] || 1;
      const data = await api('/api/admin/' + config.api + '?search=' + encodeURIComponent(search) + '&page=' + page + '&pageSize=20');
      state.data[section] = data.items;
      renderTable(section, data);
    } catch (e) {
      tableEl.innerHTML = '<div class="table-error">\u062E\u0637\u0623: ' + escapeHtml(e.message) + '</div>';
    }
  }
  
  function renderTable(section, data) {
    const config = SECTIONS[section];
    const tableEl = document.getElementById('table-' + section);
    
    if (!data.items || data.items.length === 0) {
      tableEl.innerHTML = '<div class="table-empty">\u0644\u0627 \u062A\u0648\u062C\u062F \u0628\u064A\u0627\u0646\u0627\u062A</div>';
      return;
    }
    
    let html = '<table><thead><tr>';
    config.columns.forEach(c => { html += '<th>' + escapeHtml(config.labels[c] || c) + '</th>'; });
    html += '<th>\u0627\u0644\u0625\u062C\u0631\u0627\u0621\u0627\u062A</th></tr></thead><tbody>';
    
    data.items.forEach(item => {
      html += '<tr>';
      config.columns.forEach(c => {
        let val = item[c] === null || item[c] === undefined ? '—' : item[c];
        html += '<td class="cell-truncate" title="' + escapeAttr(val) + '">' + escapeHtml(val) + '</td>';
      });
      html += '<td><div class="table-actions">';
      html += '<button class="btn btn-sm btn-secondary" data-action="edit" data-section="' + section + '" data-id="' + escapeAttr(item.id) + '">\u062A\u0639\u062F\u064A\u0644</button>';
      html += '<button class="btn btn-sm btn-danger" data-action="delete" data-section="' + section + '" data-id="' + escapeAttr(item.id) + '">\u062D\u0630\u0641</button>';
      html += '</div></td></tr>';
    });
    
    html += '</tbody></table>';
    
    // Pagination
    html += '<div class="pagination">';
    html += '<span>\u0627\u0644\u0635\u0641\u062D\u0629 ' + data.page + ' \u0645\u0646 ' + data.totalPages + ' (' + data.total + ' \u0633\u062C\u0644)</span>';
    html += '<div class="pagination-buttons">';
    html += '<button data-action="prev-page" data-section="' + section + '" ' + (data.page <= 1 ? 'disabled' : '') + '>\u0627\u0644\u0633\u0627\u0628\u0642</button>';
    html += '<button data-action="next-page" data-section="' + section + '" ' + (data.page >= data.totalPages ? 'disabled' : '') + '>\u0627\u0644\u062A\u0627\u0644\u064A</button>';
    html += '</div></div>';
    
    tableEl.innerHTML = html;
  }
  
  // ============ Modal ============
  function generateLicenseKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    function seg(n) {
      let s = '';
      const arr = crypto.getRandomValues(new Uint8Array(n));
      for (let i = 0; i < n; i++) s += chars[arr[i] % chars.length];
      return s;
    }
    return 'RACHID-' + seg(5) + '-' + seg(5) + '-' + seg(5);
  }

  function showModal(title, content) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = content;
    document.getElementById('modalOverlay').classList.add('active');
    const genBtn = document.getElementById('generateKeyBtn');
    if (genBtn) {
      genBtn.onclick = () => {
        const keyField = document.getElementById('field-key');
        if (keyField) {
          keyField.value = generateLicenseKey();
          keyField.dispatchEvent(new Event('input', { bubbles: true }));
        }
      };
    }
    const autofillBtn = document.getElementById('autofillBtn');
    if (autofillBtn) {
      autofillBtn.onclick = async () => {
        // Tolerant read: by id first, then by field name fallback.
        const sidEl = document.getElementById('field-steamId') ||
          document.querySelector('[name="steamId"]');
        const raw = sidEl ? String(sidEl.value || '') : '';
        // Normalize non-ASCII digits (Arabic-Indic ٠-٩, Persian ۰-۹, fullwidth).
        const norm = raw
          .replace(/[٠-٩]/g, d => '0123456789'['٠١٢٣٤٥٦٧٨٩'.indexOf(d)])
          .replace(/[۰-۹]/g, d => '0123456789'['۰۱۲۳۴۵۶۷۸۹'.indexOf(d)])
          .replace(/[０-９]/g, d => String('０１２３４５６７８９'.indexOf(d)));
        const digits = norm.match(/\d+/g);
        const sid = digits ? digits.join('') : '';
        if (!sid) {
          showToast('الحقل فارغ (المقروء: "' + raw.slice(0, 20) + '") — اكتب Steam ID رقمي', 'error');
          return;
        }
        autofillBtn.disabled = true;
        autofillBtn.textContent = '⏳ جاري الجلب...';
        try {
          const res = await api('/api/admin/games/autofill', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ steamId: sid })
          });
          const fields = res.fields || {};
          let filled = 0;
          Object.keys(fields).forEach(k => {
            const el = document.querySelector('[name="' + k + '"]');
            if (el && fields[k] !== null && fields[k] !== undefined && String(fields[k]) !== '') {
              el.value = typeof fields[k] === 'string' ? fields[k] : String(fields[k]);
              filled++;
            }
          });
          showToast('تم ملء ' + filled + ' حقلاً — راجع ثم احفظ', 'success');
        } catch (e) {
          showToast('فشل الملء: ' + e.message, 'error');
        } finally {
          autofillBtn.disabled = false;
          autofillBtn.textContent = '⚡ ملء تلقائي';
        }
      };
    }
  }
  
  function hideModal() {
    document.getElementById('modalOverlay').classList.remove('active');
  }
  
  function buildForm(section, item) {
    const config = SECTIONS[section];
    const isEdit = !!item;
    let html = '';
    config.columns.forEach(c => {
      const val = item ? (item[c] || '') : '';
      const label = config.labels[c] || c;
      const isReadonly = isEdit && c === 'id';
      
      if (c === 'devices' || c === 'fileSize') {
        html += '<div class="form-group"><label>' + label + ' <span class="required">*</span></label>';
        html += '<input type="number" name="' + c + '" value="' + escapeAttr(val) + '" min="0" ' + (isReadonly ? 'readonly' : '') + ' required /></div>';
      } else if (c === 'createdAt' || c === 'expiryDate') {
        let dateVal = val;
        if (!dateVal) {
          const d = new Date();
          if (c === 'expiryDate') d.setFullYear(d.getFullYear() + 1);
          dateVal = d.toISOString().slice(0, 16);
        }
        html += '<div class="form-group"><label>' + label + ' <span class="required">*</span></label>';
        html += '<input type="datetime-local" name="' + c + '" value="' + escapeAttr(dateVal) + '" ' + (isReadonly ? 'readonly' : '') + ' required /></div>';
      } else if (section === 'licenses' && c === 'key') {
        html += '<div class="form-group"><label>' + label + ' <span class="required">*</span></label>';
        html += '<div style="display:flex; gap:8px;">';
        html += '<input type="text" name="' + c + '" id="field-key" value="' + escapeAttr(val) + '" placeholder="RACHID-XXXXX-XXXXX-XXXXX" required style="flex:1;" />';
        html += '<button type="button" class="btn btn-secondary" id="generateKeyBtn" style="width:auto; padding:10px 14px; white-space:nowrap;">\u062A\u0648\u0644\u064A\u062F \u0639\u0634\u0648\u0627\u0626\u064A</button>';
        html += '</div></div>';
      } else if (c === 'biosId') {
        html += '<div class="form-group"><label>' + label + ' (\u0627\u062E\u062A\u064A\u0627\u0631\u064A)</label>';
        html += '<input type="text" name="' + c + '" value="' + escapeAttr(val) + '" ' + (isReadonly ? 'readonly' : '') + ' /></div>';
      } else if (section === 'games' && c === 'steamId') {
        html += '<div class="form-group"><label>' + label + ' <span class="required">*</span></label>';
        html += '<div style="display:flex; gap:8px;">';
        html += '<input type="text" name="' + c + '" id="field-steamId" value="' + escapeAttr(val) + '" ' + (isReadonly ? 'readonly' : '') + ' required style="flex:1;" />';
        html += '<button type="button" class="btn btn-secondary" id="autofillBtn" style="width:auto; padding:10px 14px; white-space:nowrap;">⚡ ملء تلقائي</button>';
        html += '</div></div>';
      } else if (UPLOAD_FIELDS[section] && UPLOAD_FIELDS[section].includes(c)) {
        const inputId = 'inp-' + c;
        const fileId = 'fil-' + c;
        const modeName = 'mode-' + c;
        const required = c !== 'description' && c !== 'version' && c !== 'updated_at' && c !== 'biosId';
        html += '<div class="form-group upload-field" data-section="' + section + '" data-field="' + c + '">';
        html += '<label>' + label + (required ? ' <span class="required">*</span>' : '') + '</label>';
        html += '<div class="upload-mode-toggle">';
        html += '<label><input type="radio" name="' + modeName + '" value="url" checked> \uD83D\uDD17 \u0631\u0627\u0628\u0637</label>';
        html += '<label><input type="radio" name="' + modeName + '" value="zip"> \uD83D\uDCE5 \u0631\u0641\u0639 \u0645\u0644\u0641 ZIP</label>';
        html += '</div>';
        html += '<div class="upload-url-wrap">';
        html += '<input type="text" name="' + c + '" id="' + inputId + '" value="' + escapeAttr(val) + '" placeholder="https://..." ' + (required ? 'required' : '') + ' style="flex:1;" />';
        html += '</div>';
        html += '<div class="upload-zip-wrap">';
        html += '<input type="file" id="' + fileId + '" style="display:none;" accept=".zip,application/zip,application/x-zip-compressed" />';
        html += '<button type="button" class="btn btn-secondary select-file-btn" data-field="' + c + '" data-section="' + section + '">\u0627\u062E\u062A\u0631 \u0645\u0644\u0641 ZIP</button>';
        html += '<button type="button" class="btn btn-primary upload-btn" data-field="' + c + '" data-section="' + section + '" disabled style="white-space:nowrap;">\uD83D\uDCE5 \u0631\u0641\u0639 \u0645\u0628\u0627\u0634\u0631</button>';
        html += '</div>';
        html += '</div>';
      } else {
        const optionalMeta = ['description', 'version', 'updated_at', 'biosId', 'name', 'cover', 'short_desc', 'genres', 'developers', 'publishers', 'released', 'metacritic', 'screenshots', 'pc_min', 'pc_rec', 'size_text', 'trailer', 'logo', 'hero', 'page_bg', 'steam_synced_at'];
        const required = !optionalMeta.includes(c);
        html += '<div class="form-group"><label>' + label + (required ? ' <span class="required">*</span>' : '') + '</label>';
        html += '<input type="text" name="' + c + '" value="' + escapeAttr(val) + '" ' + (isReadonly ? 'readonly' : '') + (required ? 'required' : '') + ' /></div>';
      }
    });
    return html;
  }
  
  function getFormData(section) {
    const config = SECTIONS[section];
    const data = {};
    config.columns.forEach(c => {
      const el = document.querySelector('[name="' + c + '"]');
      if (el) {
        if (c === 'devices' || c === 'fileSize') {
          data[c] = parseInt(el.value) || 0;
        } else if (c === 'createdAt' || c === 'expiryDate') {
          data[c] = el.value && el.value.trim() !== '' ? el.value : null;
        } else {
          data[c] = el.value.trim() || null;
        }
      }
    });
    return data;
  }
  
  // ============ Actions ============
  async function handleAdd(section) {
    const config = SECTIONS[section];
    showModal('\u0625\u0636\u0627\u0641\u0629 ' + config.title, buildForm(section, null));
    document.getElementById('modalSave').onclick = async () => {
      try {
        const data = getFormData(section);
        if (section === 'licenses') {
          if (!data.key || data.key.trim() === '') {
            showToast('\u064A\u0631\u062C\u0649 \u0625\u062F\u062E\u0627\u0644 \u0645\u0641\u062A\u0627\u062D \u0627\u0644\u062A\u0631\u062E\u064A\u0635 \u0623\u0648 \u062A\u0648\u0644\u064A\u062F \u0645\u0641\u062A\u0627\u062D \u062C\u062F\u064A\u062F', 'error');
            return;
          }
          if (!data.createdAt) {
            showToast('\u064A\u0631\u062C\u0649 \u062A\u062D\u062F\u064A\u062F \u062A\u0627\u0631\u064A\u062E \u0627\u0644\u0625\u0646\u0634\u0627\u0621', 'error');
            return;
          }
          if (!data.expiryDate) {
            showToast('\u064A\u0631\u062C\u0649 \u062A\u062D\u062F\u064A\u062F \u062A\u0627\u0631\u064A\u062E \u0627\u0644\u0627\u0646\u062A\u0647\u0627\u0621', 'error');
            return;
          }
        }
        await api('/api/admin/' + config.api, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        hideModal();
        showToast('\u062A\u0645 \u0627\u0644\u0625\u0636\u0627\u0641\u0629 \u0628\u0646\u062C\u0627\u062D', 'success');
        loadSection(section);
      } catch (e) {
        showToast('\u0641\u0634\u0644: ' + e.message, 'error');
      }
    };
  }
  
  async function handleEdit(section, id) {
    const config = SECTIONS[section];
    // \u0645\u0642\u0627\u0631\u0646\u0629 \u0646\u0635\u064A\u0629 \u0622\u0645\u0646\u0629: games/pc_apps/plugins \u062A\u0633\u062A\u062E\u062F\u0645 id \u0631\u0642\u0645\u064A\u064B\u0627 (autoincrement)
    // \u0628\u064A\u0646\u0645\u0627 id \u0627\u0644\u0642\u0627\u062F\u0645 \u0645\u0646 data-id \u0641\u064A \u0627\u0644\u0640DOM \u0647\u0648 \u062F\u0627\u0626\u0645\u064B\u0627 \u0646\u0635. \u0627\u0644\u0645\u0642\u0627\u0631\u0646\u0629 \u0627\u0644\u0635\u0627\u0631\u0645\u0629 (===)
    // \u0643\u0627\u0646\u062A \u062A\u0641\u0634\u0644 \u0628\u0635\u0645\u062A \u0644\u0647\u0630\u0647 \u0627\u0644\u062C\u062F\u0627\u0648\u0644 \u0627\u0644\u062B\u0644\u0627\u062B\u0629 \u062A\u062D\u062F\u064A\u062F\u064B\u0627 (5 !== "5")\u060C \u0641\u062A\u062A\u062D\u0648\u0644 \u0644\u0639\u062F\u0645 \u0641\u0639\u0644
    // \u0623\u064A \u0634\u064A\u0621 \u0639\u0646\u062F \u0627\u0644\u0636\u063A\u0637 \u0639\u0644\u0649 "\u062A\u0639\u062F\u064A\u0644". \u0647\u0630\u0627 \u0647\u0648 \u0633\u0628\u0628 \u0639\u0637\u0644 \u0632\u0631 \u0627\u0644\u062A\u0639\u062F\u064A\u0644 \u0641\u064A games.
    const item = state.data[section].find(i => String(i.id) === String(id));
    if (!item) return;
    showModal('\u062A\u0639\u062F\u064A\u0644 ' + config.title, buildForm(section, item));
    document.getElementById('modalSave').onclick = async () => {
      try {
        const data = getFormData(section);
        if (section === 'licenses' && (!data.key || data.key.trim() === '')) {
          showToast('\u064A\u0631\u062C\u0649 \u0625\u062F\u062E\u0627\u0644 \u0645\u0641\u062A\u0627\u062D \u0627\u0644\u062A\u0631\u062E\u064A\u0635 \u0623\u0648 \u062A\u0648\u0644\u064A\u062F \u0645\u0641\u062A\u0627\u062D \u062C\u062F\u064A\u062F', 'error');
          return;
        }
        data.id = id;
        await api('/api/admin/' + config.api + '/' + encodeURIComponent(id), {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        hideModal();
        showToast('\u062A\u0645 \u0627\u0644\u062A\u062D\u062F\u064A\u062B \u0628\u0646\u062C\u0627\u062D', 'success');
        loadSection(section);
      } catch (e) {
        showToast('\u0641\u0634\u0644: ' + e.message, 'error');
      }
    };
  }
  
  async function handleDelete(section, id) {
    const config = SECTIONS[section];
    if (!confirm('\u0647\u0644 \u0623\u0646\u062A \u0645\u062A\u0623\u0643\u062F \u0645\u0646 \u062D\u0630\u0641 \u0647\u0630\u0627 \u0627\u0644\u0633\u062C\u0644\u061F')) return;
    try {
      await api('/api/admin/' + config.api + '/' + encodeURIComponent(id), { method: 'DELETE' });
      showToast('\u062A\u0645 \u0627\u0644\u062D\u0630\u0641 \u0628\u0646\u062C\u0627\u062D', 'success');
      loadSection(section);
    } catch (e) {
      showToast('\u0641\u0634\u0644 \u0627\u0644\u062D\u0630\u0641: ' + e.message, 'error');
    }
  }
  
  // ============ Init ============
  async function init() {
    try {
      loadDashboard();
    } catch (e) {
      // 401 handled
    }
  }
  
  // ============ Event Listeners ============
  document.getElementById('loginBtn').addEventListener('click', login);
  document.getElementById('password').addEventListener('keydown', (e) => { if (e.key === 'Enter') login(); });
  document.getElementById('logoutBtn').addEventListener('click', logout);
  document.getElementById('modalClose').addEventListener('click', hideModal);
  document.getElementById('modalCancel').addEventListener('click', hideModal);
  
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(link.dataset.section);
    });
  });
  
  // Delegated event handler for dynamic buttons
  document.addEventListener('click', (e) => {
    const target = e.target.closest('[data-action]');
    if (!target) return;
    const action = target.dataset.action;
    const section = target.dataset.section;
    const id = target.dataset.id;
    
    if (action === 'add') handleAdd(section);
    else if (action === 'edit') handleEdit(section, id);
    else if (action === 'delete') handleDelete(section, id);
    else if (action === 'prev-page') {
      state.pagination[section] = (state.pagination[section] || 1) - 1;
      loadSection(section);
    } else if (action === 'next-page') {
      state.pagination[section] = (state.pagination[section] || 1) + 1;
      loadSection(section);
    }
  });
  
  // Search input handler
  document.querySelectorAll('.search-box').forEach(input => {
    let timer;
    input.addEventListener('input', (e) => {
      clearTimeout(timer);
      const section = input.dataset.search;
      timer = setTimeout(() => {
        state.search[section] = e.target.value;
        state.pagination[section] = 1;
        loadSection(section);
      }, 300);
    });
  });

  const paymentSearchInput = document.getElementById('paymentSearch');
  if (paymentSearchInput) {
    let timer;
    paymentSearchInput.addEventListener('input', (e) => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        loadPaymentStats(e.target.value);
      }, 300);
    });
  }

  // ============ Upload to R2 ============
  const selectedFiles = {};

  async function uploadFileToR2(file, section, fieldName) {
    const presignRes = await api('/api/admin/upload-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: file.name, contentType: file.type || 'application/zip' })
    });
    const uploadRes = await fetch(presignRes.uploadUrl, {
      method: 'PUT',
      headers: { 'Content-Type': file.type || 'application/zip' },
      body: file
    });
    if (!uploadRes.ok) {
      throw new Error('Upload failed: HTTP ' + uploadRes.status);
    }
    return presignRes.publicUrl;
  }

  // Upload event delegation
  document.addEventListener('click', async (e) => {
    const radio = e.target.closest('input[type="radio"][name^="mode-"]');
    if (radio) {
      const fieldGroup = radio.closest('.upload-field');
      if (!fieldGroup) return;
      if (radio.value === 'zip') {
        fieldGroup.classList.add('upload-zip-mode');
        fieldGroup.classList.remove('upload-url-mode');
        const textInput = fieldGroup.querySelector('input[type="text"]');
        if (textInput) { textInput.readOnly = true; }
      } else {
        fieldGroup.classList.add('upload-url-mode');
        fieldGroup.classList.remove('upload-zip-mode');
        const textInput = fieldGroup.querySelector('input[type="text"]');
        if (textInput) { textInput.readOnly = false; }
      }
      return;
    }
    const selectBtn = e.target.closest('.select-file-btn');
    if (selectBtn) {
      const fieldGroup = selectBtn.closest('.upload-field');
      if (!fieldGroup) return;
      const fileInput = fieldGroup.querySelector('input[type="file"]');
      if (!fileInput) return;
      fileInput.onchange = async () => {
        const file = fileInput.files[0];
        if (!file) return;
        const field = selectBtn.dataset.field;
        const section = selectBtn.dataset.section;
        selectedFiles[section + ':' + field] = file;
        const uploadBtn = fieldGroup.querySelector('.upload-btn');
        if (uploadBtn) {
          uploadBtn.disabled = false;
          uploadBtn.textContent = '📤 رفع مباشر';
        }
        showToast('تم اختيار الملف: ' + file.name, 'info');
      };
      fileInput.click();
      return;
    }
    const uploadBtn = e.target.closest('.upload-btn');
    if (!uploadBtn || uploadBtn.disabled) return;
    const field = uploadBtn.dataset.field;
    const section = uploadBtn.dataset.section;
    const fieldGroup = uploadBtn.closest('.upload-field');
    if (!fieldGroup) return;
    const file = selectedFiles[section + ':' + field];
    if (!file) {
      showToast('اختر ملفاً أولاً', 'error');
      return;
    }
    const originalText = uploadBtn.textContent;
    uploadBtn.textContent = 'جارٍ الرفع...';
    uploadBtn.disabled = true;
    try {
      const publicUrl = await uploadFileToR2(file, section, field);
      const textInput = fieldGroup.querySelector('input[type="text"]');
      if (textInput) {
        textInput.value = publicUrl;
        textInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
      const fileSizeInput = document.querySelector('[name="fileSize"]');
      if (fileSizeInput) fileSizeInput.value = file.size;
      showToast('تم الرفع بنجاح', 'success');
    } catch (err) {
      showToast('فشل الرفع: ' + err.message, 'error');
    } finally {
      uploadBtn.textContent = originalText;
      uploadBtn.disabled = false;
    }
  });

  // Check if already logged in
  api('/api/admin/dashboard').then(() => {
    showApp();
    init();
  }).catch(() => {
    showLogin();
  });
})();
<\/script>
</body>
</html>`;
}
__name(adminPanelHtml, "adminPanelHtml");
__name2(adminPanelHtml, "adminPanelHtml");
var CLIENT_SESSION_TTL_MS = 20 * 60 * 1e3;
var KeyManager = class {
  static {
    __name(this, "KeyManager");
  }
  static {
    __name2(this, "KeyManager");
  }
  constructor(env) {
    let parsed = {};
    try {
      parsed = JSON.parse(env.SESSION_SIGNING_KEYS || "{}");
    } catch {
      parsed = {};
    }
    this.keys = parsed;
    this.activeKid = env.SESSION_ACTIVE_KID;
  }
  getActiveKid() {
    return this.activeKid;
  }
  getActiveSecret() {
    const secret = this.keys[this.activeKid];
    if (!secret) throw new Error("no_active_signing_key_configured");
    return secret;
  }
  getVerificationSecret(kid) {
    return this.keys[kid] || null;
  }
};
async function hashBiosId(biosId) {
  const normalized = String(biosId || "").trim().toUpperCase();
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(hashBiosId, "hashBiosId");
__name2(hashBiosId, "hashBiosId");
function generateJti() {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
__name(generateJti, "generateJti");
__name2(generateJti, "generateJti");
function stringToBase64Url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
__name(stringToBase64Url, "stringToBase64Url");
__name2(stringToBase64Url, "stringToBase64Url");
function base64UrlToString(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}
__name(base64UrlToString, "base64UrlToString");
__name2(base64UrlToString, "base64UrlToString");
async function createClientToken(env, licenseId, planId, biosId) {
  try {
    const now = Date.now();
    const biosHash = await hashBiosId(biosId);
    const claims = {
      lid: licenseId,
      pid: planId,
      bh: biosHash,
      iat: now,
      exp: now + CLIENT_SESSION_TTL_MS,
      jti: generateJti()
    };
    const claimsB64 = stringToBase64Url(JSON.stringify(claims));
    const keyManager = new KeyManager(env);
    const kid = keyManager.getActiveKid();
    const signingInput = `${kid}.${claimsB64}`;
    const secret = keyManager.getActiveSecret();
    const signature = await hmacSign(secret, signingInput);
    return `${signingInput}.${signature}`;
  } catch (e) {
    throw new Error("token_creation_failed: " + e.message);
  }
}
__name(createClientToken, "createClientToken");
__name2(createClientToken, "createClientToken");
async function verifyClientToken(env, token, providedBiosId) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [kid, claimsB64, signature] = parts;
  const keyManager = new KeyManager(env);
  const secret = keyManager.getVerificationSecret(kid);
  if (!secret) return null;
  const signingInput = `${kid}.${claimsB64}`;
  const expectedSignature = await hmacSign(secret, signingInput);
  if (!timingSafeEqual(signature, expectedSignature)) return null;
  let claims;
  try {
    claims = JSON.parse(base64UrlToString(claimsB64));
  } catch {
    return null;
  }
  const { lid: licenseId, pid: planId, bh: biosHash, iat, exp, jti } = claims;
  if (!licenseId || !planId || !biosHash || !exp) return null;
  if (Date.now() > exp) return null;
  if (providedBiosId) {
    const providedHash = await hashBiosId(providedBiosId);
    if (!timingSafeEqual(biosHash, providedHash)) return null;
  }
  try {
    const license = await env.DB.prepare(
      "SELECT revokedAt, expiryDate FROM licenses WHERE id = ?"
    ).bind(licenseId).first();
    if (!license) return null;
    if (license.revokedAt) return null;
    if (new Date(license.expiryDate).getTime() < Date.now()) return null;
  } catch {
    return null;
  }
  return { licenseId, planId };
}
__name(verifyClientToken, "verifyClientToken");
__name2(verifyClientToken, "verifyClientToken");
function getBearerToken(request) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}
__name(getBearerToken, "getBearerToken");
__name2(getBearerToken, "getBearerToken");
async function requireClientAuth(request, env) {
  const token = getBearerToken(request);
  const biosId = request.headers.get("X-Device-Id");
  return verifyClientToken(env, token, biosId);
}
__name(requireClientAuth, "requireClientAuth");
__name2(requireClientAuth, "requireClientAuth");
async function checkRateLimit(env, key, maxAttempts, windowMs) {
  let state;
  try {
    const raw = await env.CONFIG_KV.get(key);
    state = raw ? JSON.parse(raw) : { count: 0, windowStart: Date.now() };
  } catch {
    state = { count: 0, windowStart: Date.now() };
  }
  const active = Date.now() - state.windowStart <= windowMs;
  if (active && state.count >= maxAttempts) {
    const retryAfterSeconds = Math.max(1, Math.ceil((state.windowStart + windowMs - Date.now()) / 1e3));
    return { allowed: false, retryAfterSeconds };
  }
  const nextState = active ? { count: state.count + 1, windowStart: state.windowStart } : { count: 1, windowStart: Date.now() };
  try {
    await env.CONFIG_KV.put(key, JSON.stringify(nextState), { expirationTtl: Math.ceil(windowMs / 1e3) });
  } catch {
  }
  return { allowed: true };
}
__name(checkRateLimit, "checkRateLimit");
__name2(checkRateLimit, "checkRateLimit");
async function logSecurityEvent(env, eventType, { licenseId = null, ip = null } = {}) {
  try {
    await env.DB.prepare(
      "INSERT INTO security_events (event_type, license_id, ip, created_at) VALUES (?, ?, ?, ?)"
    ).bind(eventType, licenseId, ip, (/* @__PURE__ */ new Date()).toISOString()).run();
  } catch {
  }
}
__name(logSecurityEvent, "logSecurityEvent");
__name2(logSecurityEvent, "logSecurityEvent");
async function handleValidate(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const token = authHeader.slice(7);
  const deviceId = request.headers.get("X-Device-Id");
  if (!deviceId) {
    return jsonResponse({ error: "missing_device_id" }, 400);
  }
  const payload = await verifyToken(token, env);
  if (!payload) {
    return jsonResponse({ error: "invalid_token" }, 401);
  }
  const license = await env.DB.prepare(
    "SELECT id, createdAt, expiryDate, revokedAt, biosId FROM licenses WHERE id = ?"
  ).bind(payload.licenseId).first();
  if (!license) {
    return jsonResponse({ error: "license_not_found" }, 404);
  }
  if (license.revokedAt) {
    return jsonResponse({ error: "license_revoked" }, 403);
  }
  if (new Date(license.expiryDate).getTime() <= Date.now()) {
    return jsonResponse({ error: "license_expired" }, 403);
  }
  const deviceIdHash = await hashBiosId(deviceId);
  const deviceMatches = /* @__PURE__ */ __name2((stored) => {
    if (!stored) return true;
    const s = String(stored).trim();
    if (s === deviceIdHash) return true;
    if (s.toUpperCase() === String(deviceId || "").trim().toUpperCase()) return true;
    return false;
  }, "deviceMatches");
  if (!license.biosId || !deviceMatches(license.biosId)) {
    return jsonResponse({ error: "device_not_authorized" }, 403);
  }
  return jsonResponse({
    success: true,
    status: "ACTIVE",
    planId: PRO_PLAN_ID,
    licenseId: license.id,
    createdAt: license.createdAt,
    expiryDate: license.expiryDate
  });
}
__name(handleValidate, "handleValidate");
__name2(handleValidate, "handleValidate");
async function handleRenew(request, env) {
  const ip = getClientIp(request);
  const rl = await checkRateLimit(env, `ratelimit:renew:${getClientIp(request)}`, 30, 60 * 1e3);
  if (!rl.allowed) {
    return jsonResponse({ error: "too_many_attempts", retryAfterSeconds: rl.retryAfterSeconds }, 429, { "Cache-Control": "no-store" });
  }
  const token = getBearerToken(request);
  const rawBiosId = request.headers.get("X-Device-Id");
  if (!token || !rawBiosId) {
    return jsonResponse({ error: "missing_fields" }, 400, { "Cache-Control": "no-store" });
  }
  const verified = await verifyClientToken(env, token, rawBiosId);
  if (!verified) {
    await logSecurityEvent(env, "token_renewal_rejected", { ip });
    return jsonResponse({ error: "invalid_token" }, 401, { "Cache-Control": "no-store" });
  }
  const license = await env.DB.prepare(
    "SELECT id, createdAt, biosId, revokedAt, expiryDate FROM licenses WHERE id = ?"
  ).bind(verified.licenseId).first();
  if (!license) {
    await logSecurityEvent(env, "token_renewal_rejected", { licenseId: verified.licenseId, ip });
    return jsonResponse({ error: "invalid_license" }, 401, { "Cache-Control": "no-store" });
  }
  if (license.revokedAt) {
    await logSecurityEvent(env, "token_renewal_rejected", { licenseId: license.id, ip });
    return jsonResponse({ error: "license_revoked" }, 403, { "Cache-Control": "no-store" });
  }
  if (new Date(license.expiryDate).getTime() < Date.now()) {
    await logSecurityEvent(env, "token_renewal_rejected", { licenseId: license.id, ip });
    return jsonResponse({ error: "license_expired" }, 403, { "Cache-Control": "no-store" });
  }
  const currentBiosHash = await hashBiosId(rawBiosId);
  const biosMatches = /* @__PURE__ */ __name2((stored) => {
    if (!stored) return true;
    const s = String(stored).trim();
    if (s === currentBiosHash) return true;
    if (s.toUpperCase() === String(rawBiosId || "").trim().toUpperCase()) return true;
    return false;
  }, "biosMatches");
  if (!biosMatches(license.biosId)) {
    await logSecurityEvent(env, "token_renewal_rejected", { licenseId: license.id, ip });
    return jsonResponse({ error: "device_not_authorized" }, 403, { "Cache-Control": "no-store" });
  }
  const newToken = await createClientToken(env, license.id, PRO_PLAN_ID, rawBiosId);
  await logSecurityEvent(env, "token_renewed", { licenseId: license.id, ip });
  return jsonResponse(
    {
      token: newToken,
      expiresAt: Date.now() + CLIENT_SESSION_TTL_MS,
      planId: PRO_PLAN_ID,
      licenseId: license.id,
      createdAt: license.createdAt,
      expiryDate: license.expiryDate
    },
    200,
    { "Cache-Control": "no-store" }
  );
}
__name(handleRenew, "handleRenew");
__name2(handleRenew, "handleRenew");
async function handleActivate(request, env) {
  const ip = getClientIp(request);
  const rl = await checkRateLimit(env, `ratelimit:activate:${ip}`, 5, 15 * 60 * 1e3);
  if (!rl.allowed) {
    return jsonResponse(
      { error: "too_many_attempts", retryAfterSeconds: rl.retryAfterSeconds },
      429,
      { "Retry-After": String(rl.retryAfterSeconds), "Cache-Control": "no-store" }
    );
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400, { "Cache-Control": "no-store" });
  }
  const { key, email, biosId } = body || {};
  if (typeof key !== "string" || !key || typeof email !== "string" || !email || typeof biosId !== "string" || !biosId) {
    return jsonResponse({ error: "missing_fields" }, 400, { "Cache-Control": "no-store" });
  }
  const biosIdHash = await hashBiosId(biosId);
  const license = await env.DB.prepare(
    "SELECT id, createdAt, expiryDate, biosId, email, revokedAt FROM licenses WHERE key = ?"
  ).bind(key).first();
  if (!license) {
    await logSecurityEvent(env, "activation_invalid_key", { ip });
    return jsonResponse({ error: "invalid_license" }, 401, { "Cache-Control": "no-store" });
  }
  if (license.revokedAt) {
    await logSecurityEvent(env, "activation_revoked", { licenseId: license.id, ip });
    return jsonResponse({ error: "license_revoked" }, 403, { "Cache-Control": "no-store" });
  }
  if (new Date(license.expiryDate).getTime() < Date.now()) {
    await logSecurityEvent(env, "activation_expired", { licenseId: license.id, ip });
    return jsonResponse({ error: "license_expired" }, 403, { "Cache-Control": "no-store" });
  }
  const storedEmail = (license.email || "").trim().toLowerCase();
  const providedEmail = (email || "").trim().toLowerCase();
  if (!storedEmail || storedEmail !== providedEmail) {
    await logSecurityEvent(env, "activation_invalid_email", { licenseId: license.id, ip });
    return jsonResponse({ error: "invalid_email" }, 401, { "Cache-Control": "no-store" });
  }
  const biosMatches = /* @__PURE__ */ __name2((stored) => {
    if (!stored) return true;
    const s = String(stored).trim();
    if (s === biosIdHash) return true;
    if (s.toUpperCase() === String(biosId || "").trim().toUpperCase()) return true;
    return false;
  }, "biosMatches");
  if (license.biosId && !biosMatches(license.biosId)) {
    await logSecurityEvent(env, "activation_device_mismatch", { licenseId: license.id, ip });
    return jsonResponse({ error: "device_mismatch" }, 403, { "Cache-Control": "no-store" });
  }
  if (!license.biosId) {
    const bindResult = await env.DB.prepare(
      "UPDATE licenses SET biosId = ? WHERE id = ? AND biosId IS NULL"
    ).bind(biosIdHash, license.id).run();
    if (bindResult.meta.changes === 0) {
      const refreshed = await env.DB.prepare(
        "SELECT biosId FROM licenses WHERE id = ?"
      ).bind(license.id).first();
      if (!refreshed || !biosMatches(refreshed.biosId)) {
        await logSecurityEvent(env, "activation_device_mismatch_race", { licenseId: license.id, ip });
        return jsonResponse({ error: "device_mismatch" }, 403, { "Cache-Control": "no-store" });
      }
    }
  }
  const token = await createClientToken(env, license.id, PRO_PLAN_ID, biosId);
  await logSecurityEvent(env, "activation_success", { licenseId: license.id, ip });
  return jsonResponse(
    {
      success: true,
      token,
      planId: PRO_PLAN_ID,
      licenseId: license.id,
      createdAt: license.createdAt,
      expiryDate: license.expiryDate,
      expiresAt: Date.now() + CLIENT_SESSION_TTL_MS
    },
    200,
    { "Cache-Control": "no-store" }
  );
}
__name(handleActivate, "handleActivate");
__name2(handleActivate, "handleActivate");
async function handlePermissions(request, env) {
  const session = await requireClientAuth(request, env);
  if (!session) return jsonResponse({ error: "unauthorized" }, 401, { "Cache-Control": "no-store" });
  return jsonResponse({ planId: session.planId, permissions: {} }, 200, { "Cache-Control": "no-store" });
}
__name(handlePermissions, "handlePermissions");
__name2(handlePermissions, "handlePermissions");
async function guardPublicContent(request, env, serviceName) {
  const session = await requireClientAuth(request, env);
  if (!session) {
    return { allowed: false, response: jsonResponse({ error: "unauthorized" }, 401, { "Cache-Control": "no-store" }) };
  }
  const rl = await checkRateLimit(env, `ratelimit:content:${session.licenseId}`, 60, 60 * 1e3);
  if (!rl.allowed) {
    return {
      allowed: false,
      response: jsonResponse(
        { error: "too_many_requests", retryAfterSeconds: rl.retryAfterSeconds },
        429,
        { "Retry-After": String(rl.retryAfterSeconds), "Cache-Control": "no-store" }
      )
    };
  }
  return { allowed: true };
}
__name(guardPublicContent, "guardPublicContent");
__name2(guardPublicContent, "guardPublicContent");
async function guardContentSection(request, env, section) {
  const session = await requireClientAuth(request, env);
  if (!session) {
    return { allowed: false, response: jsonResponse({ error: "unauthorized" }, 401, { "Cache-Control": "no-store" }) };
  }
  const rl = await checkRateLimit(env, `ratelimit:content:${session.licenseId}`, 60, 60 * 1e3);
  if (!rl.allowed) {
    return {
      allowed: false,
      response: jsonResponse(
        { error: "too_many_requests", retryAfterSeconds: rl.retryAfterSeconds },
        429,
        { "Retry-After": String(rl.retryAfterSeconds), "Cache-Control": "no-store" }
      )
    };
  }
  return { allowed: true };
}
__name(guardContentSection, "guardContentSection");
__name2(guardContentSection, "guardContentSection");
var PAYPAL_API_BASE = "https://api-m.paypal.com";
var PaymentStatus = Object.freeze({
  CREATED: "CREATED",
  APPROVED: "APPROVED",
  CAPTURED: "CAPTURED",
  VERIFIED: "VERIFIED",
  LICENSE_ISSUED: "LICENSE_ISSUED",
  FAILED: "FAILED",
  REFUNDED: "REFUNDED",
  REVERSED: "REVERSED",
  DISPUTED: "DISPUTED"
});
var ErrorCodes = Object.freeze({
  INVALID_LICENSE: "invalid_license",
  INVALID_EMAIL: "invalid_email",
  DEVICE_NOT_AUTHORIZED: "device_not_authorized",
  LICENSE_EXPIRED: "license_expired",
  LICENSE_REVOKED: "license_revoked",
  PENDING_ACTIVATION: "pending_activation",
  INVALID_TOKEN: "invalid_token",
  TOKEN_EXPIRED: "token_expired",
  PAYMENT_NOT_FOUND: "payment_not_found",
  PAYMENT_ALREADY_PROCESSED: "payment_already_processed",
  PAYMENT_VERIFICATION_FAILED: "payment_verification_failed",
  PAYMENT_AMOUNT_MISMATCH: "payment_amount_mismatch",
  INVALID_OFFER: "invalid_offer",
  RATE_LIMITED: "rate_limited",
  INVALID_BODY: "invalid_body",
  INTERNAL_ERROR: "internal_error"
});
var PURCHASE_PLANS = {
  monthly: { amount: "3.00", currency: "USD", durationDays: 30, label: "\u0634\u0647\u0631\u064A" },
  yearly: { amount: "11.00", currency: "USD", durationDays: 365, label: "\u0633\u0646\u0648\u064A" }
};
function matchesOffer(offer, amount, currency) {
  return !!offer && Math.abs(parseFloat(amount) - parseFloat(offer.amount)) < 1e-3 && String(currency).toUpperCase() === offer.currency.toUpperCase();
}
__name(matchesOffer, "matchesOffer");
__name2(matchesOffer, "matchesOffer");
function generateLicenseId() {
  return `license-${Date.now()}`;
}
__name(generateLicenseId, "generateLicenseId");
__name2(generateLicenseId, "generateLicenseId");
function generateLicenseKey() {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const randomGroup = /* @__PURE__ */ __name2(() => {
    const bytes = crypto.getRandomValues(new Uint8Array(5));
    return Array.from(bytes, (b) => charset[b % charset.length]).join("");
  }, "randomGroup");
  return `RACHID-${randomGroup()}-${randomGroup()}-${randomGroup()}`;
}
__name(generateLicenseKey, "generateLicenseKey");
__name2(generateLicenseKey, "generateLicenseKey");
function formatExpiryDate(daysFromNow) {
  return new Date(Date.now() + daysFromNow * 24 * 60 * 60 * 1e3).toISOString().slice(0, 16);
}
__name(formatExpiryDate, "formatExpiryDate");
__name2(formatExpiryDate, "formatExpiryDate");
async function getPayPalAccessToken(env) {
  const credentials = btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`);
  const res = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${credentials}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials"
  });
  if (!res.ok) {
    let bodyText = "";
    try {
      bodyText = await res.text();
    } catch {
      bodyText = "<unreadable_body>";
    }
    const err = new Error("paypal_auth_failed");
    err.diagnostic = {
      stage: "oauth",
      status: res.status,
      paypal_body: safeTruncate(bodyText, 500)
    };
    throw err;
  }
  return (await res.json()).access_token;
}
__name(getPayPalAccessToken, "getPayPalAccessToken");
__name2(getPayPalAccessToken, "getPayPalAccessToken");
async function isAlreadyProcessed(env, captureId) {
  try {
    return !!await env.CONFIG_KV.get(`paypal_txn:${captureId}`);
  } catch {
    return false;
  }
}
__name(isAlreadyProcessed, "isAlreadyProcessed");
__name2(isAlreadyProcessed, "isAlreadyProcessed");
async function markAsProcessed(env, captureId) {
  try {
    await env.CONFIG_KV.put(`paypal_txn:${captureId}`, "1", { expirationTtl: 60 * 24 * 60 * 60 });
  } catch {
  }
}
__name(markAsProcessed, "markAsProcessed");
__name2(markAsProcessed, "markAsProcessed");
async function sendLicenseEmail(env, toEmail, licenseKey, planLabel) {
  if (!toEmail) return { sent: false, reason: "no_email_available" };
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "Veltrix32 <noreply@yourdomain.com>",
        // ⚠️ استبدل بنطاقك المتحقَّق في Resend
        to: [toEmail],
        subject: "\u0645\u0641\u062A\u0627\u062D \u062A\u0631\u062E\u064A\u0635 Veltrix32 Pro \u0627\u0644\u062E\u0627\u0635 \u0628\u0643",
        html: `<div dir="rtl" style="font-family:Arial,sans-serif;">
          <h2>\u0634\u0643\u0631\u064B\u0627 \u0644\u0627\u0634\u062A\u0631\u0627\u0643\u0643 \u0641\u064A \u062E\u0637\u0629 Pro (${planLabel})</h2>
          <p style="font-size:20px;font-weight:bold;background:#f2f2f2;padding:12px;border-radius:8px;">${licenseKey}</p>
        </div>`
      })
    });
    return { sent: res.ok, reason: res.ok ? null : `resend_error_${res.status}` };
  } catch {
    return { sent: false, reason: "resend_network_error" };
  }
}
__name(sendLicenseEmail, "sendLicenseEmail");
__name2(sendLicenseEmail, "sendLicenseEmail");
async function issueLicenseForPayment(env, { captureId, orderId, planKey, amount, buyerEmail }) {
  if (await isAlreadyProcessed(env, captureId)) {
    return { alreadyIssued: true };
  }
  const plan = PURCHASE_PLANS[planKey];
  if (!plan) {
    await logSecurityEvent(env, "payment_rejected_invalid_plan", {});
    return { error: ErrorCodes.INVALID_OFFER };
  }
  const licenseId = generateLicenseId();
  const licenseKey = generateLicenseKey();
  const expiryDate = formatExpiryDate(plan.durationDays);
  const username = buyerEmail ? buyerEmail.split("@")[0] : "customer";
  const createdAt = (/* @__PURE__ */ new Date()).toISOString().slice(0, 16);
  await env.DB.prepare(
    `INSERT INTO payment_events (captureId, orderId, planKey, amount, buyerEmail, license_id, status, createdAt)
     VALUES (?, ?, ?, ?, ?, NULL, ?, ?)`
  ).bind(captureId, orderId || null, planKey, amount, buyerEmail || null, PaymentStatus.CAPTURED, (/* @__PURE__ */ new Date()).toISOString()).run();
  await logSecurityEvent(env, "payment_captured", {});
  if (!matchesOffer(plan, amount, "USD")) {
    await env.DB.prepare("UPDATE payment_events SET status = ? WHERE captureId = ?").bind(PaymentStatus.FAILED, captureId).run();
    await logSecurityEvent(env, "payment_rejected_amount_mismatch", {});
    return { error: ErrorCodes.PAYMENT_AMOUNT_MISMATCH };
  }
  await env.DB.prepare("UPDATE payment_events SET status = ? WHERE captureId = ?").bind(PaymentStatus.VERIFIED, captureId).run();
  await logSecurityEvent(env, "payment_verified", {});
  await env.DB.prepare(
    `INSERT INTO licenses (id, username, email, key, createdAt, expiryDate, devices, biosId)
     VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`
  ).bind(
    licenseId,
    username,
    buyerEmail || null,
    licenseKey,
    createdAt,
    expiryDate,
    1
  ).run();
  await logSecurityEvent(env, "license_created", { licenseId });
  await env.DB.prepare("UPDATE payment_events SET license_id = ?, status = ? WHERE captureId = ?").bind(licenseId, PaymentStatus.LICENSE_ISSUED, captureId).run();
  await markAsProcessed(env, captureId);
  const emailResult = await sendLicenseEmail(env, buyerEmail, licenseKey, plan.label);
  return { alreadyIssued: false, licenseKey, expiryDate, planLabel: plan.label, emailSent: emailResult.sent };
}
__name(issueLicenseForPayment, "issueLicenseForPayment");
__name2(issueLicenseForPayment, "issueLicenseForPayment");
async function handlePurchaseConfig(env) {
  return jsonResponse(
    {
      clientId: env.PAYPAL_CLIENT_ID,
      currency: "USD",
      plans: Object.entries(PURCHASE_PLANS).map(([key, p]) => ({
        key,
        amount: p.amount,
        durationDays: p.durationDays,
        label: p.label
      }))
    },
    200,
    { "Cache-Control": "public, max-age=300" }
  );
}
__name(handlePurchaseConfig, "handlePurchaseConfig");
__name2(handlePurchaseConfig, "handlePurchaseConfig");
async function handleCreateOrder(request, env) {
  const rl = await checkRateLimit(env, `ratelimit:purchase-create:${getClientIp(request)}`, 20, 60 * 1e3);
  if (!rl.allowed) {
    return jsonResponse({ error: "too_many_requests", retryAfterSeconds: rl.retryAfterSeconds }, 429, {
      "Cache-Control": "no-store"
    });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400, { "Cache-Control": "no-store" });
  }
  const plan = PURCHASE_PLANS[body?.planKey];
  if (!plan) return jsonResponse({ error: "invalid_plan_key" }, 400, { "Cache-Control": "no-store" });
  try {
    const accessToken = await getPayPalAccessToken(env);
    const orderRes = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        intent: "CAPTURE",
        purchase_units: [{ amount: { currency_code: plan.currency, value: plan.amount } }]
      })
    });
    if (!orderRes.ok) return jsonResponse({ error: "paypal_order_failed" }, 502, { "Cache-Control": "no-store" });
    const order = await orderRes.json();
    await env.CONFIG_KV.put(`pending_order:${order.id}`, body.planKey, { expirationTtl: 3600 });
    const approveUrl = order.links?.find((link) => link.rel === "approve")?.href || null;
    return jsonResponse(
      {
        success: true,
        orderId: order.id,
        approveUrl
      },
      200,
      { "Cache-Control": "no-store" }
    );
  } catch (e) {
    console.error("[create-order] Unhandled error", {
      message: e?.message,
      diagnostic: e?.diagnostic || null
    });
    return jsonResponse(
      {
        error: "paypal_error",
        debug: {
          message: e?.message || "unknown",
          ...e?.diagnostic || {}
        }
      },
      502,
      { "Cache-Control": "no-store" }
    );
  }
}
__name(handleCreateOrder, "handleCreateOrder");
__name2(handleCreateOrder, "handleCreateOrder");
async function handleCaptureOrder(request, env) {
  const rl = await checkRateLimit(env, `ratelimit:purchase-capture:${getClientIp(request)}`, 20, 60 * 1e3);
  if (!rl.allowed) {
    return jsonResponse({ error: "too_many_requests", retryAfterSeconds: rl.retryAfterSeconds }, 429, {
      "Cache-Control": "no-store"
    });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_body" }, 400, { "Cache-Control": "no-store" });
  }
  const orderId = body?.orderId;
  if (typeof orderId !== "string" || !orderId) {
    return jsonResponse({ error: "missing_order_id" }, 400, { "Cache-Control": "no-store" });
  }
  let captureData;
  try {
    const accessToken = await getPayPalAccessToken(env);
    const captureRes = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders/${orderId}/capture`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" }
    });
    if (!captureRes.ok) return jsonResponse({ error: "capture_failed" }, 502, { "Cache-Control": "no-store" });
    captureData = await captureRes.json();
  } catch {
    return jsonResponse({ error: "paypal_error" }, 502, { "Cache-Control": "no-store" });
  }
  const capture = captureData.purchase_units?.[0]?.payments?.captures?.[0];
  if (!capture || capture.status !== "COMPLETED") {
    return jsonResponse({ error: "payment_not_completed" }, 402, { "Cache-Control": "no-store" });
  }
  const amount = parseFloat(capture.amount?.value ?? "0");
  const buyerEmail = captureData.payer?.email_address || null;
  const savedPlanKey = await env.CONFIG_KV.get(`pending_order:${orderId}`);
  if (!savedPlanKey) {
    return jsonResponse({ error: "order_not_found_or_expired" }, 400, { "Cache-Control": "no-store" });
  }
  const result = await issueLicenseForPayment(env, { captureId: capture.id, orderId, planKey: savedPlanKey, amount, buyerEmail });
  if (result.error) {
    await logSecurityEvent(env, "payment_capture_failed", {});
    return jsonResponse({ error: result.error }, 402, { "Cache-Control": "no-store" });
  }
  if (result.alreadyIssued) {
    await logSecurityEvent(env, "payment_capture_already_processed", {});
    return jsonResponse({ success: true, alreadyIssued: true }, 200, { "Cache-Control": "no-store" });
  }
  await logSecurityEvent(env, "payment_capture_success", { licenseId: result.licenseId });
  return jsonResponse(
    {
      success: true,
      licenseKey: result.licenseKey,
      expiryDate: result.expiryDate,
      planLabel: result.planLabel,
      emailSent: result.emailSent
    },
    200,
    { "Cache-Control": "no-store" }
  );
}
__name(handleCaptureOrder, "handleCaptureOrder");
__name2(handleCaptureOrder, "handleCaptureOrder");
async function verifyPayPalWebhookSignature(env, request, rawBody) {
  const accessToken = await getPayPalAccessToken(env);
  const res = await fetch(`${PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      transmission_id: request.headers.get("paypal-transmission-id"),
      transmission_time: request.headers.get("paypal-transmission-time"),
      cert_url: request.headers.get("paypal-cert-url"),
      auth_algo: request.headers.get("paypal-auth-algo"),
      transmission_sig: request.headers.get("paypal-transmission-sig"),
      webhook_id: env.PAYPAL_WEBHOOK_ID,
      webhook_event: JSON.parse(rawBody)
    })
  });
  if (!res.ok) return false;
  return (await res.json()).verification_status === "SUCCESS";
}
__name(verifyPayPalWebhookSignature, "verifyPayPalWebhookSignature");
__name2(verifyPayPalWebhookSignature, "verifyPayPalWebhookSignature");
var REFUND_EVENT_TYPES = {
  "PAYMENT.CAPTURE.REFUNDED": "REFUNDED",
  "PAYMENT.CAPTURE.REVERSED": "REVERSED",
  "DISPUTE.CREATED": "DISPUTED"
};
function extractOriginalCaptureId(resource) {
  if (!resource) return null;
  const ref = resource?.supplementary_data?.related_ids?.original_capture_id;
  return ref || resource?.parent_capture || resource?.capture_id || null;
}
__name(extractOriginalCaptureId, "extractOriginalCaptureId");
__name2(extractOriginalCaptureId, "extractOriginalCaptureId");
async function handlePayPalWebhook(request, env) {
  const rawBody = await request.text();
  const ip = getClientIp(request);
  let isValid = false;
  try {
    isValid = await verifyPayPalWebhookSignature(env, request, rawBody);
  } catch {
    await logSecurityEvent(env, "webhook_verification_failed", { ip });
    return jsonResponse({ error: "verification_failed" }, 400, { "Cache-Control": "no-store" });
  }
  if (!isValid) {
    await logSecurityEvent(env, "webhook_invalid_signature", { ip });
    return jsonResponse({ error: "invalid_signature" }, 400, { "Cache-Control": "no-store" });
  }
  const event = JSON.parse(rawBody);
  if (event.event_type === "PAYMENT.CAPTURE.COMPLETED" && event.resource?.status === "COMPLETED") {
    const captureId = event.resource.id;
    if (!captureId) return jsonResponse({ error: "missing_capture_id" }, 400, { "Cache-Control": "no-store" });
    const orderId = event.resource?.supplementary_data?.related_ids?.order_id || null;
    const amount = parseFloat(event.resource.amount?.value ?? "0");
    const buyerEmail = event.resource.payer?.email_address || null;
    let savedPlanKey = null;
    if (orderId) {
      savedPlanKey = await env.CONFIG_KV.get(`pending_order:${orderId}`);
    }
    if (!savedPlanKey) {
      await logSecurityEvent(env, "payment_webhook_missing_plan_key", { ip });
      return jsonResponse({ received: true, error: "plan_not_found" }, 200, { "Cache-Control": "no-store" });
    }
    const result = await issueLicenseForPayment(env, { captureId, orderId, planKey: savedPlanKey, amount, buyerEmail });
    await logSecurityEvent(env, "payment_webhook_processed", { ip });
    return jsonResponse({ received: true, licenseCreated: !result.alreadyIssued }, 200, { "Cache-Control": "no-store" });
  }
  if (REFUND_EVENT_TYPES[event.event_type]) {
    const originalCaptureId = extractOriginalCaptureId(event.resource) || event.resource?.id;
    if (!originalCaptureId) {
      return jsonResponse({ error: "missing_capture_id" }, 400, { "Cache-Control": "no-store" });
    }
    const payment = await env.DB.prepare("SELECT license_id FROM payment_events WHERE captureId = ?").bind(originalCaptureId).first();
    const licenseId = payment ? payment.license_id : null;
    await env.DB.prepare("UPDATE payment_events SET status = ? WHERE captureId = ?").bind(REFUND_EVENT_TYPES[event.event_type], originalCaptureId).run();
    if (licenseId) {
      await env.DB.prepare("UPDATE licenses SET revokedAt = ? WHERE id = ?").bind((/* @__PURE__ */ new Date()).toISOString(), licenseId).run();
    }
    await logSecurityEvent(env, `payment_${REFUND_EVENT_TYPES[event.event_type].toLowerCase()}`, { licenseId, ip });
    return jsonResponse({ handled: true }, 200, { "Cache-Control": "no-store" });
  }
  return jsonResponse({ ignored: true }, 200, { "Cache-Control": "no-store" });
}
__name(handlePayPalWebhook, "handlePayPalWebhook");
__name2(handlePayPalWebhook, "handlePayPalWebhook");
async function handlePublicLatestUpdate(request, env) {
  const url = new URL(request.url);
  const name = url.searchParams.get("name");
  let query = "SELECT id, name, version, url FROM updates";
  const params = [];
  if (name) {
    query += " WHERE name = ?";
    params.push(name);
  }
  const { results } = await env.DB.prepare(query).bind(...params).all();
  if (!results.length) {
    return jsonResponse({ error: "not_found" }, 404, { "Cache-Control": "no-store" });
  }
  const compareVersions = (a, b) => {
    const pa = String(a).split(".").map(Number);
    const pb = String(b).split(".").map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const diff = (pa[i] || 0) - (pb[i] || 0);
      if (diff !== 0) return diff;
    }
    return 0;
  };
  const latest = results.reduce((best, row) => (compareVersions(row.version, best.version) > 0 ? row : best));
  return jsonResponse({ name: latest.name, version: latest.version, url: latest.url }, 200, {
    "Cache-Control": "public, max-age=120"
  });
}
var worker_default = {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;
      if (path === "/test") {
        let kvStatus = "ERROR";
        let d1Status = "ERROR";
        let kvValue = null;
        let d1Result = null;
        try {
          await env.CONFIG_KV.put("system_test", "KV_OK");
          kvValue = await env.CONFIG_KV.get("system_test");
          kvStatus = kvValue === "KV_OK" ? "OK" : "FAILED";
        } catch {
          kvStatus = "FAILED";
        }
        try {
          d1Result = await env.DB.prepare("SELECT 1 AS test").first();
          d1Status = d1Result?.test === 1 ? "OK" : "FAILED";
        } catch {
          d1Status = "FAILED";
        }
        return jsonResponse({
          success: kvStatus === "OK" && d1Status === "OK",
          KV: { status: kvStatus },
          D1: { status: d1Status }
        }, 200, SECURITY_HEADERS);
      }
      if (path === "/") {
        return jsonResponse({ success: true, service: "Veltrix37 API", status: "online" });
      }
      if (path === "/api/v1/updates/latest" && method === "GET") {
        return handlePublicLatestUpdate(request, env);
      }
      if (path === "/api/v1/activate" && method === "POST") {
        return handleActivate(request, env);
      }
      if (path === "/api/v1/auth/renew" && method === "POST") {
        return handleRenew(request, env);
      }
      if (path === "/api/v1/permissions" && method === "GET") {
        return handlePermissions(request, env);
      }
      if (path === "/api/v1/content/plugins" && method === "GET") {
        const guard = await guardPublicContent(request, env, "plugins");
        if (!guard.allowed) return guard.response;
        try {
          const { results } = await env.DB.prepare("SELECT id, name, description, version, images, url, fileSize, exeName FROM plugins ORDER BY id").all();
          return jsonResponse(results, 200, { "Cache-Control": "private, max-age=300" });
        } catch {
          return jsonResponse({ error: "internal_error" }, 500, { "Cache-Control": "no-store" });
        }
      }
      if (path === "/api/v1/content/pc_apps" && method === "GET") {
        const guard = await guardPublicContent(request, env, "pc_apps");
        if (!guard.allowed) return guard.response;
        try {
          const { results } = await env.DB.prepare("SELECT id, name, description, version, images, url, fileSize FROM pc_apps ORDER BY id").all();
          return jsonResponse(results, 200, { "Cache-Control": "private, max-age=300" });
        } catch {
          return jsonResponse({ error: "internal_error" }, 500, { "Cache-Control": "no-store" });
        }
      }
      if (path === "/api/v1/content/games" && method === "GET") {
        const guard = await guardPublicContent(request, env, "games");
        if (!guard.allowed) return guard.response;
        try {
          const { results } = await env.DB.prepare("SELECT id, steamId, bypass, onlineFix, steamtools, gameplay, exeName, download, name, cover, short_desc, genres, developers, publishers, released, metacritic, screenshots, pc_min, pc_rec, size_text, trailer, logo, hero, page_bg, steam_synced_at FROM games ORDER BY id").all();
          return jsonResponse(results, 200, { "Cache-Control": "private, max-age=300" });
        } catch {
          return jsonResponse({ error: "internal_error" }, 500, { "Cache-Control": "no-store" });
        }
      }
      if (path === "/api/v1/content/movies" && method === "GET") {
        const guard = await guardContentSection(request, env, "movies");
        if (!guard.allowed) return guard.response;
        try {
          const { results } = await env.DB.prepare("SELECT id, name FROM movies ORDER BY id").all();
          return jsonResponse(results, 200, { "Cache-Control": "private, max-age=300" });
        } catch {
          return jsonResponse({ error: "internal_error" }, 500, { "Cache-Control": "no-store" });
        }
      }
      if (path === "/api/v1/content/series" && method === "GET") {
        const guard = await guardContentSection(request, env, "series");
        if (!guard.allowed) return guard.response;
        try {
          const { results } = await env.DB.prepare("SELECT id, name FROM series ORDER BY id").all();
          return jsonResponse(results, 200, { "Cache-Control": "private, max-age=300" });
        } catch {
          return jsonResponse({ error: "internal_error" }, 500, { "Cache-Control": "no-store" });
        }
      }
      if (path === "/api/v1/content/live_streams" && method === "GET") {
        const guard = await guardContentSection(request, env, "live_streams");
        if (!guard.allowed) return guard.response;
        try {
          const { results } = await env.DB.prepare("SELECT id, name, url FROM live_streams ORDER BY id").all();
          return jsonResponse(results, 200, { "Cache-Control": "private, max-age=60" });
        } catch {
          return jsonResponse({ error: "internal_error" }, 500, { "Cache-Control": "no-store" });
        }
      }
      if (path === "/api/v1/content/affiliate_products" && method === "GET") {
        const guard = await guardContentSection(request, env, "affiliate_products");
        if (!guard.allowed) return guard.response;
        try {
          const { results } = await env.DB.prepare("SELECT id, name, url FROM affiliate_products ORDER BY id").all();
          return jsonResponse(results, 200, { "Cache-Control": "private, max-age=300" });
        } catch {
          return jsonResponse({ error: "internal_error" }, 500, { "Cache-Control": "no-store" });
        }
      }
      if (path === "/api/v1/content/updates" && method === "GET") {
        const guard = await guardContentSection(request, env, "updates");
        if (!guard.allowed) return guard.response;
        try {
          const { results } = await env.DB.prepare("SELECT id, name, version, url FROM updates ORDER BY id").all();
          return jsonResponse(results, 200, { "Cache-Control": "private, max-age=300" });
        } catch {
          return jsonResponse({ error: "internal_error" }, 500, { "Cache-Control": "no-store" });
        }
      }
      if (path === "/rachidov1983admin" && method === "GET") {
        return htmlResponse(adminPanelHtml());
      }
      if (path === "/api/v1/purchase/config" && method === "GET") {
        return handlePurchaseConfig(env);
      }
      if (path === "/api/v1/purchase/create-order" && method === "POST") {
        return handleCreateOrder(request, env);
      }
      if (path === "/api/v1/purchase/capture-order" && method === "POST") {
        return handleCaptureOrder(request, env);
      }
      if (path === "/api/v1/purchase/webhook" && method === "POST") {
        return handlePayPalWebhook(request, env);
      }
      if (path === "/api/v1/activation/activate" && method === "POST") {
        return handleActivate(request, env);
      }
      if (path === "/api/v1/validation/check" && method === "GET") {
        return handleValidate(request, env);
      }
      if (path === "/api/v1/auth/renew" && method === "POST") {
        return handleRenew(request, env);
      }
      if (path === "/admin" && method === "GET") {
        return new Response(null, {
          status: 302,
          headers: { Location: "/rachidov1983admin" }
        });
      }
      if (path === "/admin/login" && method === "POST") {
        return handleAdminLogin(request, env);
      }
      if (path === "/admin/logout" && method === "POST") {
        return handleAdminLogout();
      }
      if (path.startsWith("/api/admin/")) {
        const authed = await requireAuth(request, env);
        if (!authed) {
          return jsonResponse({ error: "unauthorized" }, 401);
        }
        if (path === "/api/admin/dashboard" && method === "GET") {
          return handleDashboardStats(env);
        }
        if (path === "/api/admin/payment-stats" && method === "GET") {
          return handlePaymentStats(request, env);
        }
        if (path === "/api/admin/movies" && method === "GET") return handleListMovies(request, env);
        if (path === "/api/admin/movies" && method === "POST") return handleCreateMovie(request, env);
        const movieIdMatch = path.match(/^\/api\/admin\/movies\/(.+)$/);
        if (movieIdMatch) {
          const id = decodeURIComponent(movieIdMatch[1]);
          if (method === "GET") return handleGetMovie(request, env);
          if (method === "PUT") return handleUpdateMovie(request, env);
          if (method === "DELETE") return handleDeleteMovie(env, id);
        }
        if (path === "/api/admin/series" && method === "GET") return handleListSeries(request, env);
        if (path === "/api/admin/series" && method === "POST") return handleCreateSeries(request, env);
        const seriesIdMatch = path.match(/^\/api\/admin\/series\/(.+)$/);
        if (seriesIdMatch) {
          const id = decodeURIComponent(seriesIdMatch[1]);
          if (method === "GET") return handleGetSeries(request, env);
          if (method === "PUT") return handleUpdateSeries(request, env);
          if (method === "DELETE") return handleDeleteSeries(env, id);
        }
        if (path === "/api/admin/games" && method === "GET") return handleListGames(request, env);
        if (path === "/api/admin/games" && method === "POST") return handleCreateGame(request, env);
        if (path === "/api/admin/games/autofill" && method === "POST") return handleAutofillGame(request, env);
        const gameIdMatch = path.match(/^\/api\/admin\/games\/(.+)$/);
        if (gameIdMatch) {
          const id = decodeURIComponent(gameIdMatch[1]);
          if (method === "GET") return handleGetGame(request, env);
          if (method === "PUT") return handleUpdateGame(request, env);
          if (method === "DELETE") return handleDeleteGame(env, id);
        }
        if (path === "/api/admin/live-streams" && method === "GET") return handleListLiveStreams(request, env);
        if (path === "/api/admin/live-streams" && method === "POST") return handleCreateLiveStream(request, env);
        const liveStreamIdMatch = path.match(/^\/api\/admin\/live-streams\/(.+)$/);
        if (liveStreamIdMatch) {
          const id = decodeURIComponent(liveStreamIdMatch[1]);
          if (method === "GET") return handleGetLiveStream(request, env);
          if (method === "PUT") return handleUpdateLiveStream(request, env);
          if (method === "DELETE") return handleDeleteLiveStream(env, id);
        }
        if (path === "/api/admin/pc-apps" && method === "GET") return handleListPcApps(request, env);
        if (path === "/api/admin/pc-apps" && method === "POST") return handleCreatePcApp(request, env);
        const pcAppIdMatch = path.match(/^\/api\/admin\/pc-apps\/(.+)$/);
        if (pcAppIdMatch) {
          const id = decodeURIComponent(pcAppIdMatch[1]);
          if (method === "GET") return handleGetPcApp(request, env);
          if (method === "PUT") return handleUpdatePcApp(request, env);
          if (method === "DELETE") return handleDeletePcApp(env, id);
        }
        if (path === "/api/admin/plugins" && method === "GET") return handleListPlugins(request, env);
        if (path === "/api/admin/plugins" && method === "POST") return handleCreatePlugin(request, env);
        const pluginIdMatch = path.match(/^\/api\/admin\/plugins\/(.+)$/);
        if (pluginIdMatch) {
          const id = decodeURIComponent(pluginIdMatch[1]);
          if (method === "GET") return handleGetPlugin(request, env);
          if (method === "PUT") return handleUpdatePlugin(request, env);
          if (method === "DELETE") return handleDeletePlugin(env, id);
        }
        if (path === "/api/admin/affiliate-products" && method === "GET") return handleListAffiliateProducts(request, env);
        if (path === "/api/admin/affiliate-products" && method === "POST") return handleCreateAffiliateProduct(request, env);
        const affiliateIdMatch = path.match(/^\/api\/admin\/affiliate-products\/(.+)$/);
        if (affiliateIdMatch) {
          const id = decodeURIComponent(affiliateIdMatch[1]);
          if (method === "GET") return handleGetAffiliateProduct(request, env);
          if (method === "PUT") return handleUpdateAffiliateProduct(request, env);
          if (method === "DELETE") return handleDeleteAffiliateProduct(env, id);
        }
        if (path === "/api/admin/licenses" && method === "GET") return handleListLicenses(request, env);
        if (path === "/api/admin/licenses" && method === "POST") return handleCreateLicense(request, env);
        const licenseIdMatch = path.match(/^\/api\/admin\/licenses\/(.+)$/);
        if (licenseIdMatch) {
          const id = decodeURIComponent(licenseIdMatch[1]);
          if (method === "GET") return handleGetLicense(request, env);
          if (method === "PUT") return handleUpdateLicense(request, env);
          if (method === "DELETE") return handleDeleteLicense(env, id);
        }
        if (path === "/api/admin/updates" && method === "GET") return handleListUpdates(request, env);
        if (path === "/api/admin/updates/latest" && method === "GET") return handleGetLatestUpdate(request, env);
        if (path === "/api/admin/updates" && method === "POST") return handleCreateUpdate(request, env);
        const updateIdMatch = path.match(/^\/api\/admin\/updates\/(.+)$/);
        if (updateIdMatch) {
          const id = decodeURIComponent(updateIdMatch[1]);
          if (method === "GET") return handleGetUpdate(request, env);
          if (method === "PUT") return handleUpdateUpdate(request, env);
          if (method === "DELETE") return handleDeleteUpdate(env, id);
        }
        if (path === "/api/admin/config" && method === "GET") return handleListConfigs(request, env);
        if (path === "/api/admin/config" && method === "POST") return handleCreateConfig(request, env);
        if (path === "/api/admin/upload-url" && method === "POST") return handleGetUploadUrl(request, env);
        if (path === "/api/admin/crypto-test" && method === "GET") return cryptoTest(request, env);
        const configIdMatch = path.match(/^\/api\/admin\/config\/(.+)$/);
        if (configIdMatch) {
          const id = decodeURIComponent(configIdMatch[1]);
          if (method === "GET") return handleGetConfig(request, env);
          if (method === "PUT") return handleUpdateConfig(request, env);
          if (method === "DELETE") return handleDeleteConfig(env, id);
        }
        return jsonResponse({ error: "not_found" }, 404);
      }
      return jsonResponse({ error: "not_found" }, 404);
    } catch (e) {
      return jsonResponse({ error: "internal_error", message: e.message }, 500);
    }
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
