import { Router } from "express";
import _nodeFetch, { Response as NodeFetchResponse } from "node-fetch";
import type { RequestInit as NodeFetchRequestInit } from "node-fetch";
import { HttpsProxyAgent } from "https-proxy-agent";
import crypto from "crypto";
import https from "https";
import http from "http";
import type { IncomingMessage } from "http";

// ─── Proxy support ────────────────────────────────────────────────────────────
// Set PROXY_URL to a residential HTTP/HTTPS proxy (e.g. "http://user:pass@host:port")
// to route all scraper traffic through it. Required for sites whose CDN blocks
// datacenter egress (Aniwave, 9anime, GogoAnime all use the same infrastructure).

let _cachedProxyAgent: HttpsProxyAgent<string> | undefined;

function getProxyAgent(): HttpsProxyAgent<string> | undefined {
  const proxyUrl = process.env.PROXY_URL;
  if (!proxyUrl) return undefined;
  if (!_cachedProxyAgent) _cachedProxyAgent = new HttpsProxyAgent(proxyUrl);
  return _cachedProxyAgent;
}

// Proxy-aware fetch — drop-in replacement for node-fetch.
// All fetch() calls in this file automatically use PROXY_URL when set.
function fetch(
  url: Parameters<typeof _nodeFetch>[0],
  options: NodeFetchRequestInit = {}
) {
  const agent = getProxyAgent();
  return _nodeFetch(url, agent ? { ...options, agent } : options);
}

const router = Router();

// ─── Global CORS — applied to every route including unmatched ones ────────────
router.use((_req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  next();
});

// ─── Shared result interface ──────────────────────────────────────────────────

interface StreamResult {
  url: string;
  type: "mp4" | "hls" | "iframe";
  subtitles: { lang: string; url: string }[];
  intro: { start: number; end: number } | null;
  outro: { start: number; end: number } | null;
  server: string;
  site: string;
}

// ─── Shared request headers for HiAnime ──────────────────────────────────────

function hiHeaders(
  referer = "https://aniwatchtv.to/",
  extra: Record<string, string> = {}
) {
  return {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    Referer: referer,
    Origin: new URL(referer).origin,
    "X-Requested-With": "XMLHttpRequest",
    ...extra,
  };
}

async function hiFetch(url: string, headers: Record<string, string> = {}) {
  const res = await fetch(url, {
    headers: hiHeaders("https://aniwatchtv.to/", headers),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res;
}

// ─── AES-256-CBC decryption (CryptoJS / OpenSSL EVP_BytesToKey format) ───────

function decryptAES(ciphertext: string, password: string): string {
  const buf = Buffer.from(ciphertext, "base64");
  if (buf.slice(0, 8).toString("ascii") !== "Salted__") {
    throw new Error("Not OpenSSL-format ciphertext");
  }
  const salt = buf.slice(8, 16);
  const encData = buf.slice(16);
  const pass = Buffer.from(password, "utf8");

  let d = Buffer.alloc(0);
  let block = Buffer.alloc(0);
  while (d.length < 48) {
    block = crypto
      .createHash("md5")
      .update(Buffer.concat([block, pass, salt]))
      .digest();
    d = Buffer.concat([d, block]);
  }
  const key = d.slice(0, 32);
  const iv = d.slice(32, 48);

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(encData), decipher.final()]).toString(
    "utf8"
  );
}

// ─── Key extraction from obfuscated Megacloud / RapidCloud JS ────────────────

interface KeyCache {
  key: string;
  ts: number;
}
const keyCache: Record<string, KeyCache> = {};
const KEY_TTL = 15 * 60_000;

function extractKeyFromBundle(js: string): string | null {
  const arrRe = /\[(\s*(?:[0-9]{2,3}\s*,\s*){7,}[0-9]{2,3}\s*)\]/g;
  let m: RegExpExecArray | null;
  const candidates: string[] = [];
  while ((m = arrRe.exec(js)) !== null) {
    const nums = m[1].split(",").map((n) => parseInt(n.trim(), 10));
    if (nums.every((n) => n >= 32 && n <= 126)) {
      const s = nums.map((n) => String.fromCharCode(n)).join("");
      if (/^[\x20-\x7e]{8,}$/.test(s)) candidates.push(s);
    }
  }
  if (candidates.length > 0) {
    candidates.sort((a, b) => b.length - a.length);
    return candidates[0];
  }

  const atobRe = /atob\(["']([A-Za-z0-9+/=]{20,})["']\)/g;
  while ((m = atobRe.exec(js)) !== null) {
    try {
      const decoded = Buffer.from(m[1], "base64").toString("utf8");
      if (/^[\x20-\x7e]{8,}$/.test(decoded)) return decoded;
    } catch {
      continue;
    }
  }

  const kwRe =
    /(?:key|password|secret|passwd)\s*[=:]\s*["']([A-Za-z0-9!@#$%^&*()_+\-={}|;':,./<>?]{8,})["']/i;
  const kw = js.match(kwRe);
  if (kw) return kw[1];

  return null;
}

async function getKeyForHost(
  host: string,
  embedHtmlUrl: string
): Promise<string> {
  const cached = keyCache[host];
  if (cached && Date.now() - cached.ts < KEY_TTL) return cached.key;

  const html = await fetch(embedHtmlUrl, {
    headers: hiHeaders("https://aniwatchtv.to/"),
    signal: AbortSignal.timeout(15000),
  }).then((r) => r.text());

  const scriptMatch =
    html.match(/src="(\/js\/[^"]+\.min\.js)"/) ||
    html.match(/src="(\/js\/[^"]+\.js)"/);
  if (!scriptMatch) throw new Error(`No JS bundle found on ${embedHtmlUrl}`);

  const jsUrl = `https://${host}${scriptMatch[1]}`;
  const js = await fetch(jsUrl, {
    headers: hiHeaders(`https://${host}/`),
    signal: AbortSignal.timeout(20000),
  }).then((r) => r.text());

  const key = extractKeyFromBundle(js);
  if (!key) throw new Error(`Key extraction failed for ${host}`);

  keyCache[host] = { key, ts: Date.now() };
  return key;
}

// ─── Megacloud (e-1) ──────────────────────────────────────────────────────────

async function getMegacloudSources(sourceId: string) {
  const embedUrl = `https://megacloud.tv/embed-2/e-1/${sourceId}?k=1`;
  const apiUrl = `https://megacloud.tv/embed-2/ajax/e-1/getSources?id=${sourceId}`;

  const res = await fetch(apiUrl, {
    headers: hiHeaders("https://megacloud.tv/", {
      Referer: embedUrl,
      Origin: "https://megacloud.tv",
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`Megacloud API HTTP ${res.status}`);
  const data = (await res.json()) as Record<string, unknown>;

  let sources: unknown[] = [];
  if (data.encrypted && typeof data.sources === "string") {
    const key = await getKeyForHost("megacloud.tv", embedUrl);
    const decrypted = decryptAES(data.sources as string, key);
    sources = JSON.parse(decrypted) as unknown[];
  } else if (Array.isArray(data.sources)) {
    sources = data.sources as unknown[];
  }

  return {
    sources: sources as { file: string; type: string }[],
    tracks: (data.tracks as unknown[] | null) || [],
    intro: data.intro as { start: number; end: number } | null,
    outro: data.outro as { start: number; end: number } | null,
  };
}

// ─── RapidCloud / VidStreaming (embed-6) ──────────────────────────────────────

async function getRapidCloudSources(sourceId: string, embedUrl: string) {
  const base = new URL(embedUrl).origin;
  const apiUrl = `${base}/ajax/embed-6-v2/getSources?id=${sourceId}`;

  const res = await fetch(apiUrl, {
    headers: hiHeaders(`${base}/`, { Referer: embedUrl, Origin: base }),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`RapidCloud API HTTP ${res.status}`);
  const data = (await res.json()) as Record<string, unknown>;

  let sources: unknown[] = [];
  if (data.encrypted && typeof data.sources === "string") {
    const host = new URL(base).hostname;
    const key = await getKeyForHost(host, embedUrl);
    const decrypted = decryptAES(data.sources as string, key);
    sources = JSON.parse(decrypted) as unknown[];
  } else if (Array.isArray(data.sources)) {
    sources = data.sources as unknown[];
  }

  return {
    sources: sources as { file: string; type: string }[],
    tracks: (data.tracks as unknown[] | null) || [],
    intro: data.intro as { start: number; end: number } | null,
    outro: data.outro as { start: number; end: number } | null,
  };
}

// ─── HiAnime episode server scraper ──────────────────────────────────────────

function parseServerIds(html: string, type: "sub" | "dub"): string[] {
  const ids: string[] = [];
  const patterns = [
    new RegExp(`data-type="${type}"[^>]*?data-id="([^"]+)"`, "g"),
    new RegExp(`data-id="([^"]+)"[^>]*?data-type="${type}"`, "g"),
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      if (!ids.includes(m[1])) ids.push(m[1]);
    }
  }
  return ids;
}

async function scrapeHiAnime(
  episodeId: string,
  type: "sub" | "dub"
): Promise<StreamResult> {
  const serversRes = await hiFetch(
    `https://aniwatchtv.to/ajax/v2/episode/servers?episodeId=${encodeURIComponent(
      episodeId
    )}`
  );
  const serversData = (await serversRes.json()) as { html: string };

  const serverIds = parseServerIds(serversData.html, type);
  if (serverIds.length === 0) {
    throw new Error(`No ${type} servers found for episode ${episodeId}`);
  }

  const errors: string[] = [];

  for (const serverId of serverIds) {
    try {
      const srcRes = await hiFetch(
        `https://aniwatchtv.to/ajax/v2/episode/sources?id=${serverId}`
      );
      const srcData = (await srcRes.json()) as { link: string; type: string };
      if (!srcData.link) continue;

      const link = srcData.link;

      let result: Awaited<ReturnType<typeof getMegacloudSources>> | null = null;
      let serverName = "";

      if (link.includes("megacloud.tv")) {
        const idMatch = link.match(/\/e-1\/([^?/]+)/);
        if (!idMatch) continue;
        result = await getMegacloudSources(idMatch[1]);
        serverName = "megacloud";
      } else if (
        link.includes("rapid-cloud.co") ||
        link.includes("vidstreaming.io") ||
        link.includes("megacloud.tv/embed-6")
      ) {
        const idMatch = link.match(/\/embed-6(?:-v2)?\/([^?/]+)/);
        if (!idMatch) continue;
        result = await getRapidCloudSources(idMatch[1], link);
        serverName = "rapidcloud";
      } else {
        continue;
      }

      if (!result || result.sources.length === 0) continue;

      const best =
        result.sources.find(
          (s) => s.type === "hls" || s.file?.endsWith(".m3u8")
        ) || result.sources[0];
      if (!best?.file) continue;

      const streamType: "hls" | "mp4" =
        best.type === "hls" || best.file?.endsWith(".m3u8") ? "hls" : "mp4";

      return {
        url: best.file,
        type: streamType,
        subtitles: (
          result.tracks as { kind?: string; label?: string; file?: string }[]
        )
          .filter((t) => t.kind === "captions" || t.kind === "subtitles")
          .map((t) => ({ lang: t.label || "Unknown", url: t.file || "" }))
          .filter((t) => t.url),
        intro: result.intro,
        outro: result.outro,
        server: serverName,
        site: "hianime.to",
      };
    } catch (e) {
      errors.push(String(e));
      continue;
    }
  }

  throw new Error(`HiAnime: all servers failed: ${errors.join("; ")}`);
}

// ─── AllAnime ─────────────────────────────────────────────────────────────────

const ALLANIME_API = "https://api.allanime.day/api";
const ALLANIME_REFERER = "https://allanime.to";

function allanimeHeaders(): Record<string, string> {
  return {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    Referer: ALLANIME_REFERER,
    Origin: ALLANIME_REFERER,
  };
}

function decodeAllanimeUrl(encoded: string): string {
  if (!encoded.startsWith("--")) return encoded;
  const hex = encoded.slice(2);
  let result = "";
  for (let i = 0; i < hex.length - 1; i += 2) {
    result += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16) ^ 56);
  }
  return result;
}

async function allanimeGraphql(
  query: string,
  variables: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const url = `${ALLANIME_API}?variables=${encodeURIComponent(
    JSON.stringify(variables)
  )}&query=${encodeURIComponent(query)}`;

  const res = await fetch(url, {
    headers: allanimeHeaders(),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`AllAnime GraphQL HTTP ${res.status}`);
  return res.json() as Promise<Record<string, unknown>>;
}

const AA_SEARCH_QUERY = `
query($search: SearchInput, $limit: Int, $page: Int, $translationType: VaildTranslationTypeEnumType, $countryOrigin: VaildCountryOriginEnumType) {
  shows(search: $search, limit: $limit, page: $page, translationType: $translationType, countryOrigin: $countryOrigin) {
    pageInfo { total }
    edges { _id name availableEpisodes malId __typename }
  }
}`.trim();

interface AASearchResult {
  id: string;
  name: string;
  episodeCount: number | null;
  malId: number | null;
  episodeIdPrefix: string;
}

async function searchAllanime(
  query: string,
  type: "sub" | "dub"
): Promise<AASearchResult[]> {
  const data = await allanimeGraphql(AA_SEARCH_QUERY, {
    search: { allowAdult: false, allowUnknown: false, query },
    limit: 26,
    page: 1,
    translationType: type,
    countryOrigin: "ALL",
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const edges = ((data as any)?.data?.shows?.edges as any[]) ?? [];
  return edges.map((e) => ({
    id: e._id as string,
    name: e.name as string,
    episodeCount:
      (e.availableEpisodes?.[type] as number | null | undefined) ?? null,
    malId: (e.malId as number | null) ?? null,
    episodeIdPrefix: `${e._id}/`,
  }));
}

const AA_EPISODE_QUERY = `
query($showId: String!, $translationType: VaildTranslationTypeEnumType!, $episodeString: String!) {
  episode(showId: $showId, translationType: $translationType, episodeString: $episodeString) {
    episodeString
    sourceUrls
  }
}`.trim();

interface AASourceUrl {
  sourceUrl: string;
  priority: number;
  sourceName: string;
  type: string;
}

async function resolveAllanimeSource(
  sourceUrl: string,
  sourceType: string
): Promise<{ url: string; type: "mp4" | "hls" | "iframe" } | null> {
  if (!sourceUrl.startsWith("--")) {
    if (/^https?:\/\//.test(sourceUrl)) {
      return { url: sourceUrl, type: "iframe" };
    }
    return null;
  }

  let decoded: string;
  try {
    decoded = decodeAllanimeUrl(sourceUrl);
  } catch {
    return null;
  }

  if (decoded.endsWith(".m3u8")) return { url: decoded, type: "hls" };
  if (decoded.endsWith(".mp4")) return { url: decoded, type: "mp4" };

  if (decoded.startsWith("/")) {
    decoded = "https://blog.allanime.day" + decoded;
  }

  if (/^https?:/.test(decoded)) {
    try {
      const res = await fetch(decoded, {
        headers: allanimeHeaders(),
        signal: AbortSignal.timeout(25000),
      });
      if (!res.ok) return null;

      const ct = res.headers.get("content-type") ?? "";
      if (ct.startsWith("video/") || ct === "application/octet-stream") {
        return { url: decoded.replace(/([^:])\/\/+/g, "$1/"), type: "mp4" };
      }

      const text = await res.text();
      const trimmed = text.trimStart();
      if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
        if (/media|video/i.test(decoded)) {
          const cleanUrl = decoded.replace(/([^:])\/\/+/g, "$1/");
          return { url: cleanUrl, type: "mp4" };
        }
        return null;
      }

      const data = JSON.parse(text) as {
        links?: { link: string; hls?: boolean; resolutionStr?: string }[];
      };
      const links = data?.links ?? [];
      if (links.length === 0) return null;

      const sorted = [...links].sort((a, b) => {
        const ra = parseInt(a.resolutionStr ?? "0", 10);
        const rb = parseInt(b.resolutionStr ?? "0", 10);
        return rb - ra;
      });

      const best =
        sorted.find((l) => l.hls || l.link?.includes(".m3u8")) || sorted[0];
      if (!best?.link) return null;

      const isHls = !!(best.hls || best.link.includes(".m3u8"));
      const cleanLink = best.link.replace(/([^:])\/\/+/g, "$1/");
      return { url: cleanLink, type: isHls ? "hls" : "mp4" };
    } catch {
      return null;
    }
  }

  return null;
}

async function scrapeAllanime(
  episodeId: string,
  type: "sub" | "dub"
): Promise<StreamResult> {
  const slashIdx = episodeId.indexOf("/");
  if (slashIdx === -1) {
    throw new Error(
      "AllAnime: invalid episodeId — expected {showId}/{episodeNumber}"
    );
  }

  const showId = episodeId.slice(0, slashIdx);
  const episodeString = episodeId.slice(slashIdx + 1);

  const data = await allanimeGraphql(AA_EPISODE_QUERY, {
    showId,
    translationType: type,
    episodeString,
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const episode = (data as any)?.data?.episode;
  if (!episode) {
    throw new Error(`AllAnime: episode not found for ${episodeId}`);
  }

  const sourceUrls: AASourceUrl[] = (episode.sourceUrls as AASourceUrl[]) ?? [];
  if (sourceUrls.length === 0) {
    throw new Error("AllAnime: no source URLs returned for episode");
  }

  sourceUrls.sort((a, b) => b.priority - a.priority);

  const errors: string[] = [];

  for (const src of sourceUrls) {
    if (!src.sourceUrl || src.sourceUrl === "null") continue;
    try {
      const resolved = await resolveAllanimeSource(src.sourceUrl, src.type);
      if (resolved) {
        return {
          url: resolved.url,
          type: resolved.type,
          subtitles: [],
          intro: null,
          outro: null,
          server: src.sourceName || "allanime",
          site: "allanime.to",
        };
      }
    } catch (e) {
      errors.push(`${src.sourceName}: ${String(e)}`);
    }
  }

  throw new Error(`AllAnime: all sources failed — ${errors.join("; ")}`);
}

// ─── Aniwave ──────────────────────────────────────────────────────────────────
//
// Network traffic analysis on aniwave.to reveals the following flow:
//
//  Bot protection (FingerprintJS challenge):
//    Every AJAX request first returns a JS challenge page.
//    The page sets redirect_link = '<url>?tr_uuid=<uuid>&' then redirects with fp=<fingerprint>.
//    Using fp=-7 (the timeout fallback) triggers a 302 that:
//      - Sets cookie __tad (long-lived session token, domain=aniwave.to)
//      - Redirects to http://wwXX.aniwave.to<path>  (dynamic CDN backend)
//    The real JSON lives at the wwXX.aniwave.to CDN URL with the __tad cookie.
//
//  NOTE: wwXX.aniwave.to CDN IPs block datacenter egress (Render/Replit/AWS/etc.)
//        at the TCP level. This scraper will work from residential IPs or via a
//        residential proxy but will time out from cloud datacenter environments.
//
//  1. Episode list:  GET /ajax/episode/list/<animeId>
//     Response: { status: true, result: "<li data-id='<nodeId>' data-num='<num>'>" }
//
//  2. Server list:  GET /ajax/episode/servers/<episodeNodeId>
//     Response: { status: true, result: "<a data-id='<serverNodeId>'
//                 data-embed-id='<embedId>' data-type='sub|dub' data-title='...'>" }
//     embedId → Megacloud source ID (call getMegacloudSources directly)
//
//  3. Playback info (fallback): GET /ajax/episode/playbackInfo/<serverNodeId>
//     Response: { status: true, result: { link: "https://megacloud.tv/embed-2/e-1/<id>" } }
//
// episodeId format: "<animeId>/<episodeNumber>"  e.g. "12189/1"

const ANIWAVE_BASE = "https://aniwave.to";
const ANIWAVE_REFERER = `${ANIWAVE_BASE}/`;

// ─── Generic __tad challenge solver ──────────────────────────────────────────
//
// Aniwave, 9anime, GogoAnime (gg), and marin.moe all share the same
// FingerprintJS challenge infrastructure (same Apache server, same __tad cookie,
// same redirect flow). This generic solver handles all of them.
//
// Challenge flow (per request):
//  1. GET <url>  → HTML with: redirect_link = 'http://<domain><path>?tr_uuid=<uuid>&'
//  2. GET <redirect_link>fp=-7  → 302:
//       Set-Cookie: __tad=<token>  (long-lived session cookie)
//       Location: <cdn_url>         (e.g. http://wwXX.aniwave.to<path>)
//  3. GET <cdn_url> with Cookie: __tad=<token>  → actual JSON data
//
// Note on CDN blocking: wwXX.aniwave.to and similar CDN backends drop TCP
// connections from datacenter IPs (Render/Replit/AWS). Set PROXY_URL to a
// residential proxy to bypass this. The fetch() wrapper above handles that.

interface TadSession {
  tadCookie: string;
  cdnHost: string;  // e.g. ww38.aniwave.to
  ts: number;
}

const tadSessions: Record<string, TadSession> = {};
const TAD_SESSION_TTL = 30 * 60_000; // 30 minutes

/**
 * Solve the __tad FingerprintJS challenge for any URL on a protected site.
 * Returns the __tad cookie value and the CDN URL to use for the real request.
 */
async function solveTadChallenge(
  url: string,
  baseHeaders: Record<string, string>
): Promise<{ tadCookie: string; cdnUrl: string }> {
  // Step 1 — fetch the challenge page (manual redirect so we can read the HTML)
  const challengeRes = await _nodeFetch(url, {
    headers: baseHeaders,
    signal: AbortSignal.timeout(15000),
    redirect: "manual",
    agent: getProxyAgent(),
  });
  const html = await challengeRes.text();

  const redirectMatch = html.match(/redirect_link\s*=\s*'([^']+)'/);
  if (!redirectMatch) {
    throw new Error(
      `__tad challenge: could not extract redirect_link from response (${url})`
    );
  }
  const redirectBase = redirectMatch[1];

  // Step 2 — follow the challenge redirect with fp=-7 (the browser timeout fallback)
  const step2Res = await _nodeFetch(`${redirectBase}fp=-7`, {
    headers: baseHeaders,
    signal: AbortSignal.timeout(15000),
    redirect: "manual",
    agent: getProxyAgent(),
  });

  const setCookieHeader = step2Res.headers.get("set-cookie") || "";
  const tadMatch = setCookieHeader.match(/__tad=([^;]+)/);
  if (!tadMatch) {
    throw new Error(`__tad challenge: no __tad cookie in step-2 response for ${url}`);
  }
  const tadCookie = `__tad=${tadMatch[1]}`;

  const location = step2Res.headers.get("location");
  if (!location) {
    throw new Error(`__tad challenge: no Location header in step-2 response for ${url}`);
  }

  return { tadCookie, cdnUrl: location };
}

/**
 * Fetch an AJAX endpoint on any __tad-protected site.
 *
 * Strategy (in order):
 *  1. If we have a valid cached session for this domain, try the CDN URL directly.
 *  2. Otherwise solve the challenge → get __tad + CDN URL.
 *  3. If the CDN URL carries the same path (Aniwave case), fetch the CDN URL.
 *     If the CDN URL is a router/ad redirect (9anime/GogoAnime case), retry the
 *     original URL with the __tad cookie (works via residential proxy).
 *  4. Cache the session for future calls.
 */
async function tadFetch(
  url: string,
  siteBase: string,       // e.g. "https://aniwave.to"
  siteHeaders: Record<string, string>
): Promise<Awaited<ReturnType<typeof fetch>>> {
  const parsedUrl = new URL(url);
  const urlPath = parsedUrl.pathname + parsedUrl.search;
  const domain = parsedUrl.hostname;

  // Try cached session
  const cached = tadSessions[domain];
  if (cached && Date.now() - cached.ts < TAD_SESSION_TTL) {
    const cdnUrl = `http://${cached.cdnHost}${urlPath}`;
    try {
      const res = await fetch(cdnUrl, {
        headers: { ...siteHeaders, Cookie: cached.tadCookie },
        signal: AbortSignal.timeout(9000),
      });
      if (res.ok) return res;
    } catch {
      // CDN stale or unreachable — fall through to re-challenge
    }
    delete tadSessions[domain];
  }

  // Solve the challenge
  const { tadCookie, cdnUrl } = await solveTadChallenge(url, siteHeaders);

  let cdnHost: string;
  try {
    cdnHost = new URL(cdnUrl).hostname;
  } catch {
    cdnHost = domain;
  }

  const cdnPath = (() => {
    try { return new URL(cdnUrl).pathname; } catch { return ""; }
  })();

  // Check if the CDN URL is actually serving the requested data (path matches)
  // vs being a router/ad redirect (9anime → a11.click, etc.)
  const isCdnData = cdnPath === parsedUrl.pathname;

  if (isCdnData) {
    // CDN host serves the data directly (Aniwave pattern)
    tadSessions[domain] = { tadCookie, cdnHost, ts: Date.now() };
    let res: Awaited<ReturnType<typeof fetch>>;
    try {
      res = await fetch(cdnUrl, {
        headers: { ...siteHeaders, Cookie: tadCookie },
        signal: AbortSignal.timeout(9000),
      });
    } catch (e) {
      throw new Error(
        `CDN unreachable (${cdnUrl}): ${String(e)}. ` +
        `${domain}'s CDN (${cdnHost}) blocks datacenter IPs. ` +
        `Set PROXY_URL to a residential proxy to bypass this.`
      );
    }
    if (!res.ok) throw new Error(`CDN HTTP ${res.status} from ${cdnUrl}`);
    return res;
  } else {
    // CDN URL is a router/ad (9anime/GogoAnime pattern) — retry original URL
    // with __tad cookie. Works when PROXY_URL is a residential IP (no challenge shown).
    // Store cdnHost as the original domain since we're retrying there.
    tadSessions[domain] = { tadCookie, cdnHost: domain, ts: Date.now() };
    let res: Awaited<ReturnType<typeof fetch>>;
    try {
      res = await fetch(url, {
        headers: { ...siteHeaders, Cookie: tadCookie },
        signal: AbortSignal.timeout(9000),
      });
    } catch (e) {
      throw new Error(
        `${domain} unreachable after challenge: ${String(e)}. ` +
        `Set PROXY_URL to a residential proxy to bypass CDN IP blocking.`
      );
    }
    // If still a challenge page, proxy is needed
    const text = await res.text();
    if (text.includes("redirect_link")) {
      throw new Error(
        `${domain} continues to show bot challenge after __tad cookie. ` +
        `Set PROXY_URL to a residential proxy — datacenter IPs are blocked.`
      );
    }
    // Check if the response is HTML (challenge page, access denied, etc.) rather than JSON data
    const contentType = res.headers.get("content-type") || "";
    const looksLikeHtml = !contentType.includes("json") && (
      text.trimStart().startsWith("<") || text.includes("<html")
    );
    if (looksLikeHtml) {
      throw new Error(
        `${domain} returned HTML after __tad challenge — datacenter IPs are blocked. ` +
        `Set PROXY_URL to a residential proxy to bypass this.`
      );
    }

    // Return a synthetic Response with the text body
    return new NodeFetchResponse(text, {
      status: res.status,
      headers: res.headers,
    }) as unknown as Awaited<ReturnType<typeof fetch>>;
  }
}

// ─── Aniwave-specific helpers (thin wrappers over tadFetch) ──────────────────

function aniwaveHeaders(
  extra: Record<string, string> = {},
  tadCookie?: string
): Record<string, string> {
  return {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    Referer: ANIWAVE_REFERER,
    Origin: ANIWAVE_BASE,
    "X-Requested-With": "XMLHttpRequest",
    ...(tadCookie ? { Cookie: tadCookie } : {}),
    ...extra,
  };
}

async function aniwaveFetch(url: string, extra: Record<string, string> = {}) {
  return tadFetch(url, ANIWAVE_BASE, aniwaveHeaders(extra));
}

interface AniwaveServer {
  serverNodeId: string;
  embedId: string;
  type: "sub" | "dub" | "raw";
  title: string;
}

/**
 * Parse server list HTML from /ajax/episode/servers/<episodeNodeId>.
 * Each server is an <a> (or <li><a>) with:
 *   data-id="<serverNodeId>"
 *   data-embed-id="<embedId>"
 *   data-type="sub|dub|raw"
 *   data-title="Server Name"
 */
function parseAniwaveServers(html: string, type: "sub" | "dub"): AniwaveServer[] {
  const servers: AniwaveServer[] = [];

  // Match elements carrying both data-id and data-embed-id
  const re =
    /data-id="([^"]+)"[^>]*?data-embed-id="([^"]+)"[^>]*?data-type="([^"]+)"[^>]*?data-title="([^"]*)"/g;
  const re2 =
    /data-embed-id="([^"]+)"[^>]*?data-id="([^"]+)"[^>]*?data-type="([^"]+)"[^>]*?data-title="([^"]*)"/g;

  let m: RegExpExecArray | null;

  while ((m = re.exec(html)) !== null) {
    const [, serverNodeId, embedId, sType, title] = m;
    if (sType === type) {
      servers.push({ serverNodeId, embedId, type: sType as "sub" | "dub", title });
    }
  }

  // Try alternate attribute order if first pass found nothing
  if (servers.length === 0) {
    while ((m = re2.exec(html)) !== null) {
      const [, embedId, serverNodeId, sType, title] = m;
      if (sType === type) {
        servers.push({ serverNodeId, embedId, type: sType as "sub" | "dub", title });
      }
    }
  }

  return servers;
}

/**
 * Resolve a single Aniwave server to a StreamResult.
 *
 * Strategy:
 *  1. Use the embedId directly with Megacloud getSources (fastest path — no extra round-trip).
 *  2. If that 404s, call /ajax/episode/playbackInfo/<serverNodeId> to get the embed link,
 *     then dispatch based on the returned embed host.
 */
async function resolveAniwaveServer(
  server: AniwaveServer,
  referer: string
): Promise<Omit<StreamResult, "site"> | null> {
  // Fast path: try embedId directly against Megacloud e-1
  try {
    const result = await getMegacloudSources(server.embedId);
    if (result.sources.length > 0) {
      const best =
        result.sources.find((s) => s.type === "hls" || s.file?.endsWith(".m3u8")) ||
        result.sources[0];
      if (best?.file) {
        const streamType: "hls" | "mp4" =
          best.type === "hls" || best.file.endsWith(".m3u8") ? "hls" : "mp4";
        return {
          url: best.file,
          type: streamType,
          subtitles: (result.tracks as { kind?: string; label?: string; file?: string }[])
            .filter((t) => t.kind === "captions" || t.kind === "subtitles")
            .map((t) => ({ lang: t.label || "Unknown", url: t.file || "" }))
            .filter((t) => t.url),
          intro: result.intro,
          outro: result.outro,
          server: server.title || "megacloud",
        };
      }
    }
  } catch {
    // Fall through to playbackInfo route
  }

  // Slow path: fetch playback info to get embed URL
  try {
    const infoRes = await aniwaveFetch(
      `${ANIWAVE_BASE}/ajax/episode/playbackInfo/${server.serverNodeId}`,
      { Referer: referer }
    );
    const infoData = (await infoRes.json()) as {
      status: boolean;
      result?: { type?: string; link?: string; embed_url?: string };
    };

    const embedLink =
      infoData?.result?.link ||
      infoData?.result?.embed_url;

    if (!embedLink) return null;

    let result: Awaited<ReturnType<typeof getMegacloudSources>> | null = null;
    let serverName = server.title || "unknown";

    if (embedLink.includes("megacloud.tv")) {
      const idMatch =
        embedLink.match(/\/e-1\/([^?/]+)/) ||
        embedLink.match(/\/embed-2\/([^?/]+)/);
      if (!idMatch) return null;
      result = await getMegacloudSources(idMatch[1]);
      serverName = server.title || "megacloud";
    } else if (
      embedLink.includes("rapid-cloud.co") ||
      embedLink.includes("vidstreaming.io")
    ) {
      const idMatch = embedLink.match(/\/embed-6(?:-v2)?\/([^?/]+)/);
      if (!idMatch) return null;
      result = await getRapidCloudSources(idMatch[1], embedLink);
      serverName = server.title || "rapidcloud";
    } else {
      // Unknown embed host — return as iframe
      return {
        url: embedLink,
        type: "iframe",
        subtitles: [],
        intro: null,
        outro: null,
        server: serverName,
      };
    }

    if (!result || result.sources.length === 0) return null;

    const best =
      result.sources.find((s) => s.type === "hls" || s.file?.endsWith(".m3u8")) ||
      result.sources[0];
    if (!best?.file) return null;

    const streamType: "hls" | "mp4" =
      best.type === "hls" || best.file.endsWith(".m3u8") ? "hls" : "mp4";

    return {
      url: best.file,
      type: streamType,
      subtitles: (result.tracks as { kind?: string; label?: string; file?: string }[])
        .filter((t) => t.kind === "captions" || t.kind === "subtitles")
        .map((t) => ({ lang: t.label || "Unknown", url: t.file || "" }))
        .filter((t) => t.url),
      intro: result.intro,
      outro: result.outro,
      server: serverName,
    };
  } catch {
    return null;
  }
}

/**
 * scrapeAniwave(episodeId, type)
 *
 * episodeId format:  "<animeId>/<episodeNumber>"
 *   e.g. "12189/1"
 *
 * The animeId is the numeric ID found in data-id attributes on the aniwave.to
 * anime listing pages (also appears in the URL path of individual anime pages
 * like https://aniwave.to/watch/one-piece.12189).
 *
 * Waterfall:
 *  1. GET /ajax/episode/list/<animeId>  — find the episode node for the given number
 *  2. GET /ajax/episode/servers/<episodeNodeId> — list servers filtered by type
 *  3. For each server, attempt getMegacloudSources(embedId) directly, then fall
 *     back to /ajax/episode/playbackInfo/<serverNodeId> if needed.
 */
async function scrapeAniwave(
  episodeId: string,
  type: "sub" | "dub"
): Promise<StreamResult> {
  const slashIdx = episodeId.indexOf("/");
  if (slashIdx === -1) {
    throw new Error(
      "Aniwave: invalid episodeId — expected {animeId}/{episodeNumber} e.g. '12189/1'"
    );
  }

  const animeId = episodeId.slice(0, slashIdx);
  const episodeNumber = episodeId.slice(slashIdx + 1);

  // 1. Fetch episode list
  const listRes = await aniwaveFetch(
    `${ANIWAVE_BASE}/ajax/episode/list/${animeId}`
  );
  const listData = (await listRes.json()) as { status: boolean; result: string };

  if (!listData.status || !listData.result) {
    throw new Error(`Aniwave: episode list request failed for anime ${animeId}`);
  }

  // Parse episode node ID for the requested episode number
  // HTML: <li data-id="<nodeId>" data-num="<num>" ...>
  const epNodeIdMatch =
    new RegExp(`data-id="([^"]+)"[^>]*?data-num="${episodeNumber}"`).exec(listData.result) ||
    new RegExp(`data-num="${episodeNumber}"[^>]*?data-id="([^"]+)"`).exec(listData.result);

  if (!epNodeIdMatch) {
    throw new Error(
      `Aniwave: episode ${episodeNumber} not found in episode list for anime ${animeId}`
    );
  }

  const episodeNodeId = epNodeIdMatch[1];

  // 2. Fetch server list for this episode node
  const serversRes = await aniwaveFetch(
    `${ANIWAVE_BASE}/ajax/episode/servers/${episodeNodeId}`
  );
  const serversData = (await serversRes.json()) as { status: boolean; result: string };

  if (!serversData.status || !serversData.result) {
    throw new Error(`Aniwave: server list request failed for episode node ${episodeNodeId}`);
  }

  const servers = parseAniwaveServers(serversData.result, type);

  if (servers.length === 0) {
    throw new Error(
      `Aniwave: no ${type} servers found for episode ${episodeNumber} (anime ${animeId})`
    );
  }

  const episodePageUrl = `${ANIWAVE_BASE}/watch/${animeId}`;
  const errors: string[] = [];

  for (const server of servers) {
    try {
      const partial = await resolveAniwaveServer(server, episodePageUrl);
      if (partial) {
        return { ...partial, site: "aniwave.to" };
      }
    } catch (e) {
      errors.push(`${server.title || server.embedId}: ${String(e)}`);
    }
  }

  throw new Error(`Aniwave: all servers failed — ${errors.join("; ")}`);
}

// ─── 9anime ──────────────────────────────────────────────────────────────────
//
// 9anime.to uses the same __tad FingerprintJS challenge infrastructure as Aniwave.
// Unlike Aniwave, 9anime's challenge routes through a11.click (an ad/router CDN)
// rather than directly to a data CDN. tadFetch handles both cases.
//
// episodeId format: "<animeId>/<episodeNumber>"
//   animeId — the alphanumeric ID in the 9anime URL, e.g. "r9w9" from
//             https://9anime.to/watch/one-piece.r9w9
//
// With PROXY_URL set to a residential proxy, this works reliably.
// Without a proxy, it will fail with a "datacenter IPs are blocked" error.

const NINEANIME_BASE = "https://9anime.to";
const NINEANIME_REFERER = `${NINEANIME_BASE}/`;

function nineAnimeHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    Referer: NINEANIME_REFERER,
    Origin: NINEANIME_BASE,
    "X-Requested-With": "XMLHttpRequest",
    ...extra,
  };
}

async function nineAnimeFetch(url: string, extra: Record<string, string> = {}) {
  return tadFetch(url, NINEANIME_BASE, nineAnimeHeaders(extra));
}

/**
 * Parse 9anime episode list HTML to find the episode node ID for a given episode number.
 * HTML: <li data-id="{nodeId}" data-num="{num}" ...>
 */
function parseNineAnimeEpisodeId(html: string, episodeNum: string): string | null {
  const re1 = new RegExp(`data-id="([^"]+)"[^>]*?data-num="${episodeNum}"`);
  const re2 = new RegExp(`data-num="${episodeNum}"[^>]*?data-id="([^"]+)"`);
  return (re1.exec(html) || re2.exec(html))?.[1] ?? null;
}

interface NineAnimeServer {
  serverId: string;
  serverName: string;
  type: string;
}

/**
 * Parse 9anime server list HTML.
 * HTML: <li class="..." data-id="{serverId}" data-name="{name}" data-type="sub|dub">
 */
function parseNineAnimeServers(html: string, type: "sub" | "dub"): NineAnimeServer[] {
  const servers: NineAnimeServer[] = [];
  const re = /data-id="([^"]+)"[^>]*?data-name="([^"]*)"[^>]*?data-type="([^"]*)"/g;
  const re2 = /data-name="([^"]*)"[^>]*?data-id="([^"]+)"[^>]*?data-type="([^"]*)"/g;
  let m: RegExpExecArray | null;

  while ((m = re.exec(html)) !== null) {
    if (m[3] === type || m[3] === "sub") {
      servers.push({ serverId: m[1], serverName: m[2], type: m[3] });
    }
  }
  if (servers.length === 0) {
    while ((m = re2.exec(html)) !== null) {
      if (m[3] === type || m[3] === "sub") {
        servers.push({ serverId: m[2], serverName: m[1], type: m[3] });
      }
    }
  }
  return servers.filter((s) => s.type === type);
}

async function scrape9Anime(
  episodeId: string,
  type: "sub" | "dub"
): Promise<StreamResult> {
  const slashIdx = episodeId.indexOf("/");
  if (slashIdx === -1) {
    throw new Error(
      "9anime: invalid episodeId — expected {animeId}/{episodeNumber} e.g. 'r9w9/1'"
    );
  }

  const animeId = episodeId.slice(0, slashIdx);
  const episodeNum = episodeId.slice(slashIdx + 1);

  // 1. Episode list
  const listRes = await nineAnimeFetch(`${NINEANIME_BASE}/ajax/episode/list/${animeId}`);
  const listData = (await listRes.json()) as { status?: string; result?: string };
  if (!listData.result) {
    throw new Error(`9anime: episode list empty for anime ${animeId}`);
  }

  const episodeNodeId = parseNineAnimeEpisodeId(listData.result, episodeNum);
  if (!episodeNodeId) {
    throw new Error(`9anime: episode ${episodeNum} not found for anime ${animeId}`);
  }

  // 2. Server list
  const serversRes = await nineAnimeFetch(`${NINEANIME_BASE}/ajax/episode/servers/${episodeNodeId}`);
  const serversData = (await serversRes.json()) as { status?: string; result?: string };
  if (!serversData.result) {
    throw new Error(`9anime: server list empty for episode node ${episodeNodeId}`);
  }

  const servers = parseNineAnimeServers(serversData.result, type);
  if (servers.length === 0) {
    throw new Error(`9anime: no ${type} servers found for episode ${episodeNum}`);
  }

  const errors: string[] = [];

  for (const server of servers) {
    try {
      // 3. Get embed URL for this server
      const srcRes = await nineAnimeFetch(`${NINEANIME_BASE}/ajax/server/${server.serverId}`);
      const srcData = (await srcRes.json()) as { status?: string; result?: { url?: string } };
      const embedUrl = srcData?.result?.url;
      if (!embedUrl) continue;

      // 4. Dispatch to known embed providers
      let result: Awaited<ReturnType<typeof getMegacloudSources>> | null = null;
      let serverName = server.serverName || "unknown";

      if (embedUrl.includes("megacloud.tv")) {
        const idMatch =
          embedUrl.match(/\/e-1\/([^?/]+)/) ||
          embedUrl.match(/\/embed-2\/([^?/]+)/);
        if (!idMatch) continue;
        result = await getMegacloudSources(idMatch[1]);
        serverName = server.serverName || "megacloud";
      } else if (
        embedUrl.includes("rapid-cloud.co") ||
        embedUrl.includes("vidstreaming.io")
      ) {
        const idMatch = embedUrl.match(/\/embed-6(?:-v2)?\/([^?/]+)/);
        if (!idMatch) continue;
        result = await getRapidCloudSources(idMatch[1], embedUrl);
        serverName = server.serverName || "rapidcloud";
      } else {
        // Unknown embed — return as iframe
        return {
          url: embedUrl,
          type: "iframe",
          subtitles: [],
          intro: null,
          outro: null,
          server: serverName,
          site: "9anime.to",
        };
      }

      if (!result || result.sources.length === 0) continue;

      const best =
        result.sources.find((s) => s.type === "hls" || s.file?.endsWith(".m3u8")) ||
        result.sources[0];
      if (!best?.file) continue;

      const streamType: "hls" | "mp4" =
        best.type === "hls" || best.file.endsWith(".m3u8") ? "hls" : "mp4";

      return {
        url: best.file,
        type: streamType,
        subtitles: (result.tracks as { kind?: string; label?: string; file?: string }[])
          .filter((t) => t.kind === "captions" || t.kind === "subtitles")
          .map((t) => ({ lang: t.label || "Unknown", url: t.file || "" }))
          .filter((t) => t.url),
        intro: result.intro,
        outro: result.outro,
        server: serverName,
        site: "9anime.to",
      };
    } catch (e) {
      errors.push(`${server.serverName}: ${String(e)}`);
    }
  }

  throw new Error(`9anime: all servers failed — ${errors.join("; ")}`);
}

// ─── GogoAnime (revived — gogoanime.gg) ──────────────────────────────────────
//
// gogoanime.gg is alive and uses the same __tad challenge infrastructure.
// It hosts GogoCDN and VidStreaming embeds.
//
// episodeId format: "{animeSlug}/episode-{num}"
//   e.g. "naruto/episode-220"  (the slug is the URL path segment on gogoanime.gg)
//
// Requires PROXY_URL set to a residential proxy to bypass CDN IP blocking.

const GOGOANIME_BASE = "https://gogoanime.gg";
const GOGOANIME_REFERER = `${GOGOANIME_BASE}/`;

function gogoanimeHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    Referer: GOGOANIME_REFERER,
    Origin: GOGOANIME_BASE,
    ...extra,
  };
}

async function gogoanimePageFetch(url: string, extra: Record<string, string> = {}) {
  return tadFetch(url, GOGOANIME_BASE, gogoanimeHeaders(extra));
}

/**
 * Parse GogoCDN or VidStreaming embed URL from GogoAnime episode page HTML.
 * The page contains an iframe or a script tag with the streaming URL.
 */
function extractGogoanimeEmbed(html: string): string | null {
  // Primary: <iframe src="..."> with gogoCDN / vidstreaming / mega
  const iframeMatch =
    html.match(/\bsrc="(https?:\/\/(?:[^"]*(?:gogocdn|vidstreaming|megacloud|mycloud|rapid-cloud)[^"]*))"/i) ||
    html.match(/\bdata-video="(https?:\/\/[^"]+)"/i) ||
    html.match(/iframe[^>]+src="(https?:\/\/[^"]+)"/i);
  if (iframeMatch) return iframeMatch[1];
  return null;
}

async function scrapeGogoanime(
  episodeId: string,
  type: "sub" | "dub"
): Promise<StreamResult> {
  const slashIdx = episodeId.lastIndexOf("/");
  if (slashIdx === -1 || !episodeId.slice(slashIdx + 1).startsWith("episode-")) {
    throw new Error(
      "GogoAnime: invalid episodeId — expected {animeSlug}/episode-{num} e.g. 'naruto/episode-1'"
    );
  }

  const animeSlug = episodeId.slice(0, slashIdx);
  const episodePart = episodeId.slice(slashIdx + 1); // e.g. "episode-1"

  // Fetch the episode page
  const pageUrl = `${GOGOANIME_BASE}/${animeSlug}-${episodePart}`;
  const pageRes = await gogoanimePageFetch(pageUrl);
  const html = await pageRes.text();

  const embedUrl = extractGogoanimeEmbed(html);
  if (!embedUrl) {
    throw new Error(
      `GogoAnime: could not extract embed URL from episode page ${pageUrl}`
    );
  }

  // Dispatch to known embed providers
  if (embedUrl.includes("megacloud.tv")) {
    const idMatch =
      embedUrl.match(/\/e-1\/([^?/]+)/) ||
      embedUrl.match(/\/embed-2\/([^?/]+)/);
    if (idMatch) {
      const result = await getMegacloudSources(idMatch[1]);
      if (result.sources.length > 0) {
        const best =
          result.sources.find((s) => s.type === "hls" || s.file?.endsWith(".m3u8")) ||
          result.sources[0];
        if (best?.file) {
          const streamType: "hls" | "mp4" =
            best.type === "hls" || best.file.endsWith(".m3u8") ? "hls" : "mp4";
          return {
            url: best.file,
            type: streamType,
            subtitles: (result.tracks as { kind?: string; label?: string; file?: string }[])
              .filter((t) => t.kind === "captions" || t.kind === "subtitles")
              .map((t) => ({ lang: t.label || "Unknown", url: t.file || "" }))
              .filter((t) => t.url),
            intro: result.intro,
            outro: result.outro,
            server: "megacloud",
            site: "gogoanime.gg",
          };
        }
      }
    }
  }

  if (embedUrl.includes("rapid-cloud.co") || embedUrl.includes("vidstreaming.io")) {
    const idMatch = embedUrl.match(/\/embed-6(?:-v2)?\/([^?/]+)/);
    if (idMatch) {
      const result = await getRapidCloudSources(idMatch[1], embedUrl);
      if (result.sources.length > 0) {
        const best =
          result.sources.find((s) => s.type === "hls" || s.file?.endsWith(".m3u8")) ||
          result.sources[0];
        if (best?.file) {
          const streamType: "hls" | "mp4" =
            best.type === "hls" || best.file.endsWith(".m3u8") ? "hls" : "mp4";
          return {
            url: best.file,
            type: streamType,
            subtitles: (result.tracks as { kind?: string; label?: string; file?: string }[])
              .filter((t) => t.kind === "captions" || t.kind === "subtitles")
              .map((t) => ({ lang: t.label || "Unknown", url: t.file || "" }))
              .filter((t) => t.url),
            intro: result.intro,
            outro: result.outro,
            server: "rapidcloud",
            site: "gogoanime.gg",
          };
        }
      }
    }
  }

  // Unknown embed — return as iframe
  return {
    url: embedUrl,
    type: "iframe",
    subtitles: [],
    intro: null,
    outro: null,
    server: "gogocdn",
    site: "gogoanime.gg",
  };
}

// ─── AnimePahe (bot-gated Kwik embeds — left as stub) ────────────────────────

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function scrapeAnimepahe(
  _episodeId: string,
  _type: "sub" | "dub"
): Promise<StreamResult> {
  throw new Error(
    "AnimePahe: server-side scraping is not supported — Kwik embed bot detection blocks automated requests"
  );
}

// ─── Auto (waterfall) ─────────────────────────────────────────────────────────
//
// ID format routing:
//   purely numeric          → HiAnime  (e.g. "12345")
//   {alpha}/{num}           → AllAnime or Aniwave or 9anime  (e.g. "abc123/1")
//   {alpha}/episode-{num}   → GogoAnime  (e.g. "naruto/episode-1")
//
// The waterfall tries all applicable sites in priority order and returns the
// first success. Set PROXY_URL to a residential proxy to unlock Aniwave, 9anime,
// and GogoAnime from datacenter environments.

async function scrapeAuto(
  episodeId: string,
  type: "sub" | "dub"
): Promise<StreamResult> {
  const errors: Record<string, string> = {};
  const hasSlash = episodeId.includes("/");
  const isNumeric = /^\d+$/.test(episodeId);
  const isGogoFormat = hasSlash && /\/episode-\d+$/.test(episodeId);

  // 1. AllAnime — {showId}/{episode} format (works from datacenter)
  if (hasSlash && !isGogoFormat) {
    try {
      return await scrapeAllanime(episodeId, type);
    } catch (e) {
      errors.allanime = String(e);
    }
  }

  // 2. HiAnime — purely numeric episode ID (works from datacenter)
  if (isNumeric) {
    try {
      return await scrapeHiAnime(episodeId, type);
    } catch (e) {
      errors.hianime = String(e);
    }
  }

  // 3. Aniwave — {animeId}/{episodeNumber} format (needs PROXY_URL for datacenter)
  if (hasSlash && !isGogoFormat) {
    try {
      return await scrapeAniwave(episodeId, type);
    } catch (e) {
      errors.aniwave = String(e);
    }
  }

  // 4. 9anime — {animeId}/{episodeNumber} format (needs PROXY_URL for datacenter)
  if (hasSlash && !isGogoFormat) {
    try {
      return await scrape9Anime(episodeId, type);
    } catch (e) {
      errors["9anime"] = String(e);
    }
  }

  // 5. GogoAnime — {animeSlug}/episode-{num} format (needs PROXY_URL for datacenter)
  if (isGogoFormat) {
    try {
      return await scrapeGogoanime(episodeId, type);
    } catch (e) {
      errors.gogoanime = String(e);
    }
  }

  throw new Error(`Auto: all sites failed — ${JSON.stringify(errors)}`);
}

// ─── CORS helper ──────────────────────────────────────────────────────────────

function setCors(res: import("express").Response) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
}

// ─── Proxy video request ──────────────────────────────────────────────────────

function proxyVideoRequest(
  req: import("express").Request,
  res: import("express").Response
) {
  const { url, referer } = req.query as { url?: string; referer?: string };
  if (!url) {
    res.status(400).json({ error: "Missing url query param" });
    return;
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(url);
  } catch {
    res.status(400).json({ error: "Invalid url" });
    return;
  }

  const ref = referer ? decodeURIComponent(referer) : "https://allanime.to";
  const protocol = targetUrl.protocol === "https:" ? https : http;

  const reqHeaders: Record<string, string> = {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Referer": ref,
    "Origin": new URL(ref).origin,
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
  };
  // Forward Range header so Android WebView gets proper 206 Partial Content
  const range = req.headers["range"];
  if (range) reqHeaders["Range"] = Array.isArray(range) ? range[0] : range;

  const options = {
    hostname: targetUrl.hostname,
    port: targetUrl.port ? parseInt(targetUrl.port) : (targetUrl.protocol === "https:" ? 443 : 80),
    path: targetUrl.pathname + targetUrl.search,
    method: "GET",
    headers: reqHeaders,
  };

  const proxyReq = protocol.request(options, (proxyRes: IncomingMessage) => {
    const status = proxyRes.statusCode ?? 200;

    // Follow redirects server-side (up to 5 hops).
    // Using res.redirect() would send the Location to the browser which can't
    // add the required Referer/UA headers on the follow-up request.
    if ([301, 302, 303, 307, 308].includes(status) && proxyRes.headers.location) {
      const location = proxyRes.headers.location;
      proxyRes.resume(); // drain redirect body
      const nextUrl = location.startsWith("http")
        ? location
        : new URL(location, `${targetUrl.protocol}//${targetUrl.hostname}`).href;
      // Strip Origin/Referer on cross-origin redirect to avoid 403
      const nextOptions = { ...options };
      try {
        const nextHost = new URL(nextUrl).hostname;
        if (nextHost !== targetUrl.hostname) {
          const h = { ...(nextOptions.headers as Record<string,string>) };
          delete h["Referer"]; delete h["Origin"];
          nextOptions.headers = h;
        }
      } catch { /**/ }
      // Recurse via a new request
      const nextTarget = new URL(nextUrl);
      const nextProtocol = nextTarget.protocol === "https:" ? https : http;
      const nextReq = nextProtocol.request({
        ...nextOptions,
        hostname: nextTarget.hostname,
        port: nextTarget.port || (nextTarget.protocol === "https:" ? 443 : 80),
        path: nextTarget.pathname + nextTarget.search,
      }, (nextRes: IncomingMessage) => {
        if (!res.headersSent) {
          res.writeHead(nextRes.statusCode ?? 200, {
            "Content-Type": nextRes.headers["content-type"] ?? "video/mp4",
            "Content-Length": nextRes.headers["content-length"] ?? "",
            "Accept-Ranges": "bytes",
            "Content-Range": nextRes.headers["content-range"] ?? "",
            "Access-Control-Allow-Origin": "*",
          });
        }
        nextRes.pipe(res);
      });
      nextReq.on("error", (e: Error) => { if (!res.headersSent) res.status(502).json({ error: e.message }); });
      nextReq.end();
      return;
    }

    if (!res.headersSent) {
      res.writeHead(status, {
        "Content-Type": proxyRes.headers["content-type"] ?? "video/mp4",
        "Content-Length": proxyRes.headers["content-length"] ?? "",
        "Accept-Ranges": "bytes",
        "Content-Range": proxyRes.headers["content-range"] ?? "",
        "Access-Control-Allow-Origin": "*",
      });
    }
    proxyRes.pipe(res);
  });

  proxyReq.on("error", (e: Error) => {
    if (!res.headersSent) res.status(502).json({ error: e.message });
  });

  proxyReq.end();
}

// ─── Route: GET /api/health ──────────────────────────────────────────────────

router.get("/health", (_req, res) => {
  setCors(res);
  res.json({ status: "ok" });
});

// ─── Route: GET /api/search ───────────────────────────────────────────────────

router.get("/search", async (req, res) => {
  setCors(res);
  const { q, type } = req.query as { q?: string; type?: string };
  if (!q) { res.status(400).json({ success: false, error: "Missing required query param: q" }); return; }
  const streamType: "sub" | "dub" = type === "dub" ? "dub" : "sub";
  try {
    const results = await searchAllanime(q, streamType);
    res.json({ success: true, site: "allanime", results });
  } catch (err) {
    res.status(500).json({ success: false, error: String(err) });
  }
});

// ─── Route: GET /api/debug-sources ───────────────────────────────────────────

router.get("/debug-sources", async (req, res) => {
  setCors(res);
  const { episodeId, type } = req.query as { episodeId?: string; type?: string };
  if (!episodeId) { res.status(400).json({ error: "Missing episodeId" }); return; }
  const streamType: "sub" | "dub" = type === "dub" ? "dub" : "sub";
  const slashIdx = episodeId.indexOf("/");
  const showId = episodeId.slice(0, slashIdx);
  const episodeString = episodeId.slice(slashIdx + 1);

  const data = await allanimeGraphql(AA_EPISODE_QUERY, { showId, translationType: streamType, episodeString });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const sourceUrls = (data as any)?.data?.episode?.sourceUrls as AASourceUrl[] ?? [];

  const results = await Promise.all(sourceUrls.map(async (src) => {
    const out: Record<string, unknown> = {
      sourceName: src.sourceName,
      priority: src.priority,
      type: src.type,
      encoded: src.sourceUrl,
    };
    if (!src.sourceUrl || src.sourceUrl === "null") { out.status = "null/empty"; return out; }

    let decoded = src.sourceUrl;
    if (src.sourceUrl.startsWith("--")) {
      const hex = src.sourceUrl.slice(2);
      decoded = "";
      for (let i = 0; i < hex.length - 1; i += 2) {
        decoded += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16) ^ 56);
      }
    }
    out.decoded = decoded;

    if (/^https?:\/\//.test(decoded)) {
      try {
        const r = await fetch(decoded, { headers: allanimeHeaders(), signal: AbortSignal.timeout(20000) });
        out.vaultStatus = r.status;
        if (r.ok) {
          const body = await r.json() as Record<string, unknown>;
          out.vaultBody = body;
        }
      } catch (e) {
        out.vaultError = String(e);
      }
    }

    return out;
  }));

  res.json({ results });
});

// ─── Route: GET /api/proxy/video ─────────────────────────────────────────────

router.get("/proxy/video", (req, res) => {
  setCors(res);
  proxyVideoRequest(req, res);
});

// ─── Route: GET /api/sources ─────────────────────────────────────────────────

router.get("/sources", async (req, res) => {
  setCors(res);

  const { site, episodeId, type } = req.query as {
    site?: string;
    episodeId?: string;
    type?: string;
  };

  if (!episodeId) {
    res.status(400).json({ error: "Missing episodeId" });
    return;
  }

  const streamType: "sub" | "dub" = type === "dub" ? "dub" : "sub";

  try {
    let result: StreamResult;

    switch (site) {
      case "hianime":
        result = await scrapeHiAnime(episodeId, streamType);
        break;
      case "allanime":
        result = await scrapeAllanime(episodeId, streamType);
        break;
      case "aniwave":
        result = await scrapeAniwave(episodeId, streamType);
        break;
      case "9anime":
        result = await scrape9Anime(episodeId, streamType);
        break;
      case "gogoanime":
        result = await scrapeGogoanime(episodeId, streamType);
        break;
      case "auto":
      default:
        result = await scrapeAuto(episodeId, streamType);
        break;
    }

    res.json({ success: true, ...result });
  } catch (e) {
    res.status(500).json({ success: false, error: String(e) });
  }
});

export default router;
