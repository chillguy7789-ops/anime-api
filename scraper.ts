import { Router } from "express";
import _nodeFetch, { Response as NodeFetchResponse } from "node-fetch";
import type { RequestInit as NodeFetchRequestInit } from "node-fetch";
import crypto from "crypto";
import https from "https";
import http from "http";
import type { IncomingMessage } from "http";

// ─── Phone proxy support ──────────────────────────────────────────────────────
// CF_PROXY_URL: URL of the phone proxy (e.g. https://xxx.trycloudflare.com)
// CF_PROXY_SECRET: shared secret matching PROXY_SECRET on the phone
//
// Routes Aniwave/9anime/GogoAnime requests through the phone's residential IP.
// AllAnime and HiAnime still go direct (they work fine from datacenter).

const CF_PROXY_URL = (process.env.CF_PROXY_URL || '').replace(/\/+$/, '');
const CF_PROXY_SECRET = process.env.CF_PROXY_SECRET || 'swach-proxy';

/**
 * Send a request through the phone proxy.
 * Falls back to direct fetch if no proxy is configured.
 */
async function cfFetch(
  url: string,
  options: { headers?: Record<string, string>; signal?: AbortSignal } = {}
): Promise<Awaited<ReturnType<typeof _nodeFetch>>> {
  if (!CF_PROXY_URL) {
    // No proxy — direct (will likely be blocked by CDN for Aniwave/9anime)
    return _nodeFetch(url, options as NodeFetchRequestInit);
  }
  return _nodeFetch(`${CF_PROXY_URL}/proxy`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Proxy-Token': CF_PROXY_SECRET,
    },
    body: JSON.stringify({
      url,
      method: 'GET',
      headers: options.headers || {},
    }),
    signal: options.signal,
  });
}

// Standard fetch for AllAnime/HiAnime (datacenter-friendly)
function fetch(
  url: Parameters<typeof _nodeFetch>[0],
  options: NodeFetchRequestInit = {}
) {
  return _nodeFetch(url, options);
}

// Compatibility shims (used by tadFetch internals)
// getProxyAgent shim — no longer used, kept for compatibility
function getProxyAgent() { return undefined; }
function getManualProxyAgent() { return undefined; }


const router = Router();

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

const ANIWAVE_BASE = "https://aniwave.to";
const ANIWAVE_REFERER = `${ANIWAVE_BASE}/`;

interface TadSession {
  tadCookie: string;
  cdnHost: string;
  ts: number;
}

const tadSessions: Record<string, TadSession> = {};
const TAD_SESSION_TTL = 30 * 60_000;

async function solveTadChallenge(
  url: string,
  baseHeaders: Record<string, string>
): Promise<{ tadCookie: string; cdnUrl: string }> {
  const challengeRes = await cfFetch(url, {
    headers: baseHeaders,
    signal: AbortSignal.timeout(15000),
  });
  const html = await challengeRes.text();

  const redirectMatch = html.match(/redirect_link\s*=\s*'([^']+)'/);
  if (!redirectMatch) {
    throw new Error(
      `__tad challenge: could not extract redirect_link from response (${url})`
    );
  }
  const redirectBase = redirectMatch[1];

  const step2Res = await cfFetch(`${redirectBase}fp=-7`, {
    headers: baseHeaders,
    signal: AbortSignal.timeout(15000),
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

async function tadFetch(
  url: string,
  siteBase: string,
  siteHeaders: Record<string, string>
): Promise<Awaited<ReturnType<typeof fetch>>> {
  const parsedUrl = new URL(url);
  const urlPath = parsedUrl.pathname + parsedUrl.search;
  const domain = parsedUrl.hostname;

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
      // fall through
    }
    delete tadSessions[domain];
  }

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

  const isCdnData = cdnPath === parsedUrl.pathname;

  // Helper: attempt the real CDN/site fetch, optionally through an agent
  const attemptCdnFetch = async (
    targetUrl: string,
    headers: Record<string, string>,
    agent?: Agent
  ): Promise<Awaited<ReturnType<typeof fetch>>> => {
    const opts: NodeFetchRequestInit = {
      headers,
      signal: AbortSignal.timeout(9000),
    };
    if (agent) opts.agent = agent;
    return _nodeFetch(targetUrl, opts);
  };

  // Helper: try a fetch first directly, then through proxy pool on failure
  const fetchWithFallback = async (
    targetUrl: string,
    headers: Record<string, string>,
    label: string
  ): Promise<Awaited<ReturnType<typeof fetch>>> => {
    // No manual agent — will use phone proxy on fallback

    // Try direct first (fast path for non-blocked IPs)
    try {
      const res = await attemptCdnFetch(targetUrl, headers);
      const text = await res.text();
      const looksBlocked =
        text.includes("redirect_link") ||
        (!res.headers.get("content-type")?.includes("json") &&
          (text.trimStart().startsWith("<") || text.includes("<html")));
      if (!looksBlocked) {
        return new NodeFetchResponse(text, {
          status: res.status,
          headers: res.headers,
        }) as unknown as Awaited<ReturnType<typeof fetch>>;
      }
      console.warn(`[tadFetch] Direct CDN blocked (HTML response) for ${label}, trying proxy pool...`);
    } catch (directErr) {
      console.warn(`[tadFetch] Direct CDN unreachable for ${label}: ${String(directErr)}, trying proxy pool...`);
    }

    // Fall back to phone proxy
    const res = await cfFetch(targetUrl, { headers });
    const text = await res.text();
    const looksBlocked =
      text.includes("redirect_link") ||
      (!res.headers.get("content-type")?.includes("json") &&
        (text.trimStart().startsWith("<") || text.includes("<html")));
    if (looksBlocked) {
      throw new Error("phone proxy returned a blocked/HTML response — check tunnel is running");
    }
    return new NodeFetchResponse(text, {
      status: res.status,
      headers: res.headers,
    }) as unknown as Awaited<ReturnType<typeof fetch>>;
  };

  if (isCdnData) {
    tadSessions[domain] = { tadCookie, cdnHost, ts: Date.now() };
    return fetchWithFallback(cdnUrl, { ...siteHeaders, Cookie: tadCookie }, cdnUrl);
  } else {
    tadSessions[domain] = { tadCookie, cdnHost: domain, ts: Date.now() };
    return fetchWithFallback(url, { ...siteHeaders, Cookie: tadCookie }, url);
  }
}

// ─── Aniwave helpers ──────────────────────────────────────────────────────────

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

function parseAniwaveServers(html: string, type: "sub" | "dub"): AniwaveServer[] {
  const servers: AniwaveServer[] = [];

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

async function resolveAniwaveServer(
  server: AniwaveServer,
  referer: string
): Promise<Omit<StreamResult, "site"> | null> {
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

  const listRes = await aniwaveFetch(
    `${ANIWAVE_BASE}/ajax/episode/list/${animeId}`
  );
  const listData = (await listRes.json()) as { status: boolean; result: string };

  if (!listData.status || !listData.result) {
    throw new Error(`Aniwave: episode list request failed for anime ${animeId}`);
  }

  const epNodeIdMatch =
    new RegExp(`data-id="([^"]+)"[^>]*?data-num="${episodeNumber}"`).exec(listData.result) ||
    new RegExp(`data-num="${episodeNumber}"[^>]*?data-id="([^"]+)"`).exec(listData.result);

  if (!epNodeIdMatch) {
    throw new Error(
      `Aniwave: episode ${episodeNumber} not found in episode list for anime ${animeId}`
    );
  }

  const episodeNodeId = epNodeIdMatch[1];

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

// ─── 9anime ───────────────────────────────────────────────────────────────────

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

  const listRes = await nineAnimeFetch(`${NINEANIME_BASE}/ajax/episode/list/${animeId}`);
  const listData = (await listRes.json()) as { status?: string; result?: string };
  if (!listData.result) {
    throw new Error(`9anime: episode list empty for anime ${animeId}`);
  }

  const episodeNodeId = parseNineAnimeEpisodeId(listData.result, episodeNum);
  if (!episodeNodeId) {
    throw new Error(`9anime: episode ${episodeNum} not found for anime ${animeId}`);
  }

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
      const srcRes = await nineAnimeFetch(`${NINEANIME_BASE}/ajax/server/${server.serverId}`);
      const srcData = (await srcRes.json()) as { status?: string; result?: { url?: string } };
      const embedUrl = srcData?.result?.url;
      if (!embedUrl) continue;

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

// ─── GogoAnime ────────────────────────────────────────────────────────────────

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

function extractGogoanimeEmbed(html: string): string | null {
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
  const episodePart = episodeId.slice(slashIdx + 1);

  const pageUrl = `${GOGOANIME_BASE}/${animeSlug}-${episodePart}`;
  const pageRes = await gogoanimePageFetch(pageUrl);
  const html = await pageRes.text();

  const embedUrl = extractGogoanimeEmbed(html);
  if (!embedUrl) {
    throw new Error(
      `GogoAnime: could not extract embed URL from episode page ${pageUrl}`
    );
  }

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

// ─── Auto (waterfall) ─────────────────────────────────────────────────────────
//
// Tries all applicable sites in priority order (datacenter-friendly first).
// Set PROXY_URL to a residential proxy to unlock Aniwave, 9anime, GogoAnime.

async function scrapeAuto(
  episodeId: string,
  type: "sub" | "dub"
): Promise<StreamResult> {
  const errors: Record<string, string> = {};
  const hasSlash = episodeId.includes("/");
  const isNumeric = /^\d+$/.test(episodeId);
  const isGogoFormat = hasSlash && /\/episode-\d+$/.test(episodeId);

  if (hasSlash && !isGogoFormat) {
    try {
      return await scrapeAllanime(episodeId, type);
    } catch (e) {
      errors.allanime = String(e);
    }
  }

  if (isNumeric) {
    try {
      return await scrapeHiAnime(episodeId, type);
    } catch (e) {
      errors.hianime = String(e);
    }
  }

  if (hasSlash && !isGogoFormat) {
    try {
      return await scrapeAniwave(episodeId, type);
    } catch (e) {
      errors.aniwave = String(e);
    }
  }

  if (hasSlash && !isGogoFormat) {
    try {
      return await scrape9Anime(episodeId, type);
    } catch (e) {
      errors["9anime"] = String(e);
    }
  }

  if (isGogoFormat) {
    try {
      return await scrapeGogoanime(episodeId, type);
    } catch (e) {
      errors.gogoanime = String(e);
    }
  }

  throw new Error(`Auto: all sites failed — ${JSON.stringify(errors)}`);
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
    Referer: ref,
    Origin: new URL(ref).origin,
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.9",
  };
  const range = req.headers["range"];
  if (range) reqHeaders["Range"] = Array.isArray(range) ? range[0] : range;

  const options = {
    hostname: targetUrl.hostname,
    port: targetUrl.port
      ? parseInt(targetUrl.port)
      : targetUrl.protocol === "https:"
      ? 443
      : 80,
    path: targetUrl.pathname + targetUrl.search,
    method: "GET",
    headers: reqHeaders,
  };

  const proxyReq = protocol.request(options, (proxyRes: IncomingMessage) => {
    const status = proxyRes.statusCode ?? 200;

    if ([301, 302, 303, 307, 308].includes(status) && proxyRes.headers.location) {
      const location = proxyRes.headers.location;
      proxyRes.resume();
      const nextUrl = location.startsWith("http")
        ? location
        : new URL(location, `${targetUrl.protocol}//${targetUrl.hostname}`).href;
      const nextOptions = { ...options };
      try {
        const nextHost = new URL(nextUrl).hostname;
        if (nextHost !== targetUrl.hostname) {
          const h = { ...(nextOptions.headers as Record<string, string>) };
          delete h["Referer"];
          delete h["Origin"];
          nextOptions.headers = h;
        }
      } catch {
        // ignore
      }
      const nextTarget = new URL(nextUrl);
      const nextProtocol = nextTarget.protocol === "https:" ? https : http;
      const nextReq = nextProtocol.request(
        {
          ...nextOptions,
          hostname: nextTarget.hostname,
          port: nextTarget.port || (nextTarget.protocol === "https:" ? 443 : 80),
          path: nextTarget.pathname + nextTarget.search,
        },
        (nextRes: IncomingMessage) => {
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
        }
      );
      nextReq.on("error", (e: Error) => {
        if (!res.headersSent) res.status(502).json({ error: e.message });
      });
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

// ─── Routes ───────────────────────────────────────────────────────────────────

// GET /api/proxy/status — shows proxy pool state
router.get("/proxy/status", async (_req, res) => {
  res.json({
    poolSize: 0,
    phoneProxy: !!process.env.CF_PROXY_URL,
  });
});

// GET /api/search?q=<query>&type=sub|dub
router.get("/search", async (req, res) => {
  const { q, type } = req.query as { q?: string; type?: string };
  if (!q) {
    res.status(400).json({ success: false, error: "Missing required query param: q" });
    return;
  }
  const streamType: "sub" | "dub" = type === "dub" ? "dub" : "sub";
  try {
    const results = await searchAllanime(q, streamType);
    res.json({ success: true, site: "allanime", results });
  } catch (err) {
    res.status(500).json({ success: false, error: String(err) });
  }
});

// GET /api/proxy/video?url=<url>&referer=<referer>
router.get("/proxy/video", (req, res) => {
  proxyVideoRequest(req, res);
});

// GET /api/sources?episodeId=<id>&type=sub|dub&site=hianime|allanime|aniwave|9anime|gogoanime|auto
router.get("/sources", async (req, res) => {
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
