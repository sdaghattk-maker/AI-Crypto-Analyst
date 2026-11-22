/**
 * AI Crypto Analyst Gateway - PHASE 7.7 ROOT-CAUSE FIX
 *
 * Cloudflare Worker Secrets:
 *   GEMINI_API_KEY       - Google AI Studio free-tier API key
 *   OPENROUTER_API_KEY   - OpenRouter API key (use a :free model/router)
 *   GROQ_API_KEY         - Groq API key (free-tier availability depends on account/model)
 *   ALTFINS_API_KEY      - optional altFINS API key (server-side only)
 *   GATEWAY_TOKEN        - protects /provider-test only
 *
 * Cloudflare Binding:
 *   RATE_LIMITER         - Rate Limiter binding, Limit 5, Period 60 seconds
 *   PROVIDER_CIRCUIT_BREAKER - Durable Object namespace (SQLite-backed migration v1)
 *
 * Routes:
 *   GET  /health
 *   POST /provider-test
 *   POST /analyze
 *   GET  /altfins/quota
 *   POST /altfins/validation
 *   GET  /altfins/diagnostics?symbol=BTCUSDT&timeframe=15m (safe support/resistance diagnostics)
 *
 * RATE LIMITING:
 *   /analyze, /models, /altfins/quota, /altfins/diagnostics,
 *   /altfins/validation and authenticated /provider-test use separate
 *   per-client buckets through the RATE_LIMITER binding.
 *   No API key or gateway token is embedded in the app.
 */

const GEMINI_DEFAULT = "gemini-3.8-flash";
const OPENROUTER_DEFAULT = "qwen/qwen3.8-27b:free";
const GROQ_DEFAULT = "openai/gpt-oss-120b";
// Versioned, capability-based candidate order. This is NOT a crypto-trading
// performance leaderboard. Live provider catalogs intersect this list, so a
// model is selectable only when the user's provider account currently exposes it.
// OpenRouter candidates are free or low-cost text-generation models; endpoint-specific
// structured-output support is still checked by the request/response validator.
const MODEL_RANKING_VERSION = "2026-11-21.1-text-only";
const CURATED_MODEL_RANKING = {
  gemini: [
    "gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.6-flash",
    "gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite"
  ],
  openrouter: [
    "qwen/qwen3.8-27b:free", "openai/gpt-oss-20b:free",
    "inclusionai/ling-3.2-flash:free", "baidu/ernie-5.5-flash-preview:free"
  ],
  groq: [
    "openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b",
    "llama-3.3-70b-versatile", "llama-3.1-8b-instant"
  ]
};
const PROVIDER_KEYS = { gemini: "GEMINI", openrouter: "OPENROUTER", groq: "GROQ" };
const MAX_AI_OVERLAYS = 10;
const MAX_BODY_BYTES = 1024 * 1024;
const PROVIDER_TIMEOUT_MS = 18000;
const ALTFINS_BASE = "https://altfins.com/api/v2/public";
const ALTFINS_TIMEOUT_MS = 10000;
const ALTFINS_CACHE_TTL_SECONDS = 900;

function responseJson(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin"
    }
  });
}

function getAllowedOrigin(request, env) {
  const configured = (env.ALLOWED_ORIGIN || "*").trim();
  const incoming = request.headers.get("Origin");
  if (configured === "*") return "*";
  if (!incoming) return configured;
  return incoming === configured ? configured : "null";
}

function normalizeSignal(value) {
  const signal = String(value || "WAIT").trim().toUpperCase();
  if (["BUY", "LONG", "BULLISH", "STRONG_BUY"].includes(signal)) return "BUY";
  if (["SELL", "SHORT", "BEARISH", "STRONG_SELL"].includes(signal)) return "SELL";
  if (["WAIT", "HOLD", "NEUTRAL", "NO_TRADE"].includes(signal)) return "WAIT";
  return "WAIT";
}

function safeError(error) {
  return String(error?.message || error || "Unknown provider error")
    .replace(/(key|token|authorization)\s*[:=]\s*[^,\s]+/ig, "$1=[redacted]")
    .slice(0, 500);
}

async function fetchTimed(url, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchProvider(url, options) {
  // HTTP errors (503/429/404) are returned immediately so the model fallback
  // can run. Only a transport-level failure gets one short retry.
  try {
    return await fetchTimed(url, options);
  } catch (firstError) {
    await new Promise(resolve => setTimeout(resolve, 300));
    try {
      return await fetchTimed(url, options);
    } catch (_) {
      throw firstError;
    }
  }
}

function openRouterErrorDetails(body) {
  const error = body?.error || {};
  const meta = error?.metadata || {};
  const router = body?.openrouter_metadata || {};
  const pipeline = Array.isArray(router.pipeline)
    ? router.pipeline.slice(0, 4).map(stage => {
        const parts = [stage?.type, stage?.name, stage?.summary].filter(Boolean);
        return parts.join("/");
      }).join(";")
    : "";
  const fields = [
    meta.error_type ? `error_type=${meta.error_type}` : "",
    meta.provider_name ? `provider=${meta.provider_name}` : "",
    meta.provider_code ? `provider_code=${meta.provider_code}` : "",
    meta.limit_source ? `limit_source=${meta.limit_source}` : "",
    meta.model_slug ? `model=${meta.model_slug}` : "",
    Array.isArray(meta.reasons) && meta.reasons.length ? `reasons=${meta.reasons.slice(0, 3).join(",")}` : "",
    router.region ? `region=${router.region}` : "",
    router.requested ? `requested=${router.requested}` : "",
    router.strategy ? `strategy=${router.strategy}` : "",
    pipeline ? `pipeline=${pipeline}` : ""
  ].filter(Boolean);
  return fields.join(" | ");
}

async function readJsonResponse(response, provider) {
  const raw = await response.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    const plain = String(raw || "").replace(/\\s+/g, " ").slice(0, 240);
    throw new Error(`${provider} returned non-JSON HTTP ${response.status}: ${plain || "empty response"}`);
  }
  if (body && typeof body === "object") {
    Object.defineProperty(body, "__rawProviderResponse", {value:raw, enumerable:false, configurable:false});
  }
  if (!response.ok) {
    const message = body?.error?.message || body?.message || raw;
    const details = provider === "OpenRouter" ? openRouterErrorDetails(body) : "";
    const hint = provider === "OpenRouter" && response.status === 403 && !details
      ? " | OpenRouter returned 403 but did not provide policy metadata; check API-key permissions/guardrails and provider-side access."
      : "";
    throw new Error(`${provider} HTTP ${response.status}: ${String(message).slice(0, 260)}${details ? ` | ${details}` : ""}${hint}`);
  }
  return body;
}

function extractJsonObject(raw, provider) {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) return raw;
  const text = String(raw || "").trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/i, "");

  try {
    return JSON.parse(text);
  } catch (_) {
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(text.slice(start, end + 1));
      } catch (_) {}
    }
    if (text.length >= 8) {
      // Accept provider-native prose as source material. Do not infer a trade
      // direction from free text; retain the full answer for the data engine/UI.
      return {
        bias: "WAIT",
        summary: hasPersianText(text) ? text.slice(0, 420) : "پاسخ متنی مدل دریافت شد؛ جزئیات اصلی در متن خام پاسخ نگهداری شده است.",
        observations: [], risks: [], confidence: null, confidenceDeclared: false,
        overlays: [], rawText: text, responseFormat: "text",
        _normalization: {sourceFormat:"plain_text", partial:true}
      };
    }
    throw new Error(`${provider} response was empty or not usable`);
  }
}

function hasPersianText(value) {
  return /[\u0600-\u06FF]/.test(String(value || ""));
}

function normalizeAnalyticalWeights(raw) {
  const keys = ["trend", "marketStructure", "liquidity", "entryConfirmation", "riskReward"];
  const source = raw && typeof raw === "object" ? raw : {};
  const values = keys.map(key => Number(source[key]));
  if (values.some(value => !Number.isFinite(value) || value < 0 || value > 100)) {
    throw new Error("analyticalWeights must contain five numeric values from 0 to 100");
  }
  const total = values.reduce((sum, value) => sum + value, 0);
  if (total <= 0) throw new Error("analyticalWeights total must be greater than zero");
  const normalized = values.map(value => Math.round(value * 100 / total));
  // Correct rounding drift so the five percentages always total exactly 100.
  normalized[0] += 100 - normalized.reduce((sum, value) => sum + value, 0);
  return Object.fromEntries(keys.map((key, index) => [key, normalized[index]]));
}

function normalizeFactorScores(raw) {
  const keys = ["trend", "marketStructure", "liquidity", "entryConfirmation", "riskReward"];
  const source = raw && typeof raw === "object" ? raw : {};
  const out = {};
  for (const key of keys) {
    const value = Number(source[key]);
    if (!Number.isFinite(value) || value < 0 || value > 100) {
      throw new Error(`factorScores.${key} must be a number from 0 to 100`);
    }
    out[key] = Math.round(value);
  }
  return out;
}


function extractTimeframeNarrative(value) {
  const chunks = [];
  const seenText = new Set();
  const add = (x, key = '') => {
    if (typeof x !== 'string' || !x.trim()) return;
    const normalized = x.trim();
    if (normalized.length < 3 || seenText.has(normalized)) return;
    seenText.add(normalized);
    chunks.push(normalized);
  };
  const walkText = (node, depth = 0, key = '') => {
    if (node == null || depth > 6) return;
    if (typeof node === 'string') {
      const trimmed = node.trim();
      // Provider envelopes frequently contain the model's actual answer as a
      // JSON string several levels below choices/message/content/parts.
      if (trimmed.length <= 100000 && ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']')))) {
        try { walkText(JSON.parse(trimmed), depth + 1, key); return; } catch (_) {}
      }
      add(node, key);
      return;
    }
    if (Array.isArray(node)) { node.slice(0, 120).forEach(item => walkText(item, depth + 1, key)); return; }
    if (typeof node !== 'object') return;
    for (const [childKey, child] of Object.entries(node).slice(0, 180)) {
      if (/prompt|debug|stack|usage|headers|request|timeframeanalysis|multitimeframeanalysis|timeframes?|evidence|candleTime|timestamp/i.test(childKey)) continue;
      walkText(child, depth + 1, childKey);
    }
  };
  // Explicitly include the complete answer, not the short UI summary (which
  // is intentionally capped) and not merely the small set of known JSON keys.
  for (const key of ['summary','analysis','reasoning','text','conclusion','market_outlook','overall_analysis','observations','findings','highlights','key_points','rawText']) {
    if (value?.[key] !== undefined) walkText(value[key], 0, key);
  }
  const normalizeDigits = s => s.replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
  const text = normalizeDigits(chunks.join('\n')).replace(/\r/g, '').replace(/[ي]/g, 'ی').replace(/[ك]/g, 'ک');
  const aliases = [
    ['1h', /(?:\b1\s*h(?:our)?\b|\b60\s*m(?:in(?:ute)?)?\b|\bhourly\b|\b1\s*ساعت(?:ه)?|یک\s*ساعت(?:ه)?|ساعتی|یک[‌\s-]*ساعته)/ig],
    ['15m', /(?:\b15\s*m(?:in(?:ute)?)?\b|\b15\s*minute\b|\b15\s*دقیقه|پانزده\s*دقیقه|ربع\s*ساعت|پانزده[‌\s-]*دقیقه‌ای)/ig],
    ['5m', /(?:\b5\s*m(?:in(?:ute)?)?\b|\b5\s*minute\b|\b5\s*دقیقه|پنج\s*دقیقه|پنج[‌\s-]*دقیقه‌ای)/ig]
  ];
  const hits = [];
  for (const [tf, re] of aliases) {
    let match;
    while ((match = re.exec(text)) !== null) hits.push({tf, start:match.index, end:match.index+match[0].length});
  }
  hits.sort((a,b)=>a.start-b.start);
  const out = {};
  for (let i=0;i<hits.length;i++) {
    const hit=hits[i];
    const nextDifferent = hits.slice(i+1).find(x=>x.tf!==hit.tf);
    const start=hit.start;
    const end=nextDifferent?.start ?? Math.min(text.length,hit.end+1200);
    const segment=text.slice(start,end).slice(0,1400);
    const bearish=/(?:\bBEAR(?:ISH)?\b|\bDOWN(?:TREND)?\b|نزولی|فشار\s*فروش|کف(?:‌|\s)*های?\s*پایین(?:تر)?|سقف(?:‌|\s)*های?\s*پایین(?:تر)?|LOWER\s+HIGHS?|LOWER\s+LOWS?)/i.test(segment);
    const bullish=/(?:\bBULL(?:ISH)?\b|\bUP(?:TREND)?\b|صعودی|فشار\s*خرید|کف(?:‌|\s)*های?\s*بالاتر|سقف(?:‌|\s)*های?\s*بالاتر|HIGHER\s+HIGHS?|HIGHER\s+LOWS?)/i.test(segment);
    const range=/(?:\bRANGE\b|\bRANGING\b|SIDEWAYS|ACCUMULATION|DISTRIBUTION|رنج|محدوده|انباشت|توزیع|خنثی)/i.test(segment);
    const trend=bearish&&!bullish?'BEARISH':bullish&&!bearish?'BULLISH':range&&!bearish&&!bullish?'RANGE':'UNKNOWN';
    const phase=/ACCUMULATION|انباشت/i.test(segment)?'ACCUMULATION':/DISTRIBUTION|توزیع/i.test(segment)?'DISTRIBUTION':range?'RANGING':(trend!=='UNKNOWN'?'TRENDING':'UNKNOWN');
    if (trend === 'UNKNOWN' && phase === 'UNKNOWN') continue;
    const evidence=segment.split(/\n+/).map(x=>x.trim()).filter(x=>x.length>=8).slice(0,3).map(x=>x.slice(0,220));
    const existing=out[hit.tf];
    // Keep the most informative occurrence; generic timeframe mentions must
    // not overwrite an explicit trend section elsewhere in the same answer.
    if (!existing || (existing.trend==='UNKNOWN' && trend!=='UNKNOWN') || (existing.phase==='UNKNOWN' && phase!=='UNKNOWN')) {
      out[hit.tf]={trend,structure:trend,structureEvent:'UNKNOWN',phase,liquidity:'UNKNOWN',buyerStrength:null,sellerStrength:null,evidence:evidence.length?evidence:[segment.slice(0,220)],_narrativeExtracted:true,_sourcePath:`narrative:${hit.tf}`};
    }
  }
  return out;
}

function normalizeTimeframeContractV3(value) {
  // Provider-native outputs may wrap timeframe data under analysis/market keys.
  // Search only for objects that look like a timeframe map; never manufacture
  // a timeframe from a generic narrative paragraph.
  const timeframeNames = {
    '1h':['1h','1H','60m','60min','1hour','hourly'],
    '15m':['15m','15M','15min','15minute'],
    '5m':['5m','5M','5min','5minute']
  };
  const strengthAliases = {
    buyer: ['buyerStrength','buyersStrength','buyStrength','buyerPower','buyersPower','buyerPercent','buyersPercent','buyerPct','buyPressure','bullishStrength','bullPower'],
    seller: ['sellerStrength','sellersStrength','sellStrength','sellerPower','sellersPower','sellerPercent','sellersPercent','sellerPct','sellPressure','bearishStrength','bearPower']
  };
  const normalizeFieldKey = key => String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
  const isTimeframeItem = item => item && typeof item === 'object' && !Array.isArray(item) &&
    ['trend','direction','bias','structure','marketStructure','market_structure','structureEvent','structure_event','phase','regime','liquidity','sweep','evidence',
      ...strengthAliases.buyer, ...strengthAliases.seller, 'buyerSellerStrength','buyersSellers','marketPower','orderFlow','strength']
      .some(k => Object.keys(item).some(actual => normalizeFieldKey(actual) === normalizeFieldKey(k)));
  // Select one coherent timeframe map. Never merge fields from separate
  // branches: those branches may describe different contexts or snapshots.
  // Prefer the candidate containing the most timeframes, then the shallowest.
  const findRoot = root => {
    const candidates = [];
    const visited = new WeakSet();
    const walk = (node, depth = 0, path = '$') => {
      if (!node || typeof node !== 'object' || depth > 7 || visited.has(node)) return;
      visited.add(node);
      if (Array.isArray(node)) { node.slice(0, 100).forEach((child, i) => walk(child, depth + 1, `${path}[${i}]`)); return; }
      const candidate = {};
      for (const [tf, aliases] of Object.entries(timeframeNames)) {
        const found = Object.entries(node).find(([key]) => aliases.some(a => a.toLowerCase() === key.toLowerCase()));
        if (found && isTimeframeItem(found[1])) candidate[tf] = found[1];
      }
      if (Object.keys(candidate).length) candidates.push({map:candidate, count:Object.keys(candidate).length, depth, path});
      for (const [key, child] of Object.entries(node)) {
        if (/raw(text|response)|debug|stack|prompt/i.test(key)) continue;
        walk(child, depth + 1, `${path}.${key}`);
      }
    };
    walk(root);
    candidates.sort((a,b)=>b.count-a.count || a.depth-b.depth);
    const selected = candidates[0];
    if (!selected) return null;
    const peers = candidates.filter(candidate => candidate.count === selected.count && candidate.depth === selected.depth);
    const conflictingPeers = peers.slice(1).filter(candidate => JSON.stringify(candidate.map) !== JSON.stringify(selected.map));
    const conflictPaths = conflictingPeers.slice(0,8).map(candidate => candidate.path);
    return {map:selected.map,path:selected.path,candidateCount:candidates.length,otherCandidatePaths:candidates.slice(1,9).map(candidate=>candidate.path),conflictPaths,hasConflict:conflictingPeers.length>0};
  };
  const structuredCandidate = findRoot(value);
  const structuredRoot = structuredCandidate?.map || {};
  const narrativeRoot = extractTimeframeNarrative(value);
  const root = {};
  for (const timeframe of ['1h','15m','5m']) {
    const structured = structuredRoot[timeframe];
    const narrative = narrativeRoot[timeframe];
    // Same-provider narrative may fill a missing timeframe, but cannot
    // overwrite a structured field or manufacture a confirmed event.
    if (structured && narrative) {
      const merged = {...narrative, ...structured, _narrativeSupplemented:true};
      // Narrative extraction deliberately marks events UNKNOWN. Do not let
      // that placeholder shadow an explicit structured event embedded in the
      // provider's structure field (for example, "CHOCH bearish").
      for (const key of ['structureEvent','structure_event','event']) {
        if (narrative[key] === 'UNKNOWN' && structured[key] == null) delete merged[key];
      }
      root[timeframe] = merged;
    } else root[timeframe] = structured || narrative || null;
  }
  const pick = (obj, keys) => {
    if (!obj || typeof obj !== 'object') return undefined;
    for (const key of keys) if (obj[key] !== undefined && obj[key] !== null) return obj[key];
    const wanted = new Set(keys.map(normalizeFieldKey));
    const found = Object.entries(obj).find(([k,v]) => wanted.has(normalizeFieldKey(k)) && v != null);
    return found?.[1];
  };
  const parsePercent = raw => {
    if (typeof raw === 'number') return Number.isFinite(raw) ? raw : NaN;
    if (raw && typeof raw === 'object') {
      const nested = pick(raw, ['value','percent','percentage','pct','score','strength']);
      return nested === undefined ? NaN : parsePercent(nested);
    }
    if (typeof raw !== 'string') return NaN;
    const normalized = raw.trim().replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d))
      .replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d)).replace(/[٪]/g, '%').replace(/,/g, '');
    const match = normalized.match(/^([-+]?(?:\d+\.?\d*|\.\d+))\s*%?$/);
    return match ? Number(match[1]) : NaN;
  };
  const pickStrength = (item, side) => {
    if (!item || typeof item !== 'object') return NaN;
    const aliases = strengthAliases[side];
    let raw = pick(item, aliases);
    if (raw !== undefined) return parsePercent(raw);
    const groups = ['buyerSellerStrength','buyersSellers','marketPower','orderFlow','strength','pressure','power'];
    for (const groupName of groups) {
      const group = pick(item, [groupName]);
      if (!group || typeof group !== 'object') continue;
      raw = pick(group, aliases.concat(side === 'buyer' ? ['buyer','buyers','buy','bullish'] : ['seller','sellers','sell','bearish']));
      if (raw !== undefined) return parsePercent(raw);
    }
    return NaN;
  };
  const enumKey = raw => String(raw ?? '').trim().toUpperCase().replace(/[\s-]+/g,'_');
  const normalizeTrend = raw => {
    const key=enumKey(raw);
    if (/^(BULL|BULLISH|UP|UPTREND|UP_TREND|صعودی|روند_صعودی)$/.test(key)) return 'BULLISH';
    if (/^(BEAR|BEARISH|DOWN|DOWNTREND|DOWN_TREND|نزولی|روند_نزولی)$/.test(key)) return 'BEARISH';
    if (/^(RANGE|RANGING|SIDEWAYS|CONSOLIDATION|خنثی|رنج|محدوده)$/.test(key)) return 'RANGE';
    return 'UNKNOWN';
  };
  const eventNegated = text => /(?:\b(?:NO|NOT|UNCONFIRMED|NOT_CONFIRMED|REJECTED|FAILED)\b.{0,45}\b(?:CHOCH|MSS|BOS|BREAK_OF_STRUCTURE)\b|\b(?:CHOCH|MSS|BOS|BREAK_OF_STRUCTURE)\b.{0,45}\b(?:NOT|UNCONFIRMED|NOT_CONFIRMED|REJECTED|FAILED)\b|(?:CHOCH|MSS|BOS).{0,45}(?:تأیید\s*نشده|تایید\s*نشده|رد\s*شد|نامعتبر)|(?:تأیید\s*نشده|تایید\s*نشده|رد\s*شد|نامعتبر).{0,45}(?:CHOCH|MSS|BOS))/i.test(text);
  const normalizeStructure = (raw, evidence=[]) => {
    const text = [typeof raw === 'string' ? raw : (raw && typeof raw === 'object' ? JSON.stringify(raw) : ''), ...evidence].join(' ').toUpperCase();
    if (eventNegated(text)) return 'UNKNOWN';
    if (/CHOCH|MSS|MARKET_STRUCTURE_SHIFT|CHARACTER_CHANGE|تغییر[\s_]+ساختار|تغییر[\s_]+کاراکتر|چرخش[\s_]+ساختار/.test(text)) return 'TRANSITION';
    if (/BULLISH_BOS|BOS_BULLISH|BOS[\s_:]+BULLISH|BOS\+|BREAK_OF_STRUCTURE_UP|HH_HL|ساختار[\s_]+صعودی|شکست[\s_]+صعودی|کف[\s_]+بالاتر/.test(text)) return 'BULLISH';
    if (/BEARISH_BOS|BOS_BEARISH|BOS[\s_:]+BEARISH|BOS-|BREAK_OF_STRUCTURE_DOWN|LH_LL|ساختار[\s_]+نزولی|شکست[\s_]+نزولی|سقف[\s_]+پایینتر/.test(text)) return 'BEARISH';
    if (/RANGE|RANGING|SIDEWAYS|ساختار_رنج|ساختار_خنثی|محدوده_خنثی/.test(text)) return 'RANGE';
    const key=enumKey(raw);
    if (['BULL','BULLISH','BEAR','BEARISH','RANGE','TRANSITION','UNKNOWN'].includes(key)) return key==='BULL'?'BULLISH':key==='BEAR'?'BEARISH':key;
    return 'UNKNOWN';
  };
  const normalizeStructureEvent = (raw, evidence=[]) => {
    const text=[typeof raw==='string'?raw:(raw&&typeof raw==='object'?JSON.stringify(raw):''),...evidence].join(' ').toUpperCase();
    if (/NO_EVENT|NO_BOS|NO_CHOCH|NO_MSS|\bNONE\b|بدون_رویداد/.test(text)) return 'NONE';
    if (eventNegated(text)) return 'UNKNOWN';
    const eventDir = direction => {
      const word = direction === 'BULLISH' ? '(?:BULLISH|BULL|UPWARD)' : '(?:BEARISH|BEAR|DOWNWARD)';
      const english = new RegExp(`(?:${word})[_\\s:-]*(?:CHOCH|MSS|BOS)|(?:CHOCH|MSS|BOS)[_\\s:-]*(?:${word})`, 'i');
      const persian = direction === 'BULLISH'
        ? /(?:CHOCH|MSS|BOS).{0,28}(?:صعودی|صعودي)|(?:صعودی|صعودي).{0,28}(?:CHOCH|MSS|BOS)/i
        : /(?:CHOCH|MSS|BOS).{0,28}(?:نزولی|نزولي)|(?:نزولی|نزولي).{0,28}(?:CHOCH|MSS|BOS)/i;
      return english.test(text) || persian.test(text);
    };
    const explicitBull=eventDir('BULLISH');
    const explicitBear=eventDir('BEARISH');
    const direction=explicitBull!==explicitBear?(explicitBull?'BULLISH':'BEARISH'):null;
    if(/CHOCH/.test(text)) return direction?`CHOCH_${direction}`:'UNKNOWN';
    if(/MSS|MARKET_STRUCTURE_SHIFT/.test(text)) return direction?`MSS_${direction}`:'UNKNOWN';
    if(/BOS|BREAK_OF_STRUCTURE/.test(text)) return direction?`BOS_${direction}`:'UNKNOWN';
    if(/NO_EVENT|NO_BOS|NO_CHOCH|NONE|بدون_رویداد|شکست_تأیید_نشده/.test(text)) return 'NONE';
    return 'UNKNOWN';
  };
  const normalizePhase = raw => {
    const key=enumKey(raw);
    if (['TREND','TRENDING','MARKUP','MARKDOWN','BULL','BULLISH','BEAR','BEARISH','UPTREND','DOWNTREND','رونددار','صعودی','نزولی'].includes(key)) return 'TRENDING';
    if (['RANGE','RANGING','SIDEWAYS','CONSOLIDATION','تجمیع_خنثی'].includes(key)) return 'RANGING';
    if (['ACCUMULATION','انباشت'].includes(key)) return 'ACCUMULATION';
    if (['DISTRIBUTION','توزیع'].includes(key)) return 'DISTRIBUTION';
    if (['REVERSAL','REVERSING','بازگشت'].includes(key)) return 'REVERSAL';
    return 'UNKNOWN';
  };
  const normalizeLiquidity = raw => {
    const key=enumKey(raw);
    if (['BUY_SIDE_SWEEP','BSL_SWEEP','شکار_نقدینگی_بالا'].includes(key)) return 'BUY_SIDE_SWEEP';
    if (['SELL_SIDE_SWEEP','SSL_SWEEP','شکار_نقدینگی_پایین'].includes(key)) return 'SELL_SIDE_SWEEP';
    if (['BUY_SIDE_LIQUIDITY_POOL','BSL','BUY_SIDE_POOL','استخر_نقدینگی_بالا'].includes(key)) return 'BUY_SIDE_LIQUIDITY_POOL';
    if (['SELL_SIDE_LIQUIDITY_POOL','SSL','SELL_SIDE_POOL','استخر_نقدینگی_پایین'].includes(key)) return 'SELL_SIDE_LIQUIDITY_POOL';
    if (['BOTH_SWEEPS','هر_دو_جاروب'].includes(key)) return 'BOTH_SWEEPS';
    if (['BOTH_POOLS','هر_دو_استخر'].includes(key)) return 'BOTH_POOLS';
    if (['NONE','NO_SWEEP','بدون_جاروب'].includes(key)) return 'NONE';
    return 'UNKNOWN';
  };
  const normalized = {};
  let valid = !structuredCandidate?.hasConflict;
  for (const timeframe of ['1h','15m','5m']) {
    const item = root[timeframe];
    const provided = !!item && typeof item === 'object';
    const rawEvidence = pick(item,['evidence','observations','findings','events']);
    const evidence = Array.isArray(rawEvidence) ? rawEvidence.slice(0,12).map(entry => {
      if (typeof entry === 'string') return entry.trim();
      if (entry && typeof entry === 'object') {
        const detail = [entry.explanation, entry.description, entry.reason, entry.event, entry.type]
          .filter(x => typeof x === 'string' && x.trim()).join(' — ');
        return detail;
      }
      return '';
    }).filter(x => x.length >= 3).slice(0,5).map(x=>x.slice(0,180)) : [];
    const trend = normalizeTrend(pick(item,['trend','direction','bias']));
    const rawStructure = pick(item,['structure','marketStructure','market_structure']);
    const rawStructureEvent = pick(item,['structureEvent','structure_event','event']);
    const structure = normalizeStructure(rawStructure ?? rawStructureEvent, evidence);
    const structureEvent = normalizeStructureEvent(rawStructureEvent ?? rawStructure, evidence);
    const phase = normalizePhase(pick(item,['phase','regime','marketPhase']));
    const liquidity = normalizeLiquidity(pick(item,['liquidity','liquidityEvent','sweep']));
    const rawBuyer = pickStrength(item, 'buyer');
    const rawSeller = pickStrength(item, 'seller');
    const scoresPresent = Number.isFinite(rawBuyer) && Number.isFinite(rawSeller) && rawBuyer >= 0 && rawBuyer <= 100 && rawSeller >= 0 && rawSeller <= 100;
    // Preserve provider values exactly. Treat them as comparable percentages
    // only when the provider's pair is complementary (allowing small rounding drift).
    const strengthComparable = scoresPresent && Math.abs((rawBuyer + rawSeller) - 100) <= 2;
    const strengthUnverified = scoresPresent && !strengthComparable;
    const buyerStrength = scoresPresent ? rawBuyer : null;
    const sellerStrength = scoresPresent ? rawSeller : null;
    const coreValid = provided && trend !== 'UNKNOWN' && structure !== 'UNKNOWN' && structureEvent !== 'UNKNOWN' && phase !== 'UNKNOWN' && liquidity !== 'UNKNOWN' && !strengthUnverified && evidence.length > 0;
    // Buyer/seller pressure is an optional OHLCV-derived metric. Missing or
    // unusable volume must not invalidate otherwise complete market structure.
    const strengthStatus = strengthComparable ? 'AVAILABLE' : strengthUnverified ? 'UNVERIFIED' : 'INSUFFICIENT_DATA';
    if (!coreValid) valid = false;
    normalized[timeframe] = {provided,trend,structure,structureEvent,phase,buyerStrength,sellerStrength,strengthComparable,strengthScale:strengthComparable?((rawBuyer+rawSeller)===100?'COMPLEMENTARY_PERCENT':'COMPLEMENTARY_PERCENT_ROUNDING_DRIFT'):strengthUnverified?'UNVERIFIED_INDEPENDENT_SCORES':'UNAVAILABLE',strengthMethod:strengthComparable?'PROVIDER_DECLARED_COMPLEMENTARY_PERCENT':'UNAVAILABLE',strengthSource:strengthComparable?'MODEL_RESPONSE':'UNAVAILABLE',strengthStatus,liquidity,evidence,source:item?._narrativeExtracted?(structuredRoot[timeframe]?'STRUCTURED_WITH_NARRATIVE':'NARRATIVE'):'STRUCTURED',narrativeOnly:!!item?._narrativeExtracted&&!structuredRoot[timeframe],narrativeSupplemented:!!item?._narrativeSupplemented};
  }
  let evidence = Array.isArray(value?.evidence) ? value.evidence.slice(0,12).filter(item =>
    item && ['1h','15m','5m'].includes(String(item.timeframe).toLowerCase()) && typeof item.type === 'string' &&
    typeof item.event === 'string' && ['CONFIRMED','PENDING','REJECTED','NOT_CONFIRMED'].includes(String(item.status).toUpperCase()) &&
    typeof item.explanation === 'string' && hasPersianText(item.explanation)
  ).map(item => {
    const candleTime = Number(item.candleTime ?? item.timestamp);
    const price = Number(item.price);
    const referenceLevel = Number(item.referenceLevel ?? item.level);
    return {
      timeframe:String(item.timeframe).toLowerCase(), type:String(item.type).slice(0,32), event:String(item.event).slice(0,48),
      status:String(item.status).toUpperCase(), explanation:String(item.explanation).slice(0,180),
      candleTime:Number.isFinite(candleTime) && candleTime > 0 ? Math.floor(candleTime) : null,
      price:Number.isFinite(price) && price > 0 ? price : null,
      referenceLevel:Number.isFinite(referenceLevel) && referenceLevel > 0 ? referenceLevel : null
    };
  }) : [];
  if (Array.isArray(value?.evidence) && evidence.length !== value.evidence.length) valid = false;
  if (!evidence.length) {
    for (const timeframe of ['1h','15m','5m']) {
      for (const explanation of normalized[timeframe].evidence) evidence.push({timeframe,type:'STRUCTURE',event:'OBSERVATION',status:'NOT_CONFIRMED',explanation});
    }
  }
  if (evidence.length === 0) valid = false;
  const invalidationRaw = String(value?.invalidation || '').trim();
  const invalidation = hasPersianText(invalidationRaw) ? invalidationRaw : 'شرط ابطال سناریو در پاسخ مدل به‌صورت صریح ثبت نشده است.';
  const provenance = structuredCandidate ? {sourcePath:structuredCandidate.path,candidateCount:structuredCandidate.candidateCount,otherCandidatePaths:structuredCandidate.otherCandidatePaths,conflictPaths:structuredCandidate.conflictPaths,conflict:structuredCandidate.hasConflict} : {sourcePath:narrativeRoot?'narrative-extraction':null,candidateCount:0,otherCandidatePaths:[],conflictPaths:[],conflict:false};
  return {valid,timeframeAnalysis:normalized,evidence,invalidation:invalidation.slice(0,220),provenance};
}

const ANALYSIS_SECTION_KEYS = ["regime", "structure", "liquidity", "poi", "premiumDiscount", "volumeMomentum", "scenarios", "execution", "dataQuality"];
const ANALYSIS_SECTION_LABELS = {
  regime: "رژیم و فاز بازار", structure: "ساختار بازار و چندتایم‌فریمی", liquidity: "نقدینگی و شکار حدضرر",
  poi: "نواحی مهم و نقاط علاقه", premiumDiscount: "محدوده تعادلی و Premium/Discount",
  volumeMomentum: "حجم، مومنتوم و نوسان", scenarios: "سناریوهای جایگزین و شروط فعال‌سازی",
  execution: "کیفیت ورود و مدیریت معامله", dataQuality: "کیفیت داده و محدودیت‌های تحلیل"
};
function normalizeAnalysisContractV3(value) {
  const source = value?.analysisSections;
  const out = {};
  const sectionStatus = {};
  const sourceShapeValid = !!source && typeof source === "object" && !Array.isArray(source);
  let allSectionsValid = sourceShapeValid;
  for (const key of ANALYSIS_SECTION_KEYS) {
    const section = sourceShapeValid ? source[key] : null;
    const statusOk = ["AVAILABLE", "NOT_AVAILABLE", "NOT_APPLICABLE", "INSUFFICIENT_DATA"].includes(section?.status);
    const rawFindings = Array.isArray(section?.findings) ? section.findings :
      (Array.isArray(section?.items) ? section.items : (typeof section?.summary === "string" ? [section.summary] : []));
    const findingsFieldPresent = Array.isArray(section?.findings) || Array.isArray(section?.items) || typeof section?.summary === "string";
    const findingsShapeOk = findingsFieldPresent && rawFindings.length <= 12 && rawFindings.every(x => typeof x === "string" && x.trim().length >= 2);
    const findingsStatusOk = section?.status === "AVAILABLE" ? rawFindings.length >= 1 : true;
    const valid = statusOk && findingsShapeOk && findingsStatusOk;
    if (!valid) allSectionsValid = false;
    const normalizedStatus = valid ? section.status : "INVALID";
    sectionStatus[key] = {
      status: normalizedStatus,
      valid,
      reason: !statusOk ? "SECTION_STATUS_MISSING_OR_UNSUPPORTED" :
        !findingsFieldPresent ? "FINDINGS_FIELD_MISSING" :
        !findingsShapeOk ? "FINDINGS_SHAPE_INVALID" :
        !findingsStatusOk ? "AVAILABLE_REQUIRES_FINDING" : null
    };
    // Preserve each valid factor even when a different factor is malformed.
    // Invalidity is local to this section and is not copied to sibling factors.
    const findings = valid ? rawFindings.slice(0, 6).map(x => String(x).trim().slice(0, 500)) : [];
    out[key] = {status: normalizedStatus, findings};
  }
  return {
    // `schemaValid` describes the envelope; `valid` means every section passed.
    // Consumers must use sectionStatus for factor-level decisions.
    schemaValid: sourceShapeValid && ANALYSIS_SECTION_KEYS.every(key => Object.hasOwn(source, key)),
    valid: allSectionsValid,
    analysisSections: out,
    sectionStatus
  };
}

function analysisSectionsOutputSchema() {
  const section = {type:"object", additionalProperties:false,
    properties:{status:{type:"string",enum:["AVAILABLE","NOT_AVAILABLE","NOT_APPLICABLE","INSUFFICIENT_DATA"]},findings:{type:"array",minItems:0,maxItems:3,items:{type:"string",minLength:4,maxLength:260}}},
    required:["status","findings"]};
  return {type:"object",additionalProperties:false,properties:Object.fromEntries(ANALYSIS_SECTION_KEYS.map(k=>[k,section])),required:ANALYSIS_SECTION_KEYS};
}

function downgradeTruncatedAnalysis(parsed, provider) {
  const execution = new Set(["Entry", "SL", "TP1", "TP2", "TP3"]);
  return {
    ...parsed,
    bias: "WAIT",
    confidence: 0,
    weightsProvided: false,
    contractStatus: "DEGRADED",
    normalization: {...(parsed.normalization || {}), providerCompletionTruncated:true},
    overlays: (parsed.overlays || []).filter(item => !execution.has(item.kind)),
    risks: [...(parsed.risks || []).slice(0, 4), "پاسخ مدل به سقف طول خروجی رسید؛ برای جلوگیری از استفاده از تحلیل ناقص، سیگنال اجرایی صادر نشد."],
  };
}


const DATA_CATEGORY_DEFS = [
  ['orderBook',['orderbook','order_book','depth','market_depth','دفتر_سفارش','عمق_بازار']],
  ['derivatives',['funding','funding_rate','fundingrate','open_interest','openinterest','oi','derivatives','perpetual','فاندینگ','نرخ_تامین','بهره_باز','مشتقات']],
  ['liquidations',['liquidation','liquidations','liquidation_map','liquidation_cluster','لیکوییدیشن','تصفیه']],
  ['onChain',['onchain','on_chain','exchange_flow','exchangeflow','whale','wallet','نهنگ','آنچین','جریان_صرافی']],
  ['newsSentiment',['news','sentiment','social','headline','اخبار','احساسات','شبکه_اجتماعی']],
  ['providerSpecific',['altfins','indicator','indicator_value','screener','provider_metric','شاخص_بیرونی','اندیکاتور_بیرونی']]
];
function flattenAnalysisValues(value,path='',out=[],depth=0) {
  if(depth>5 || out.length>=160 || value==null)return out;
  if(typeof value==='string' || typeof value==='number' || typeof value==='boolean'){
    const text=String(value).trim();if(text)out.push({path,text:text.slice(0,700)});
  }else if(Array.isArray(value)){
    value.slice(0,24).forEach((item,i)=>flattenAnalysisValues(item,`${path}[${i}]`,out,depth+1));
  }else if(typeof value==='object'){
    for(const [key,child] of Object.entries(value).slice(0,40)){
      if(/raw(text|response)|debug|stack|prompt|api.?key/i.test(key))continue;
      flattenAnalysisValues(child,path?`${path}.${key}`:key,out,depth+1);
    }
  }
  return out;
}
const CORE_RESPONSE_KEYS = new Set(['analysissections','timeframeanalysis','multitimeframeanalysis','timeframes','evidence','overlays','summary','analysis','conclusion','market_outlook','overall_analysis','reasoning','text','observations','key_points','findings','highlights','risks','risk_factors','warnings','confidence','bias','decision','signal','direction','recommendation','contractversion','invalidation','analyticalweights','factorscores','normalization','rawtext','rawresponse','provider','model','status','finishreason','usage']);
function flattenSupplementaryValues(value,path='',out=[],depth=0) {
  if (depth>5 || out.length>=100 || value==null) return out;
  const segments=path.split('.').filter(Boolean).map(x=>x.replace(/\[\d+\]$/,'').toLowerCase());
  if (segments.some(x=>CORE_RESPONSE_KEYS.has(x))) return out;
  const categoryPath=segments.some(segment=>DATA_CATEGORY_DEFS.some(([,aliases])=>aliases.some(alias=>segment===String(alias).toLowerCase())));
  if (typeof value==='number' && Number.isFinite(value) && categoryPath) {
    out.push({path,text:String(value)});
  } else if (typeof value==='string') {
    const text= value.trim();
    const numericText=/^[-+]?\d+(\.\d+)?%?$/.test(text);
    if ((text.length>=8 || (categoryPath && numericText)) && !/^(available|not_available|not_applicable|insufficient_data|unknown|true|false|null|undefined)$/i.test(text) && (!numericText || categoryPath)) out.push({path,text:text.slice(0,700)});
  } else if (Array.isArray(value)) {
    value.slice(0,20).forEach((item,i)=>flattenSupplementaryValues(item,`${path}[${i}]`,out,depth+1));
  } else if (typeof value==='object') {
    for (const [key,child] of Object.entries(value).slice(0,35)) {
      if (/raw(text|response)|debug|stack|prompt|api.?key/i.test(key)) continue;
      flattenSupplementaryValues(child,path?`${path}.${key}`:key,out,depth+1);
    }
  }
  return out;
}
function normalizeDataCategories(value, rawText='') {
  const categories={};
  const flat=flattenSupplementaryValues(value);
  for (const [category,aliases] of DATA_CATEGORY_DEFS) {
    const hits=flat.filter(item=>{
      const segments=item.path.split('.').map(x=>x.replace(/\[\d+\]$/,'').toLowerCase());
      return segments.some(segment=>aliases.some(alias=>segment===String(alias).toLowerCase()));
    });
    const unique=[...new Map(hits.map(x=>[`${x.path}|${x.text}`,x])).values()].slice(0,8);
    if(unique.length) categories[category]=unique.map(x=>({text:x.text,sourcePath:x.path,origin:'provider_claim'}));
  }
  // Only explicitly titled external-feed sections are extracted from prose.
  // Core market/structure/scenario paragraphs are already rendered elsewhere.
  if(typeof rawText==='string' && rawText.trim()) {
    const headings=[
      ['orderBook',/(?:^|\n)\s*(?:#{1,4}\s*)?(?:order book|market depth|دفتر سفارش|عمق بازار)\s*[:：\-]?\s*/ig],
      ['derivatives',/(?:^|\n)\s*(?:#{1,4}\s*)?(?:funding(?: rate)?|open interest|derivatives|فاندینگ|نرخ تأمین مالی|بهره باز)\s*[:：\-]?\s*/ig],
      ['liquidations',/(?:^|\n)\s*(?:#{1,4}\s*)?(?:liquidations?|لیکوییدیشن|تصفیه‌ها)\s*[:：\-]?\s*/ig],
      ['onChain',/(?:^|\n)\s*(?:#{1,4}\s*)?(?:on.?chain|exchange flows?|آنچین|جریان صرافی)\s*[:：\-]?\s*/ig],
      ['newsSentiment',/(?:^|\n)\s*(?:#{1,4}\s*)?(?:news|sentiment|social sentiment|اخبار|احساسات بازار)\s*[:：\-]?\s*/ig]
    ];
    for(const [category,regex] of headings){
      if(categories[category]?.length)continue;
      const match=regex.exec(rawText);if(!match)continue;
      const start=match.index+match[0].length,tail=rawText.slice(start);
      const nextHeading=tail.search(/\n\s*(?:#{1,4}\s*)?[\p{L}][^\n]{0,70}[:：]\s*/u);
      const sectionText=(nextHeading>=0?tail.slice(0,nextHeading):tail).trim();
      if(sectionText)categories[category]=[{text:sectionText.slice(0,900),sourcePath:'explicit_provider_heading',origin:'provider_claim'}];
    }
  }
  return categories;
}

function unwrapNestedAnalysisPayload(input) {
  // Providers (notably Groq) sometimes return the actual analysis as a JSON
  // string nested several levels below `analysis`, `result`, `content`, etc.
  // Expand only JSON-looking strings and retain every original field.
  const seen = new WeakSet();
  const expand = (node, depth = 0) => {
    if (depth > 6 || node == null) return node;
    if (typeof node === 'string') {
      const text = node.trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');
      if (text.length <= 100000 && ((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']')))) {
        try { return expand(JSON.parse(text), depth + 1); } catch (_) { return node; }
      }
      return node;
    }
    if (Array.isArray(node)) return node.slice(0, 200).map(item => expand(item, depth + 1));
    if (typeof node !== 'object') return node;
    if (seen.has(node)) return node;
    seen.add(node);
    const out = {};
    for (const [key, child] of Object.entries(node).slice(0, 160)) out[key] = expand(child, depth + 1);
    // Promote nested contract-bearing objects without discarding wrapper data.
    for (const key of ['summary', 'analysis', 'result', 'output', 'content', 'data', 'response']) {
      const nested = out[key];
      if (nested && typeof nested === 'object' && !Array.isArray(nested) &&
          (nested.contractVersion !== undefined || nested.analysisSections || nested.timeframeAnalysis || nested.multiTimeframeAnalysis || nested.timeframes || nested.bias || nested.overlays)) {
        Object.assign(out, nested);
      }
    }
    return out;
  };
  return expand(input);
}

function parseModelJson(raw, provider, rawProviderResponse = null) {
  const value = unwrapNestedAnalysisPayload(extractJsonObject(raw, provider));
  const rawBias = String(value.bias || value.decision || value.signal || value.direction || value.recommendation || value.trade_signal || "").trim().toUpperCase();
  const recognizedBias = ["BUY", "LONG", "BULLISH", "STRONG_BUY", "SELL", "SHORT", "BEARISH", "STRONG_SELL", "WAIT", "HOLD", "NEUTRAL", "NO_TRADE"];
  const bias = recognizedBias.includes(rawBias) ? normalizeSignal(rawBias) : "WAIT";
  const confidenceRaw = value.confidence ?? value.confidence_score ?? value.conviction;
  const confidenceCandidate = confidenceRaw === null || confidenceRaw === undefined || confidenceRaw === '' ? NaN : Number(confidenceRaw);
  const confidenceDeclared = Number.isFinite(confidenceCandidate) && confidenceCandidate >= 0 && confidenceCandidate <= 100;
  const confidenceNumber = confidenceDeclared ? Math.round(confidenceCandidate) : null;
  const summaryCandidate = value.summary ?? value.conclusion ?? value.market_outlook ?? value.overall_analysis ?? value.reasoning ?? value.text;
  const rawSerialized = typeof raw === "string" ? raw : JSON.stringify(value);
  const summaryText = typeof summaryCandidate === "string" ? summaryCandidate.trim() : "";
  const summaryLooksLikeJson = summaryText.startsWith("{") && summaryText.endsWith("}");
  const summary = summaryText && !summaryLooksLikeJson ? summaryText :
    "تحلیل ساختاریافته دریافت شد؛ جزئیات در بخش‌های تحلیلی نمایش داده می‌شود.";
  const listText = (...candidates) => {
    for (const candidate of candidates) if (Array.isArray(candidate)) return candidate.filter(x => typeof x === "string" && hasPersianText(x)).slice(0, 8).map(x => x.slice(0, 500));
    return [];
  };
  const observations = listText(value.observations, value.key_points, value.findings, value.highlights);
  const risks = listText(value.risks, value.risk_factors, value.warnings, value.risk_assessment);
  const timeframeContract = normalizeTimeframeContractV3(value);
  const contractV3 = normalizeAnalysisContractV3(value);
  let weightsProvided = false;
  let analyticalWeights = {};
  let factorScores = {};
  let analyticalWeightsStatus = "NOT_PROVIDED";
  let factorScoresStatus = "NOT_PROVIDED";
  if (value.analyticalWeights !== undefined && value.analyticalWeights !== null) {
    try { analyticalWeights = normalizeAnalyticalWeights(value.analyticalWeights); analyticalWeightsStatus = "PROVIDED"; }
    catch (_) { analyticalWeightsStatus = "INVALID_OPTIONAL_METADATA"; }
  }
  if (value.factorScores !== undefined && value.factorScores !== null) {
    try { factorScores = normalizeFactorScores(value.factorScores); factorScoresStatus = "PROVIDED"; }
    catch (_) { factorScoresStatus = "INVALID_OPTIONAL_METADATA"; }
  }
  weightsProvided = analyticalWeightsStatus === "PROVIDED" && factorScoresStatus === "PROVIDED";
  const overlays = normalizeAiOverlays(value.overlays);
  const tradeKinds = new Set(overlays.map(item => item.kind));
  if (bias === "BUY" || bias === "SELL") {
    const required = ["Entry", "SL", "TP1", "TP2", "TP3"];
    const side = bias === "BUY" ? "bullish" : "bearish";
    const matchingOb = overlays.some(x => x.type === "zone" && x.kind === (bias === "BUY" ? "Bullish OB" : "Bearish OB") && x.direction === side);
    const matchingFvg = overlays.some(x => x.type === "zone" && ["FVG", bias === "BUY" ? "Bullish FVG" : "Bearish FVG"].includes(x.kind) && x.direction === side);
    // A valid setup needs one evidenced point of interest, not an artificial
    // requirement that both an OB and an FVG exist simultaneously.
    const matchingRetest = overlays.some(x => x.type === "line" && x.direction === side &&
      (bias === "BUY" ? ["Swing Low", "EQL"].includes(x.kind) : ["Swing High", "EQH"].includes(x.kind)));
    const missing = required.filter(kind => !tradeKinds.has(kind));
    if (!(matchingOb || matchingFvg || matchingRetest)) missing.push("یک POI معتبر (OB یا FVG یا بازآزمایی Swing/Liquidity)");
    if (missing.length) {
      // A provider may deliver a rich analysis without an executable plan.
      // Preserve it as WAIT rather than rejecting the entire provider response.
      value._normalization = {...(value._normalization || {}), tradePlanIncomplete:true, missingTradeFields:missing};
    }
    const entry = overlays.find(x => x.kind === "Entry")?.price;
    const stop = overlays.find(x => x.kind === "SL")?.price;
    const targets = [1,2,3].map(n => overlays.find(x => x.kind === `TP${n}`)?.price);
    const execution = overlays.filter(x => ["Entry", "SL", "TP1", "TP2", "TP3"].includes(x.kind));
    const correctDirection = execution.every(x => x.timeframe === "5m" && x.direction === (bias === "BUY" ? "bullish" : "bearish"));
    const risk = Math.abs(entry - stop);
    const rewards = targets.map(target => Math.abs(target - entry) / risk);
    const ordered = bias === "BUY"
      ? stop < entry && targets[0] > entry && targets[1] > targets[0] && targets[2] > targets[1]
      : stop > entry && targets[0] < entry && targets[1] < targets[0] && targets[2] < targets[1];
    const coherent = ordered && correctDirection && Number.isFinite(risk) && risk > 0 && rewards[0] >= 1 && rewards[1] >= 1.5 && rewards[2] >= 2;
    if (!coherent) value._normalization = {...(value._normalization || {}), tradePlanInconsistent:true};
  } else if (["Entry", "SL", "TP1", "TP2", "TP3"].some(kind => tradeKinds.has(kind))) {
    value._normalization = {...(value._normalization || {}), executionWithoutDirection:true};
  }
  const fullRaw = typeof value.rawText === "string" ? value.rawText : rawSerialized;
  const dataCategories = normalizeDataCategories(value, fullRaw);
  const extractedFacts = flattenAnalysisValues(value).slice(0, 120).map(item => ({...item, origin:"provider"}));
  const hasMeaningfulStructure = timeframeContract.valid || contractV3.valid || observations.length > 0 || risks.length > 0 || overlays.length > 0 || Object.keys(dataCategories).length > 0;
  return {
    status: "ok", bias, summary: summary.slice(0, 1000), observations, risks,
    confidence: confidenceNumber, confidenceDeclared, analyticalWeights, analyticalWeightsStatus, factorScores, factorScoresStatus, weightsProvided, overlays,
    contractVersion: 3, contractStatus: (timeframeContract.valid && contractV3.valid) ? "VALID" : (hasMeaningfulStructure ? "NORMALIZED" : "PARTIAL"),
    timeframeAnalysis: timeframeContract.timeframeAnalysis, timeframeProvenance: timeframeContract.provenance, evidence: timeframeContract.evidence, invalidation: timeframeContract.invalidation, analysisSections: contractV3.analysisSections, analysisSectionStatus: contractV3.sectionStatus, analysisContractSchemaValid: contractV3.schemaValid,
    rawText: String(fullRaw || "").slice(0, 20000),
    rawTextTruncated: String(fullRaw || "").length > 20000,
    rawTextOriginalLength: String(fullRaw || "").length,
    rawProviderResponse: typeof rawProviderResponse === "string" ? rawProviderResponse.slice(0, 100000) : null,
    rawProviderResponseTruncated: typeof rawProviderResponse === "string" && rawProviderResponse.length > 100000,
    rawProviderResponseOriginalLength: typeof rawProviderResponse === "string" ? rawProviderResponse.length : null,
    dataCategories, extractedFacts, responseFormat: value.responseFormat === "text" ? "text" : "json",
    normalization: {sourceFormat:value.responseFormat === "text" ? "plain_text" : "provider_json", partial:!hasMeaningfulStructure, tradePlanIncomplete:!!value._normalization?.tradePlanIncomplete, tradePlanInconsistent:!!value._normalization?.tradePlanInconsistent, executionWithoutDirection:!!value._normalization?.executionWithoutDirection, missingTradeFields:value._normalization?.missingTradeFields || [], timeframeNarrativeRecovered:['1h','15m','5m'].filter(tf=>timeframeContract.timeframeAnalysis[tf].source==='NARRATIVE'||timeframeContract.timeframeAnalysis[tf].source==='STRUCTURED_WITH_NARRATIVE'), timeframeNarrativeOnly:['1h','15m','5m'].filter(tf=>!!timeframeContract.timeframeAnalysis[tf].narrativeOnly), timeframeSources:Object.fromEntries(['1h','15m','5m'].map(tf=>[tf,timeframeContract.timeframeAnalysis[tf].source])), rawTextTruncated:String(fullRaw || "").length > 20000, rawTextOriginalLength:String(fullRaw || "").length, rawProviderResponseTruncated:typeof rawProviderResponse === "string" && rawProviderResponse.length > 100000, rawProviderResponseOriginalLength:typeof rawProviderResponse === "string" ? rawProviderResponse.length : null, providerCompletionTruncated:!!value._normalization?.providerCompletionTruncated}
  };
}

// Every provider owns its own plan. Levels are validated structurally and
// against the submitted candle history; no technical-engine or peer-model data is used.
function normalizeAiOverlays(raw) {
  if (!Array.isArray(raw)) return [];
  const allowedKinds = new Set(["Swing High", "Swing Low", "FVG", "Bullish FVG", "Bearish FVG", "Bullish OB", "Bearish OB", "EQH", "EQL", "BOS+", "BOS-", "CRT-H", "CRT-L", "EQ", "Entry", "SL", "TP1", "TP2", "TP3"]);
  const out = [];
  for (const item of raw.slice(0, MAX_AI_OVERLAYS)) {
    if (!item || typeof item !== "object") continue;
    const kind = String(item.kind || "").trim().slice(0, 32);
    const type = item.type === "zone" ? "zone" : item.type === "line" ? "line" : "";
    if (!allowedKinds.has(kind)) continue;
    if (!["1h", "15m", "5m"].includes(item.timeframe)) continue;
    if (!["bullish", "bearish", "neutral"].includes(item.direction)) continue;
    const timeframe = item.timeframe, direction = item.direction;
    const allowedStatus = new Set(["ACTIVE", "MITIGATED", "INVALIDATED", "PENDING", "UNSPECIFIED"]);
    const statusRaw = String(item.status ?? item.state ?? "UNSPECIFIED").trim().toUpperCase().replace(/[ -]+/g,"_");
    const status = allowedStatus.has(statusRaw) ? statusRaw : "UNSPECIFIED";
    const timestampValue = item.timestamp ?? item.time ?? item.createdAt;
    const numericTimestamp = Number(timestampValue);
    const parsedTimestamp = Number.isFinite(numericTimestamp) ? numericTimestamp : (typeof timestampValue === "string" ? Date.parse(timestampValue) / 1000 : NaN);
    const timestamp = Number.isFinite(parsedTimestamp) && parsedTimestamp > 0
      ? Math.floor(parsedTimestamp > 100000000000 ? parsedTimestamp / 1000 : parsedTimestamp) : null;
    const sourceEvidence = typeof item.evidence === "string" ? item.evidence.slice(0,180) : (typeof item.sourceEvidence === "string" ? item.sourceEvidence.slice(0,180) : null);
    const isZone = ["FVG", "Bullish FVG", "Bearish FVG", "Bullish OB", "Bearish OB"].includes(kind);
    if (!type || type !== (isZone ? "zone" : "line")) continue;
    // Directional zone labels and direction metadata must agree. A model may
    // not label a bearish supply block as a bullish demand zone (or vice versa).
    if ((kind === "Bullish OB" || kind === "Bullish FVG") && direction !== "bullish") continue;
    if ((kind === "Bearish OB" || kind === "Bearish FVG") && direction !== "bearish") continue;
    if (type === "line") {
      const price = Number(item.price);
      if (!Number.isFinite(price) || price <= 0) continue;
      out.push({type, kind, price, timeframe, direction, status, timestamp, sourceEvidence, provenance:"provider"});
    } else {
      const low = Number(item.low), high = Number(item.high);
      if (!Number.isFinite(low) || !Number.isFinite(high) || low <= 0 || high <= low) continue;
      out.push({type, kind, low, high, timeframe, direction, status, timestamp, sourceEvidence, provenance:"provider"});
    }
  }
  // A model cannot quietly provide duplicate execution levels.
  const unique = new Map();
  for (const item of out) unique.set(item.kind, item);
  return [...unique.values()];
}

function openRouterOutputSchema() {
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      contractVersion: {type:"integer", const:3},
      analysisSections: analysisSectionsOutputSchema(),
      bias: {type: "string", enum: ["BUY", "SELL", "WAIT"]},
      timeframeAnalysis: {
        type: "object", additionalProperties: false,
        properties: Object.fromEntries(["1h", "15m", "5m"].map(tf => [tf, {
          type:"object", additionalProperties:false,
          properties:{trend:{type:"string",enum:["BULLISH","BEARISH","RANGE","UNKNOWN"]},structure:{type:"string",enum:["BULLISH","BEARISH","RANGE","TRANSITION","UNKNOWN"]},structureEvent:{type:"string",enum:["BOS_BULLISH","BOS_BEARISH","CHOCH_BULLISH","CHOCH_BEARISH","MSS_BULLISH","MSS_BEARISH","NONE","UNKNOWN"]},phase:{type:"string",enum:["TRENDING","RANGING","ACCUMULATION","DISTRIBUTION","REVERSAL","UNKNOWN"]},buyerStrength:{type:["integer","null"],minimum:0,maximum:100},sellerStrength:{type:["integer","null"],minimum:0,maximum:100},liquidity:{type:"string",enum:["BUY_SIDE_SWEEP","SELL_SIDE_SWEEP","BUY_SIDE_LIQUIDITY_POOL","SELL_SIDE_LIQUIDITY_POOL","BOTH_SWEEPS","BOTH_POOLS","NONE","UNKNOWN"]},evidence:{type:"array",maxItems:5,items:{type:"string",maxLength:180}}},
          required:["trend","structure","structureEvent","phase","buyerStrength","sellerStrength","liquidity","evidence"]
        }])) ,
        required:["1h","15m","5m"]
      },
      evidence: {type:"array",minItems:1,maxItems:12,items:{type:"object",additionalProperties:false,properties:{timeframe:{type:"string",enum:["1h","15m","5m"]},type:{type:"string",maxLength:32},event:{type:"string",maxLength:48},status:{type:"string",enum:["CONFIRMED","PENDING","REJECTED","NOT_CONFIRMED"]},explanation:{type:"string",maxLength:180},candleTime:{type:["integer","null"]},price:{type:["number","null"]},referenceLevel:{type:["number","null"]}},required:["timeframe","type","event","status","explanation","candleTime","price","referenceLevel"]}},
      invalidation: {type:"string",maxLength:220},
      summary: {type: "string", maxLength: 260},
      observations: {type: "array", maxItems: 5, items: {type: "string", maxLength: 220}},
      risks: {type: "array", maxItems: 5, items: {type: "string", maxLength: 220}},
      confidence: {type: "integer", minimum: 0, maximum: 100},
      factorScores: {
        type: "object", additionalProperties: false,
        properties: {trend: {type: "integer", minimum: 0, maximum: 100}, marketStructure: {type: "integer", minimum: 0, maximum: 100}, liquidity: {type: "integer", minimum: 0, maximum: 100}, entryConfirmation: {type: "integer", minimum: 0, maximum: 100}, riskReward: {type: "integer", minimum: 0, maximum: 100}},
        required: ["trend", "marketStructure", "liquidity", "entryConfirmation", "riskReward"]
      },
      analyticalWeights: {
        type: "object", additionalProperties: false,
        properties: {
          trend: {type: "integer", minimum: 0, maximum: 100},
          marketStructure: {type: "integer", minimum: 0, maximum: 100},
          liquidity: {type: "integer", minimum: 0, maximum: 100},
          entryConfirmation: {type: "integer", minimum: 0, maximum: 100},
          riskReward: {type: "integer", minimum: 0, maximum: 100}
        },
        required: ["trend", "marketStructure", "liquidity", "entryConfirmation", "riskReward"]
      },
      overlays: {
        type: "array",
        maxItems: 10,
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            type: {type: "string", enum: ["line", "zone"]},
            kind: {type: "string", enum: ["Swing High", "Swing Low", "FVG", "Bullish FVG", "Bearish FVG", "Bullish OB", "Bearish OB", "EQH", "EQL", "BOS+", "BOS-", "CRT-H", "CRT-L", "EQ", "Entry", "SL", "TP1", "TP2", "TP3"]},
            price: {type: ["number", "null"]},
            low: {type: ["number", "null"]},
            high: {type: ["number", "null"]},
            timeframe: {type: "string", enum: ["1h", "15m", "5m"]},
            direction: {type: "string", enum: ["bullish", "bearish", "neutral"]},
            status: {type:"string", enum:["ACTIVE","MITIGATED","INVALIDATED","PENDING","UNSPECIFIED"]},
            timestamp: {type:["integer","null"]},
            evidence: {type:["string","null"], maxLength:180}
          },
          required: ["type", "kind", "price", "low", "high", "timeframe", "direction", "status", "timestamp", "evidence"]
        }
      }
    },
    required: ["contractVersion", "analysisSections", "bias", "timeframeAnalysis", "evidence", "invalidation", "summary", "observations", "risks", "overlays"]
  };
}

function groqStrictOutputSchema() {
  const schema = openRouterOutputSchema();
  // Groq strict mode supports a smaller JSON-Schema subset. Keep structural
  // constraints (types/enums/required/closed objects) and enforce numeric,
  // length and array bounds in our local validator instead of triggering a
  // 400 and silently falling back to unconstrained JSON.
  schema.properties.contractVersion = {type:"integer", enum:[3]};
  const strip = value => {
    if (!value || typeof value !== "object") return;
    for (const key of ["const", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems"]) delete value[key];
    for (const child of Object.values(value)) {
      if (Array.isArray(child)) child.forEach(strip);
      else if (child && typeof child === "object") strip(child);
    }
  };
  strip(schema);
  return schema;
}

function geminiOutputSchema() {
  const schema = openRouterOutputSchema();
  schema.properties.contractVersion = {type:"integer", enum:[3]};
  const overlays = schema.properties.overlays.items.properties;
  for (const key of ["price", "low", "high"]) {
    overlays[key] = {anyOf:[{type:"number"},{type:"null"}]};
  }
  const stripUnsupported = value => {
    if (!value || typeof value !== "object") return;
    delete value.minLength;
    delete value.maxLength;
    for (const child of Object.values(value)) {
      if (Array.isArray(child)) child.forEach(stripUnsupported);
      else if (child && typeof child === "object") stripUnsupported(child);
    }
  };
  stripUnsupported(schema);
  return schema;
}

function compressHistory(history) {
  // Preserve every source candle and its order, using compact quantized deltas.
  // This is intentionally NOT lossless: price deltas are rounded to 1 ppm and
  // volume ratios are quantized to 1/100 and capped by the encoder.
  const source = Array.isArray(history?.rows) ? history.rows : [];
  const {basePrice, ...rest} = history || {};
  return {
    ...rest,
    historyStartPrice: Number(history?.historyStartPrice ?? basePrice),
    originalCount: source.length,
    rows: source.map(row => [...row])
  };
}

function validateEncodedHistory(item, expectedInterval, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!item || typeof item !== "object" || !Number.isFinite(Number(item.timeStart)) ||
      Number(item.timeStart) <= 0 || Number(item.timeStart) % expectedInterval !== 0 ||
      Number(item.intervalSeconds) !== expectedInterval ||
      !Number.isFinite(Number(item.historyStartPrice ?? item.basePrice)) ||
      Number(item.historyStartPrice ?? item.basePrice) <= 0 ||
      !Number.isFinite(Number(item.baseVolumeMedian)) || Number(item.baseVolumeMedian) < 0 ||
      !Array.isArray(item.rows) || item.rows.length < 50) return {ok:false, reason:"INVALID_HEADER_OR_TOO_FEW_CANDLES"};

  let previousClose = Number(item.historyStartPrice ?? item.basePrice);
  let previousTime = Number(item.timeStart);
  for (let i = 0; i < item.rows.length; i++) {
    const row = item.rows[i];
    if (!Array.isArray(row) || row.length !== 6 || !row.every(Number.isFinite))
      return {ok:false, reason:"NON_NUMERIC_ROW", index:i};
    const dt = Number(row[0]);
    if (i === 0 ? dt !== 0 : dt !== expectedInterval)
      return {ok:false, reason:dt === 0 ? "DUPLICATE_OR_MISSING_CANDLE" : "CANDLE_GAP_OR_WRONG_INTERVAL", index:i};
    if (row.some(value => !Number.isInteger(value)))
      return {ok:false, reason:"NON_INTEGER_DELTA_ENCODING", index:i};
    if (Number(row[5]) < 0 || Number(row[5]) > 1000000)
      return {ok:false, reason:"VOLUME_RATIO_OUT_OF_RANGE", index:i};
    const open = previousClose * (1 + Number(row[1]) / 1000000);
    const high = previousClose * (1 + Number(row[2]) / 1000000);
    const low = previousClose * (1 + Number(row[3]) / 1000000);
    const close = previousClose * (1 + Number(row[4]) / 1000000);
    if (![open,high,low,close].every(Number.isFinite) || low <= 0 ||
        high < Math.max(open,close) || low > Math.min(open,close) || high < low || Number(row[5]) < 0)
      return {ok:false, reason:"INVALID_OHLCV", index:i};
    previousTime += dt;
    previousClose = close;
  }
  const latestCloseTime = previousTime + expectedInterval;
  const ageSeconds = nowSeconds - latestCloseTime;
  if (ageSeconds < -expectedInterval) return {ok:false, reason:"FUTURE_CANDLE"};
  if (ageSeconds > expectedInterval * 2) return {ok:false, reason:"STALE_HISTORY", ageSeconds};
  return {ok:true, expectedIntervalSeconds:expectedInterval, actualIntervalSeconds:expectedInterval,
    candleCount:item.rows.length, closedCandleCount:item.rows.length, gapCount:0, duplicateCount:0,
    invalidOhlcCount:0, latestOpenTime:previousTime, latestCloseTime, ageSeconds, source:"exchange_ohlcv"};
}

function buildPrompt(input) {
  const history = input.marketHistory || {};
  // All closed candles are preserved exactly; never aggregate away structural sequence.
  const h1 = compressHistory(history["1h"]);
  const m15 = compressHistory(history["15m"]);
  const m5 = compressHistory(history["5m"]);
  const payload = {
    exchange: input.exchange,
    symbol: input.symbol,
    marketType: input.marketType === "FUTURES" ? "FUTURES" : "SPOT",
    snapshotId: typeof input.snapshotId === "string" ? input.snapshotId : null,
    referencePrice: Number.isFinite(Number(input.referencePrice)) ? Number(input.referencePrice) : null,
    lastClosed5mClose: Number.isFinite(Number(input.lastClosed5mClose)) ? Number(input.lastClosed5mClose) : null,
    asOfUtc: typeof input.asOfUtc === 'string' ? input.asOfUtc : null,
    encoding: "COMPACT_QUANTIZED rows=[delta_time_seconds, open/high/low/close_delta_ppm_from_previous_close, volume_ratio_x100]; every row represents one original closed candle in chronological order; price deltas rounded to 1 ppm; volume ratio rounded to 0.01 and capped at 10000x; not lossless",
    encodingMetadata: {kind:"COMPACT_QUANTIZED_DELTA_OHLCV", priceDeltaScale:1000000, priceDeltaRounding:"nearest_integer_ppm", volumeRatioScale:100, volumeRatioRounding:"nearest_integer_ratio_0_01", volumeRatioMaximum:1000000, exactOriginalValuesPreserved:false},
    history: {
      "1h": h1,
      "15m": m15,
      "5m": m5
    }
  };
  return [
    "Act as an independent crypto market analyst. Analyze ONLY the supplied OHLCV market history. Do not receive or infer any technical-indicator engine decision; there is no technical opinion in this task. This request is tied to one immutable snapshotId and one declared marketType; do not mix instruments or market classes. altFINS, technical-engine features, order book, funding, open interest, liquidation, taker delta and news are NOT supplied to this model in this request; never claim to have used them or infer measured values from OHLCV.",
    "Reconstruct each timeframe sequentially from historyStartPrice. IMPORTANT: historyStartPrice is only the OPEN price of the FIRST candle in that timeframe history, used as a decoding seed; it is NOT the current price, NOT a reference price, and it is expected to differ between 1h/15m/5m because their history windows begin at different times. Never compare historyStartPrice values across timeframes or compare them directly with referencePrice. The explicit referencePrice is the authoritative LIVE market-price anchor; lastClosed5mClose is the latest completed 5m close. Check current-price consistency using referencePrice versus lastClosed5mClose only. Analyze 1h context, 15m structure and 5m execution. Consider trend, swings, displacement, volatility, volume, liquidity sweeps, range boundaries and alignment. Never invent or shift absolute prices. Do not state a separate numeric current price in summary/observations/risks; numeric structural levels belong only in overlays. If reconstructed LAST candle prices materially disagree with lastClosed5mClose/referencePrice, return WAIT and explain the mismatch in Persian.",
    "LIQUIDITY SEMANTICS: BSL/SSL alone identify BUY_SIDE_LIQUIDITY_POOL/SELL_SIDE_LIQUIDITY_POOL, not a sweep. A sweep requires candle evidence that price traded beyond the pool and then reclaimed/closed back across the level; include timeframe, candle time and price evidence. Do not call a sweep from the mere presence of a liquidity level. Keep BOTH_SWEEPS distinct from BOTH_POOLS.",
    "MARKET STRUCTURE DEFINITIONS: Determine each timeframe independently from CLOSED candles. BOS requires a candle close beyond a previously confirmed protected swing in the direction of the existing structure. CHOCH requires a close through the opposing protected swing against the prior structure. MSS requires a close-based shift supported by displacement; a wick-only liquidity sweep is not BOS/CHOCH/MSS. Do not call a new event from an unclosed candle. If an event is described as not confirmed, rejected, invalidated or ambiguous, use UNKNOWN rather than assigning a direction. Report structure as directional state (BULLISH/BEARISH/RANGE/TRANSITION) and structureEvent separately. Use NONE when no qualifying event is confirmed in the supplied window; do not force BOS or CHOCH. 1h is context, 15m is setup structure, 5m is execution structure; explicitly state when they conflict and never let a 5m countertrend move silently override 1h/15m context. ",
    "MANDATORY MULTI-TIMEFRAME COMPLETION: The supplied history contains separate 1h, 15m and 5m OHLCV series. You MUST independently populate all three timeframeAnalysis objects. Do not output UNKNOWN merely because there is no indicator feed: infer trend/structure/phase from sequential candle closes, swing highs/lows, higher-high/higher-low or lower-high/lower-low behavior, range boundaries and displacement. Estimate buyerStrength and sellerStrength only as OHLCV candle-pressure proxies from directional bodies and valid nonzero volume; they are NOT measured buyer/seller order flow, aggressor delta or taker volume. If volume is absent or unusable, set both buyerStrength and sellerStrength to JSON null; never fabricate a percentage or use the string UNKNOWN for these numeric fields. If reported as percentages, label them estimated OHLCV pressure and make the pair total 100. Use BUY_SIDE_LIQUIDITY_POOL/SELL_SIDE_LIQUIDITY_POOL when only a pool is identified; use a *_SWEEP value only when the sweep-and-reclaim event is evidenced; use NONE only when neither a pool nor a sweep is visible. Use UNKNOWN only for the specific field that genuinely cannot be assessed after inspecting that timeframe; never replace an entire timeframe with UNKNOWN because one field is uncertain. Add at least one concise Persian evidence note per timeframe. If a timeframe history is actually missing or too short, state that explicitly in dataQuality and keep only that timeframe unknown.",
    "MANDATORY LANGUAGE: Every human-readable field (summary, each observation, each risk, each evidence explanation, invalidation) MUST be written in natural Persian/Farsi using Persian script. English sentences are invalid. Only BUY/SELL/WAIT, field names, timeframe codes and enum values remain English. If you cannot write Persian, return WAIT with a short Persian explanation.",
    "Analyze only this model's supplied OHLCV data. Do not receive, infer, copy or agree with any technical-engine result or another AI model. Each provider must independently produce its own zones and trade plan.",
    "Choose BUY, SELL or WAIT from your own evidence. Never force a trade or invent prices. For BUY or SELL, you MUST provide exactly one Entry, one SL, and TP1, TP2, TP3, all as valid line overlays with numeric prices. BUY: SL < Entry < TP1 < TP2 < TP3. SELL: SL > Entry > TP1 > TP2 > TP3. If no valid plan exists, choose WAIT and omit all five execution lines. For a directional setup, identify at least one valid POI: OB OR FVG OR a directionally relevant swing/equal-level retest; do not require both OB and FVG and never fabricate a zone. Return JSON only with contractVersion=3 and analysisSections: timeframeAnalysis for exactly 1h, 15m and 5m (each has trend, structure, structureEvent, phase, buyerStrength, sellerStrength, liquidity and evidence; buyerStrength/sellerStrength may be null only when OHLCV volume is absent or unusable). structureEvent must be BOS_BULLISH/BOS_BEARISH/CHOCH_BULLISH/CHOCH_BEARISH/MSS_BULLISH/MSS_BEARISH/NONE/UNKNOWN; use NONE only after checking and finding no confirmed event, UNKNOWN only if the timeframe data is insufficient; evidence (1-12 structured items with timeframe,type,event,status,Persian explanation,candleTime as exact candle open-time Unix seconds,price as event candle close or sweep wick extreme,referenceLevel as the broken/swept swing or liquidity level; set the three numeric fields null only for non-event observations); invalidation (Persian condition); then bias, Persian summary, Persian observations (max 5), Persian risks (max 5), optional confidence (0-100), optional analyticalWeights (five integer percentages totaling exactly 100: trend, marketStructure, liquidity, entryConfirmation, riskReward), optional factorScores (five integer scores from 0 to 100 using the same keys), and overlays (max 10). Weights express how important each factor was to your decision; factorScores express the evidence quality you actually observed. If unavailable, omit confidence/weights/scores rather than inventing them; they are not required for a directional vote.",
    "CONTRACT COMPLETENESS: Always return all nine analysisSections keys. AVAILABLE requires at least one concise Persian finding. For NOT_AVAILABLE, NOT_APPLICABLE or INSUFFICIENT_DATA, findings may be an empty array; do not invent evidence merely to fill the schema. If a finding is supplied, explain the limitation in Persian. Distinguish unavailable external feeds (order book/funding/OI/news) from evidence that can be derived from OHLCV.",
    "MANDATORY COMPREHENSIVE ANALYSIS SECTIONS: analysisSections must contain exactly regime, structure, liquidity, poi, premiumDiscount, volumeMomentum, scenarios, execution, dataQuality. Each is {status: AVAILABLE|NOT_AVAILABLE|NOT_APPLICABLE|INSUFFICIENT_DATA, findings: [] or 1-3 concise Persian findings; AVAILABLE requires at least one}. regime: trend/range/accumulation/distribution and volatility regime. structure: 1h/15m/5m alignment, BOS/CHOCH/MSS/displacement and protected swings. liquidity: BSL/SSL, EQH/EQL, sweep and reclaim evidence. poi: OB/Breaker/FVG or swing retest, timeframe, boundaries and mitigation state. premiumDiscount: dealing range, equilibrium and location; if range cannot be objectively derived mark insufficient. volumeMomentum: volume expansion/contraction, candle impulse, momentum and volatility based only on OHLCV. scenarios: bullish and bearish alternatives, activation and invalidation conditions; never force direction. execution: location quality, trigger, stop placement logic, target logic and R multiple; WAIT if not executable. dataQuality: supplied data coverage, stale/missing inputs and explicit limitations. If order book, funding, open interest, delta, news or liquidation feed is not supplied, mark NOT_AVAILABLE and explicitly say it was not provided; never infer it from candles. Each finding must be Persian.",
    "Overlay schema: {type:line|zone,kind:Swing High|Swing Low|FVG|Bullish FVG|Bearish FVG|Bullish OB|Bearish OB|EQH|EQL|BOS+|BOS-|CRT-H|CRT-L|EQ|Entry|SL|TP1|TP2|TP3,price:number|null,low:number|null,high:number|null,timeframe:1h|15m|5m,direction:bullish|bearish|neutral,status:ACTIVE|MITIGATED|INVALIDATED|PENDING|UNSPECIFIED,timestamp:unix_seconds|null,evidence:string|null}. For line set price and null low/high; for zone set low/high and null price. Never omit mitigation state when known; do not claim ACTIVE unless candles show it remains unmitigated. Entry/SL/TP lines use timeframe 5m and direction matching BUY=bullish or SELL=bearish. Never put prose in enum fields. No markdown or chain-of-thought.",
    JSON.stringify(payload)
  ].join("\n");
}


async function callGemini(prompt, env) {
  if (!env.GEMINI_API_KEY) {
    throw new Error("GEMINI_API_KEY is not configured");
  }

  const model = env.GEMINI_MODEL || GEMINI_DEFAULT;
  const endpoint =
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;

  const headers = {"Content-Type":"application/json", "x-goog-api-key":env.GEMINI_API_KEY};
  const requestBody = {
    system_instruction: {
      parts: [{ text: "Independently analyze the supplied OHLCV history and provide your richest useful market analysis in the response format you support best. Prefer a detailed, well-organized JSON object when supported, but do not omit useful findings merely to satisfy a rigid schema; provider-native structured output or clear prose is acceptable. Cover market regime, multi-timeframe trend and structure, liquidity, POIs, premium/discount, volume/momentum, bullish and bearish scenarios, execution conditions, risks and data limitations whenever evidence is available. Clearly distinguish observed facts, interpretations and recommendations. Include timeframe labels and numeric prices with units where relevant. Never invent missing feeds, prices, indicators, or trade levels. Give BUY/SELL only when you can justify a complete coherent Entry/SL/TP plan; otherwise use WAIT/no-trade. All user-facing explanations should be Persian. Analyze independently; do not use other models opinions." }]
    },
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    generationConfig: {
      // Do not force a provider output format; preserve Gemini-native prose or JSON.
      temperature: 0.25,
      maxOutputTokens: 6000
    }
  };
  let response = await fetchProvider(endpoint, {method:"POST", headers, body:JSON.stringify(requestBody)});
  if ([400, 422].includes(response.status)) {
    const errorText = await response.clone().text();
    if (/responseJsonSchema|responseSchema|schema.*(unsupported|invalid)|unsupported.*schema/i.test(errorText)) {
      const fallbackBody = {...requestBody, generationConfig:{...requestBody.generationConfig}};
      delete fallbackBody.generationConfig.responseJsonSchema;
      response = await fetchProvider(endpoint, {method:"POST", headers, body:JSON.stringify(fallbackBody)});
    }
  }

  const body = await readJsonResponse(response, "Gemini");
  const candidate = body?.candidates?.[0];
  if (!candidate) throw new Error("Gemini returned no candidate");
  const wasTruncated = candidate.finishReason === "MAX_TOKENS";
  if (candidate.finishReason === "SAFETY") throw new Error("Gemini response was blocked by safety filtering");
  const raw = candidate?.content?.parts?.map(part => part.text || "").join("");
  const parsed = parseModelJson(raw, "Gemini", body.__rawProviderResponse);
  const safeParsed = wasTruncated ? downgradeTruncatedAnalysis(parsed, "Gemini") : parsed;
  const usage = body?.usageMetadata || {};
  return {
    ...safeParsed,
    providerModel: model,
    finishReason: String(candidate.finishReason || "unknown"),
    promptTokens: Number.isFinite(Number(usage.promptTokenCount)) ? Number(usage.promptTokenCount) : null,
    completionTokens: Number.isFinite(Number(usage.candidatesTokenCount)) ? Number(usage.candidatesTokenCount) : null,
    reasoningTokens: Number.isFinite(Number(usage.thoughtsTokenCount)) ? Number(usage.thoughtsTokenCount) : null
  };
}

async function callOpenRouter(prompt, env) {
  if (!env.OPENROUTER_API_KEY) {
    throw new Error("OPENROUTER_API_KEY is not configured");
  }

  const model = env.OPENROUTER_MODEL || OPENROUTER_DEFAULT;

  const openRouterUrl = "https://openrouter.ai/api/v1/chat/completions";
  const headers = {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${env.OPENROUTER_API_KEY}`,
    "X-OpenRouter-Metadata": "enabled",
    "X-OpenRouter-Experimental-Metadata": "enabled",
    "HTTP-Referer": "https://ai-crypto-analyst.app",
    "X-Title": "AI Crypto Analyst"
  };
  const payload = {
    model,
    messages: [
      { role: "system", content: "Independently analyze the supplied OHLCV history and provide your richest useful market analysis in the response format you support best. Prefer a detailed, well-organized JSON object when supported, but do not omit useful findings merely to satisfy a rigid schema; provider-native structured output or clear prose is acceptable. Cover market regime, multi-timeframe trend and structure, liquidity, POIs, premium/discount, volume/momentum, bullish and bearish scenarios, execution conditions, risks and data limitations whenever evidence is available. Clearly distinguish observed facts, interpretations and recommendations. Include timeframe labels and numeric prices with units where relevant. Never invent missing feeds, prices, indicators, or trade levels. Give BUY/SELL only when you can justify a complete coherent Entry/SL/TP plan; otherwise use WAIT/no-trade. All user-facing explanations should be Persian. Analyze independently; do not use other models opinions." },
      { role: "user", content: prompt }
    ],
    temperature: 0.1,
    reasoning: { effort: "none" },
    max_tokens: 6000,
    provider: { sort: "throughput", allow_fallbacks: true },
    stream: false
  };
  let response = await fetchProvider(openRouterUrl, {method:"POST", headers, body:JSON.stringify(payload)});
  // Some free endpoints do not implement JSON Schema or reasoning controls.
  // Retry once without those optional constraints; parse JSON if present, otherwise preserve plain text.
  if ([400, 404, 422].includes(response.status)) {
    const errorText = await response.clone().text();
    if (/response_format|json_schema|reasoning|unsupported parameter|not supported|no endpoints|no provider|no available provider|no endpoints found|no compatible/i.test(errorText)) {
      const fallbackPayload = {...payload};
      delete fallbackPayload.response_format;
      delete fallbackPayload.reasoning;
      // Allow a healthy endpoint even when it does not implement JSON Schema.
      // JSON parsing and the full V3 contract are still enforced locally.
      // Keep the exact eligible concrete model. Never fall back to a router alias
      // that could silently select an unverified or multimodal model.
      fallbackPayload.model = model;
      fallbackPayload.provider = {allow_fallbacks:false};
      response = await fetchProvider(openRouterUrl, {method:"POST", headers, body:JSON.stringify(fallbackPayload)});
    }
  }
  const body = await readJsonResponse(response, "OpenRouter");
  const choice = body?.choices?.[0];
  const message = choice?.message;
  if (!choice || !message) throw new Error("OpenRouter returned no completion choice");
  const usage = body?.usage || {};
  const actualModel = String(body?.model || model);
  const wasTruncated = choice.finish_reason === "length";
  if (choice.finish_reason === "content_filter") throw new Error(`OpenRouter completion blocked by content filtering (model=${actualModel})`);
  let raw = message?.content;
  if (Array.isArray(raw)) {
    raw = raw.map(part => typeof part === "string" ? part : (part?.text || "")).join("\n");
  }
  if ((raw === null || raw === undefined || raw === "") && message?.parsed && typeof message.parsed === "object") {
    raw = message.parsed;
  }
  if ((raw === null || raw === undefined || raw === "") && message?.refusal) {
    throw new Error(`OpenRouter refused the request: ${String(message.refusal).slice(0, 220)}`);
  }
  const parsed = parseModelJson(raw, "OpenRouter", body.__rawProviderResponse);
  const safeParsed = wasTruncated ? downgradeTruncatedAnalysis(parsed, "OpenRouter") : parsed;
  return {
    ...safeParsed,
    providerModel: actualModel,
    finishReason: String(choice.finish_reason || "unknown"),
    nativeFinishReason: choice.native_finish_reason == null ? null : String(choice.native_finish_reason),
    promptTokens: Number.isFinite(Number(usage.prompt_tokens)) ? Number(usage.prompt_tokens) : null,
    completionTokens: Number.isFinite(Number(usage.completion_tokens)) ? Number(usage.completion_tokens) : null,
    reasoningTokens: Number.isFinite(Number(usage.completion_tokens_details?.reasoning_tokens))
      ? Number(usage.completion_tokens_details.reasoning_tokens) : null
  };
}

async function callGroq(prompt, env) {
  if (!env.GROQ_API_KEY) throw new Error("GROQ_API_KEY is not configured");
  const model = env.GROQ_MODEL || GROQ_DEFAULT;
  const payload = {
    model,
    messages: [
      { role: "system", content: "Independently analyze the supplied OHLCV history and provide your richest useful market analysis in the response format you support best. Prefer a detailed, well-organized JSON object when supported, but do not omit useful findings merely to satisfy a rigid schema; provider-native structured output or clear prose is acceptable. Cover market regime, multi-timeframe trend and structure, liquidity, POIs, premium/discount, volume/momentum, bullish and bearish scenarios, execution conditions, risks and data limitations whenever evidence is available. Clearly distinguish observed facts, interpretations and recommendations. Include timeframe labels and numeric prices with units where relevant. Never invent missing feeds, prices, indicators, or trade levels. Give BUY/SELL only when you can justify a complete coherent Entry/SL/TP plan; otherwise use WAIT/no-trade. All user-facing explanations should be Persian. Analyze independently; do not use other models opinions." },
      { role: "user", content: prompt }
    ],
    temperature: 0.1,
    max_completion_tokens: 5000,
    stream: false
  };
  // Provider-native output is intentionally unconstrained; normalize locally.
  let response = await fetchProvider("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST", headers: {"Content-Type":"application/json","Authorization":`Bearer ${env.GROQ_API_KEY}`}, body: JSON.stringify(payload)
  });
  const body = await readJsonResponse(response, "Groq");
  const choice = body?.choices?.[0];
  const message = choice?.message;
  if (!choice || !message) throw new Error("Groq returned no completion choice");
  const wasTruncated = choice.finish_reason === "length";
  if (choice.finish_reason === "content_filter") throw new Error("Groq completion blocked by content filtering");
  const raw = message.content;
  const parsed = parseModelJson(raw, "Groq", body.__rawProviderResponse);
  const safeParsed = wasTruncated ? downgradeTruncatedAnalysis(parsed, "Groq") : parsed;
  const usage = body?.usage || {};
  return {
    ...safeParsed,
    providerModel: String(body?.model || model),
    finishReason: String(choice.finish_reason || "unknown"),
    promptTokens: Number.isFinite(Number(usage.prompt_tokens)) ? Number(usage.prompt_tokens) : null,
    completionTokens: Number.isFinite(Number(usage.completion_tokens)) ? Number(usage.completion_tokens) : null,
    reasoningTokens: null
  };
}


const HEALTH_PROBE_TIMEOUT_MS = 9000;
const HEALTH_PROBE_MAX_TOKENS = 8;
// Circuit state is fail-closed: never fall back to isolate-local memory.
const CIRCUIT_BASE_COOLDOWN_MS = 30000;
const CIRCUIT_MAX_COOLDOWN_MS = 300000;
const CIRCUIT_HALF_OPEN_LEASE_MS = 25000;

async function circuitRequest(env, operation, payload) {
  const namespace = env?.PROVIDER_CIRCUIT_BREAKER;
  if (!namespace || typeof namespace.idFromName !== 'function' || typeof namespace.get !== 'function') {
    throw new Error('CIRCUIT_STATE_UNAVAILABLE: PROVIDER_CIRCUIT_BREAKER binding is missing');
  }
  const key = String(payload?.key || '');
  if (!key) throw new Error('CIRCUIT_KEY_REQUIRED');
  const id = namespace.idFromName(key);
  const stub = namespace.get(id);
  if (!stub || typeof stub.fetch !== 'function') throw new Error('CIRCUIT_STATE_UNAVAILABLE: Durable Object stub is invalid');
  const response = await stub.fetch(`https://provider-circuit.internal/${operation}`, {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload)
  });
  if (!response.ok) throw new Error(`CIRCUIT_STORE_${response.status}`);
  let result;
  try { result = await response.json(); } catch { throw new Error('CIRCUIT_STORE_INVALID_RESPONSE'); }
  if (!result || typeof result !== 'object') throw new Error('CIRCUIT_STORE_INVALID_RESPONSE');
  return result;
}

async function acquireProviderCircuit(env, key) {
  return circuitRequest(env, 'acquire', {key, now:Date.now(), leaseMs:CIRCUIT_HALF_OPEN_LEASE_MS});
}

async function recordProviderCircuitSuccess(env, key) {
  return circuitRequest(env, 'success', {key});
}

async function recordProviderCircuitFailure(env, key, errorCode) {
  return circuitRequest(env, 'failure', {key, now:Date.now(), errorCode,
    baseCooldownMs:CIRCUIT_BASE_COOLDOWN_MS, maxCooldownMs:CIRCUIT_MAX_COOLDOWN_MS});
}

/** Durable, per-provider/model circuit state shared by every Worker isolate. */
export class ProviderCircuitBreaker {
  constructor(ctx, env) { this.ctx = ctx; this.env = env; }
  async fetch(request) {
    const operation = new URL(request.url).pathname.replace(/^\//, '');
    if (request.method !== 'POST' || !['status','acquire','success','failure'].includes(operation)) {
      return new Response('Not found', {status:404});
    }
    let body;
    try { body = await request.json(); } catch { return Response.json({error:'INVALID_JSON'}, {status:400}); }
    if (!body?.key || typeof body.key !== 'string') return Response.json({error:'CIRCUIT_KEY_REQUIRED'}, {status:400});
    const now = Number(body.now) || Date.now();
    const result = await this.ctx.storage.transaction(async txn => {
      const state = await txn.get('state');
      if (operation === 'status') return {ok:true,storage:'available',durableObject:'reachable'};
      if (operation === 'success') { await txn.delete('state'); return {ok:true,cleared:true}; }
      if (operation === 'acquire') {
        if (!state) return {allowed:true,halfOpen:false,failureCount:0};
        if (now < state.nextProbeAt) return {allowed:false,failureCount:state.failures,retryAt:state.nextProbeAt};
        if (state.probeLeaseUntil > now) return {allowed:false,failureCount:state.failures,retryAt:state.probeLeaseUntil,halfOpenInProgress:true};
        const updated = {...state,probeLeaseUntil:now + Math.max(1000,Math.min(60000,Number(body.leaseMs)||CIRCUIT_HALF_OPEN_LEASE_MS))};
        await txn.put('state',updated);
        return {allowed:true,halfOpen:true,failureCount:state.failures};
      }
      const failures = (state?.failures || 0) + 1;
      const base = Math.max(1000,Number(body.baseCooldownMs)||CIRCUIT_BASE_COOLDOWN_MS);
      const max = Math.max(base,Number(body.maxCooldownMs)||CIRCUIT_MAX_COOLDOWN_MS);
      const cooldownMs = Math.min(max,base * (2 ** Math.min(failures - 1,4)));
      const nextProbeAt = now + cooldownMs;
      await txn.put('state',{failures,nextProbeAt,lastError:String(body.errorCode||'UPSTREAM_ERROR'),probeLeaseUntil:0,updatedAt:now});
      return {failures,nextProbeAt,cooldownMs};
    });
    return Response.json(result, {headers:{'Cache-Control':'no-store'}});
  }
}

function classifyProbeFailure(status, message) {
  const text = String(message || '').toLowerCase();
  if (status === 401) return {status:'UNAVAILABLE', errorCode:'AUTHENTICATION_FAILED'};
  if (status === 403 || /forbidden|access denied|not allowed/.test(text)) return {status:'UNAVAILABLE', errorCode:'ACCESS_DENIED'};
  if (status === 404 || /model.*(not found|does not exist)|unknown model/.test(text)) return {status:'UNAVAILABLE', errorCode:'MODEL_UNAVAILABLE'};
  if (status === 429 || /rate.?limit|quota|too many requests/.test(text)) return {status:'DEGRADED', errorCode:'RATE_LIMITED', routable:false};
  if (status >= 500 || /timeout|abort|network|fetch failed/.test(text)) return {status:'DEGRADED', errorCode:status >= 500 ? 'UPSTREAM_ERROR' : 'TIMEOUT_OR_NETWORK', routable:false};
  return {status:'UNAVAILABLE', errorCode:'INVALID_RESPONSE_OR_REQUEST'};
}

async function probeProviderModel(provider, model, env) {
  const started = Date.now();
  const keyName = `${PROVIDER_KEYS[provider]}_API_KEY`;
  const apiKey = env[keyName];
  if (!apiKey) return {provider, model, status:'UNAVAILABLE', errorCode:'NOT_CONFIGURED', latencyMs:0};
  const prompt = 'Reply with exactly OK.';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HEALTH_PROBE_TIMEOUT_MS);
  try {
    let url, headers, body;
    if (provider === 'gemini') {
      url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
      headers = {'Content-Type':'application/json','x-goog-api-key':apiKey};
      body = {contents:[{role:'user',parts:[{text:prompt}]}],generationConfig:{temperature:0,maxOutputTokens:HEALTH_PROBE_MAX_TOKENS}};
    } else {
      url = provider === 'openrouter' ? 'https://openrouter.ai/api/v1/chat/completions' : 'https://api.groq.com/openai/v1/chat/completions';
      headers = {'Content-Type':'application/json','Authorization':`Bearer ${apiKey}`};
      if (provider === 'openrouter') Object.assign(headers, {'HTTP-Referer':'https://ai-crypto-analyst.app','X-Title':'AI Crypto Analyst'});
      body = {model,messages:[{role:'user',content:prompt}],temperature:0,max_tokens:HEALTH_PROBE_MAX_TOKENS,stream:false};
      if (provider === 'openrouter') body.provider = {allow_fallbacks:false};
    }
    const response = await fetch(url,{method:'POST',headers,body:JSON.stringify(body),signal:controller.signal});
    const raw = await response.text();
    let data = null; try { data = JSON.parse(raw); } catch {}
    const latencyMs = Date.now() - started;
    if (!response.ok) {
      const message = safeError(data?.error?.message || data?.error || raw || `HTTP ${response.status}`);
      return {provider,model,...classifyProbeFailure(response.status,message),latencyMs,httpStatus:response.status,error:message};
    }
    const answer = provider === 'gemini'
      ? data?.candidates?.[0]?.content?.parts?.map(x=>x.text || '').join('').trim()
      : data?.choices?.[0]?.message?.content;
    const textAnswer = Array.isArray(answer) ? answer.map(x=>typeof x==='string'?x:(x?.text||'')).join('').trim() : String(answer || '').trim();
    if (!textAnswer) return {provider,model,status:'UNAVAILABLE',errorCode:'EMPTY_RESPONSE',latencyMs,httpStatus:response.status};
    return {provider,model,status:latencyMs > 7000 ? 'DEGRADED' : 'READY',routable:true,errorCode:null,latencyMs,httpStatus:response.status,probe:'text_inference'};
  } catch (error) {
    const latencyMs = Date.now() - started;
    return {provider,model,...classifyProbeFailure(0,safeError(error)),latencyMs,error:safeError(error)};
  } finally { clearTimeout(timer); }
}

async function checkProviderHealth(input, env) {
  const selected = Array.isArray(input?.selectedProviders)
    ? [...new Set(input.selectedProviders.filter(x=>['gemini','openrouter','groq'].includes(x)))]
    : ['gemini','openrouter','groq'].filter(name=>Boolean(env[`${PROVIDER_KEYS[name]}_API_KEY`]));
  const liveCatalog = {};
  const catalogNeeded = selected.filter(provider => {
    const known = configuredModelList(provider,env);
    return [input?.modelSelection?.[provider],input?.fallbackSelection?.[provider]]
      .some(value=>value != null && value !== '' && !known.includes(String(value).trim()));
  });
  await Promise.all(catalogNeeded.map(async provider => { liveCatalog[provider] = await fetchLiveModelCatalog(provider,env); }));
  const results = await Promise.all(selected.map(async provider => {
    if (!env[`${PROVIDER_KEYS[provider]}_API_KEY`]) return {provider,status:'UNAVAILABLE',routable:false,errorCode:'NOT_CONFIGURED',attempts:[]};
    const circuitKey = `${provider}:${input?.modelSelection?.[provider] || configuredModelList(provider,env)[0] || 'default'}`;
    let circuit;
    try { circuit = await acquireProviderCircuit(env,circuitKey); }
    catch (error) { return {provider,status:'UNAVAILABLE',routable:false,errorCode:'CIRCUIT_STATE_UNAVAILABLE',error:safeError(error),attempts:[]}; }
    if (!circuit.allowed) {
      return {provider,status:'UNAVAILABLE',routable:false,errorCode:circuit.halfOpenInProgress?'CIRCUIT_HALF_OPEN_PROBE_IN_PROGRESS':'CIRCUIT_OPEN',retryAt:circuit.retryAt?new Date(circuit.retryAt).toISOString():null,failureCount:circuit.failureCount,attempts:[]};
    }
    let candidates;
    try { candidates = requestedModels(provider,input,env,liveCatalog).slice(0,2); }
    catch (error) { return {provider,status:'UNAVAILABLE',errorCode:'NO_ELIGIBLE_MODEL',error:safeError(error),attempts:[]}; }
    const attempts = [];
    for (const model of candidates) {
      const result = await probeProviderModel(provider,model,env);
      attempts.push(result);
      if (result.routable === true) {
        try { await recordProviderCircuitSuccess(env,circuitKey); }
        catch (error) { return {provider,status:'DEGRADED',routable:false,errorCode:'CIRCUIT_STATE_UNAVAILABLE',error:safeError(error),attempts}; }
        return {provider,status:result.status,routable:true,selectedModel:model,latencyMs:result.latencyMs,checkedAt:new Date().toISOString(),attempts};
      }
    }
    const best = attempts.find(x=>x.status==='DEGRADED') || attempts[attempts.length-1];
    let failureState;
    try { failureState = await recordProviderCircuitFailure(env,circuitKey,best?.errorCode || 'NO_ELIGIBLE_MODEL'); }
    catch (error) { return {provider,status:'DEGRADED',routable:false,errorCode:'CIRCUIT_STATE_UNAVAILABLE',error:safeError(error),attempts}; }
    const failures = failureState.failures;
    const nextProbeAt = failureState.nextProbeAt;
    return {provider,status:best?.status || 'UNAVAILABLE',routable:false,selectedModel:best?.model || null,latencyMs:best?.latencyMs ?? null,errorCode:best?.errorCode || 'NO_ELIGIBLE_MODEL',error:best?.error || null,checkedAt:new Date().toISOString(),retryAt:new Date(nextProbeAt).toISOString(),failureCount:failures,attempts};
  }));
  return {ok:results.some(x=>x.routable===true),checkedAt:new Date().toISOString(),policy:'text-only-trading-analysis',providers:Object.fromEntries(results.map(x=>[x.provider,x]))};
}

function historyPriceBounds(history) {
  let min = Infinity, max = 0;
  for (const tf of ["1h", "15m", "5m"]) {
    const item = history?.[tf];
    if (!item || !Array.isArray(item.rows)) continue;
    let previousClose = Number(item.historyStartPrice ?? item.basePrice);
    for (const row of item.rows) {
      const base = previousClose;
      const open = base * (1 + Number(row[1]) / 1000000);
      const high = base * (1 + Number(row[2]) / 1000000);
      const low = base * (1 + Number(row[3]) / 1000000);
      const close = base * (1 + Number(row[4]) / 1000000);
      if ([open, high, low, close].every(Number.isFinite) && low > 0 && high >= low) {
        min = Math.min(min, low);
        max = Math.max(max, high);
      }
      previousClose = close;
    }
  }
  return Number.isFinite(min) && max > 0 ? {min, max} : null;
}

function sanitizeNarrativePriceValues(text, floor, ceiling) {
  if (typeof text !== "string") return {text, mismatch:false};
  let mismatch = false;
  const normalizedDigits = value => value.replace(/[۰-۹٠-٩]/g, char => {
    const code = char.charCodeAt(0);
    return String(code >= 0x06f0 && code <= 0x06f9 ? code - 0x06f0 : code - 0x0660);
  });
  // Only treat a number as a quoted market price when nearby text labels it
  // as a price. This avoids mistaking years (2026), TFs, counts and percentages
  // for stale prices and incorrectly invalidating an otherwise valid V3.
  const priceContext = /(?:قیمت|نرخ|دلار|تتر|price|last\s*price|market\s*price|usdt|usd|btc)[^0-9۰-۹٠-٩\n]{0,28}$/i;
  const pattern = /[0-9۰-۹٠-٩]+(?:[.,٫٬،][0-9۰-۹٠-٩]+)*/g;
  const sanitized = text.replace(pattern, (token, offset, whole) => {
    let normalized = normalizedDigits(token).replace(/[٬،]/g, "").replace(/٫/g, ".");
    normalized = normalized.replace(/,(?=\d{3}(?:\D|$))/g, "").replace(/,/g, ".");
    const numeric = Number(normalized);
    if (!Number.isFinite(numeric) || numeric <= 0) return token;
    const prefix = whole.slice(Math.max(0, offset - 48), offset);
    const suffix = whole.slice(offset + token.length, offset + token.length + 24);
    if (!priceContext.test(prefix) && !/^\s*(?:دلار|تتر|USD|USDT|BTC)/i.test(suffix)) return token;
    if (numeric < floor || numeric > ceiling) {
      mismatch = true;
      return "قیمت خارج از داده مرجع";
    }
    return token;
  });
  return {text:sanitized, mismatch};
}

function decodeHistoryCandles(history) {
  if (!history || !Array.isArray(history.rows)) return [];
  let previousClose = Number(history.historyStartPrice ?? history.basePrice);
  let time = Number(history.timeStart);
  const out = [];
  for (const row of history.rows) {
    time += Number(row[0] || 0);
    const candle = {
      time,
      open: previousClose * (1 + Number(row[1]) / 1000000),
      high: previousClose * (1 + Number(row[2]) / 1000000),
      low: previousClose * (1 + Number(row[3]) / 1000000),
      close: previousClose * (1 + Number(row[4]) / 1000000),
      volume: Number(row[5])
    };
    out.push(candle);
    previousClose = candle.close;
  }
  return out;
}

function nearPrice(a, b, tolerance = 0.002) {
  return Number.isFinite(a) && Number.isFinite(b) && b > 0 && Math.abs(a - b) / b <= tolerance;
}

function canonicalMarketEvent(raw) {
  const key = String(raw || "").toUpperCase().replace(/[\s-]+/g, "_");
  if (/BUY_SIDE_SWEEP|BSL_SWEEP/.test(key)) return "BUY_SIDE_SWEEP";
  if (/SELL_SIDE_SWEEP|SSL_SWEEP/.test(key)) return "SELL_SIDE_SWEEP";
  const type = key.match(/BOS|CHOCH|MSS/)?.[0];
  const direction = /BULLISH|BULL|UP/.test(key) ? "BULLISH" : /BEARISH|BEAR|DOWN/.test(key) ? "BEARISH" : null;
  return type && direction ? `${type}_${direction}` : key;
}

function validateEvidenceClaim(item, history) {
  const candles = decodeHistoryCandles(history?.[item.timeframe]);
  if (!candles.length || !Number.isFinite(item.candleTime) || !Number.isFinite(item.price) || !Number.isFinite(item.referenceLevel))
    return {status:"UNVERIFIED", reason:"شاهد فاقد زمان دقیق کندل، قیمت رویداد یا سطح مرجع است."};
  const index = candles.findIndex(candle => candle.time === item.candleTime);
  if (index < 2) return {status:"INVALID", reason:"زمان اعلام‌شده با کندل موجود تطبیق ندارد یا تاریخچه کافی نیست."};
  const candle = candles[index], previous = candles[index - 1];
  const event = canonicalMarketEvent(item.event);
  const direction = event.endsWith("BULLISH") ? "BULLISH" : event.endsWith("BEARISH") ? "BEARISH" : null;
  if (event === "BUY_SIDE_SWEEP" || event === "SELL_SIDE_SWEEP") {
    const buySide = event === "BUY_SIDE_SWEEP";
    const extreme = buySide ? candle.high : candle.low;
    const reclaimed = buySide ? candle.close < item.referenceLevel : candle.close > item.referenceLevel;
    const swept = buySide ? candle.high > item.referenceLevel : candle.low < item.referenceLevel;
    const poolSeen = candles.slice(Math.max(0, index - 80), index).some(x => nearPrice(buySide ? x.high : x.low, item.referenceLevel, 0.002));
    if (!nearPrice(item.price, extreme) || !swept || !reclaimed || !poolSeen)
      return {status:"INVALID", reason:"کندل اعلام‌شده شکست سطح و بازپس‌گیری معتبر نقدینگی را تأیید نمی‌کند."};
    return {status:"VALIDATED", candleTime:item.candleTime, event};
  }
  const eventType = event.match(/^(BOS|CHOCH|MSS)_/)?.[1];
  if (!eventType || !direction) return {status:"UNVERIFIED", reason:"نوع رویداد ساختاری قابل تطبیق با کندل‌ها نیست."};
  if (!nearPrice(item.price, candle.close))
    return {status:"INVALID", reason:"قیمت شاهد با بسته‌شدن کندل اعلام‌شده تطبیق ندارد."};
  const bullish = direction === "BULLISH";
  const crossed = bullish ? previous.close <= item.referenceLevel && candle.close > item.referenceLevel
    : previous.close >= item.referenceLevel && candle.close < item.referenceLevel;
  if (!crossed) return {status:"INVALID", reason:"بسته‌شدن کندل از سطح مرجع عبور نکرده است."};
  const pivotExists = candles.slice(2, index - 1).some((candidate, offset) => {
    const pivotIndex = offset + 2;
    if (pivotIndex + 2 > index - 1) return false;
    const neighbors = candles.slice(pivotIndex - 2, pivotIndex + 3).filter((_, j) => j !== 2);
    const pivot = bullish ? candidate.high : candidate.low;
    const isPivot = bullish ? neighbors.every(x => pivot >= x.high) : neighbors.every(x => pivot <= x.low);
    return isPivot && nearPrice(pivot, item.referenceLevel, 0.002);
  });
  if (!pivotExists) return {status:"INVALID", reason:"سطح مرجع در تاریخچه به‌عنوان Swing تأییدشده پیدا نشد."};
  if (eventType === "CHOCH") {
    const earlier = candles[Math.max(0, index - 8)].close;
    const before = candles[index - 2].close;
    if (bullish ? earlier <= before : earlier >= before)
      return {status:"INVALID", reason:"جهت ساختار قبلی برای CHOCH با جهت اعلام‌شده سازگار نیست."};
  }
  if (eventType === "MSS") {
    const bodies = candles.slice(Math.max(0, index - 21), index).map(x => Math.abs(x.close - x.open)).sort((a,b)=>a-b);
    const median = bodies.length ? bodies[Math.floor(bodies.length / 2)] : 0;
    const body = Math.abs(candle.close - candle.open);
    if ((bullish && candle.close <= candle.open) || (!bullish && candle.close >= candle.open) || body < Math.max(median * 1.25, candle.close * 0.0001))
      return {status:"INVALID", reason:"کندل MSS فاقد جابه‌جایی جهت‌دار و بدنه کافی است."};
  }
  return {status:"VALIDATED", candleTime:item.candleTime, event};
}

function validateSwingOverlay(item, history) {
  const candles = decodeHistoryCandles(history?.[item.timeframe]);
  if (!candles.length || !Number.isFinite(item.timestamp) || !Number.isFinite(item.price)) return {ok:false,reason:"زمان و قیمت Swing مشخص نیست."};
  const index = candles.findIndex(candle => candle.time === item.timestamp);
  if (index < 2 || index + 2 >= candles.length) return {ok:false,reason:"کندل Swing برای تأیید پیوت کافی نیست."};
  const candle = candles[index];
  const isLow = item.kind === "Swing Low" || item.kind === "EQL";
  const pivotPrice = isLow ? candle.low : candle.high;
  const neighbors = candles.slice(index - 2,index + 3).filter((_,i)=>i!==2);
  const pivot = isLow ? neighbors.every(x=>pivotPrice<=x.low) : neighbors.every(x=>pivotPrice>=x.high);
  if (!pivot || !nearPrice(item.price,pivotPrice)) return {ok:false,reason:"قیمت اعلام‌شده Swing با پیوت واقعی تطبیق ندارد."};
  if (item.kind === "EQL" || item.kind === "EQH") {
    const sameSide = candles.slice(Math.max(0,index-60),index).filter(x=>nearPrice(isLow?x.low:x.high,item.price,0.0015));
    if (!sameSide.length) return {ok:false,reason:"سطح برابر EQH/EQL با پیوت دوم تأیید نشد."};
  }
  const invalidated = candles.slice(index+1).some(x=>isLow?x.close<item.price:x.close>item.price);
  const status = ["MITIGATED", "INVALIDATED", "PENDING"].includes(item.status) ? item.status : invalidated ? "INVALIDATED" : "ACTIVE";
  return {ok:true,item:{...item,status,validation:"CANDLE_BACKED",provenance:"provider+candles"},eligible:status === "ACTIVE"};
}

function validatePoiOverlay(item, history) {
  const candles = decodeHistoryCandles(history?.[item.timeframe]);
  if (!candles.length || !Number.isFinite(item.timestamp)) return {ok:false, reason:"زمان ایجاد ناحیه ثبت نشده است."};
  const index = candles.findIndex(candle => candle.time === item.timestamp);
  if (index < 0) return {ok:false, reason:"زمان ایجاد ناحیه با کندل‌های ارسالی تطبیق ندارد."};
  const candle = candles[index];
  let matches = false;
  if (item.kind === "Bullish OB") {
    const impulse = candles.slice(index + 1, index + 4).some(next => next.close > candle.high && next.close > next.open);
    matches = candle.close < candle.open && nearPrice(item.low, candle.low) && nearPrice(item.high, candle.open) && impulse;
  } else if (item.kind === "Bearish OB") {
    const impulse = candles.slice(index + 1, index + 4).some(next => next.close < candle.low && next.close < next.open);
    matches = candle.close > candle.open && nearPrice(item.low, candle.open) && nearPrice(item.high, candle.high) && impulse;
  } else if (["FVG", "Bullish FVG", "Bearish FVG"].includes(item.kind) && index >= 2) {
    const first = candles[index - 2];
    const bullish = item.direction === "bullish";
    matches = bullish
      ? first.high < candle.low && nearPrice(item.low, first.high) && nearPrice(item.high, candle.low)
      : first.low > candle.high && nearPrice(item.low, candle.high) && nearPrice(item.high, first.low);
  }
  if (!matches) return {ok:false, reason:"مرزهای ناحیه با الگوی واقعی OB/FVG در کندل‌های همان تایم‌فریم تطبیق ندارند."};
  const laterTouched = candles.slice(index + 1).some(next => next.low <= item.high && next.high >= item.low);
  let status = item.status;
  if (["INVALIDATED", "MITIGATED", "PENDING"].includes(status)) {
    // Preserve explicit provider status; candle evidence may only downgrade ACTIVE.
  } else {
    status = laterTouched ? "MITIGATED" : "ACTIVE";
  }
  if (status === "ACTIVE" && laterTouched) status = "MITIGATED";
  return {ok:true, item:{...item,status,validation:"CANDLE_BACKED",provenance:"provider+candles"}, eligible:status === "ACTIVE"};
}

function validateProviderEvidence(provider, history) {
  const findings = [];
  const timeframeStatus = Object.fromEntries(["1h", "15m", "5m"].map(tf => [tf, "VALIDATED"]));
  const timeframeFactorStatus = Object.fromEntries(["1h", "15m", "5m"].map(tf => [tf, {marketStructure:"VALIDATED", liquidity:"VALIDATED", otherEvidence:"NOT_EVALUATED"}]));
  const factorStatus = {marketStructure:"VALIDATED", liquidity:"VALIDATED", otherEvidence:"NOT_EVALUATED"};
  const checked = new Set();
  const record = (claim, event, fallbackReason, factor) => {
    const key = `${claim?.timeframe || ""}:${event}`;
    if (checked.has(key)) return;
    checked.add(key);
    const result = claim ? validateEvidenceClaim(claim, history) : {status:"UNVERIFIED",reason:fallbackReason};
    const timeframe = claim?.timeframe || "";
    findings.push({timeframe,event,...result});
    if (timeframeStatus[timeframe]) {
      if (result.status === "INVALID") timeframeStatus[timeframe] = "INVALID";
      else if (result.status !== "VALIDATED" && timeframeStatus[timeframe] !== "INVALID") timeframeStatus[timeframe] = "UNVERIFIED";
    }
    if (factor && factorStatus[factor]) {
      if (result.status === "INVALID") factorStatus[factor] = "INVALID";
      else if (result.status !== "VALIDATED" && factorStatus[factor] !== "INVALID") factorStatus[factor] = "UNVERIFIED";
      if (timeframeFactorStatus[timeframe]) {
        if (result.status === "INVALID") timeframeFactorStatus[timeframe][factor] = "INVALID";
        else if (result.status !== "VALIDATED" && timeframeFactorStatus[timeframe][factor] !== "INVALID") timeframeFactorStatus[timeframe][factor] = "UNVERIFIED";
      }
    }
  };
  for (const timeframe of ["1h", "15m", "5m"]) {
    const item = provider.timeframeAnalysis?.[timeframe];
    if (!item || item.provided === false) continue;
    const structureEvent = item.structureEvent;
    if (structureEvent && structureEvent !== "NONE" && structureEvent !== "UNKNOWN") {
      const claim = (provider.evidence || []).find(e => e.timeframe === timeframe && e.status === "CONFIRMED" && canonicalMarketEvent(e.event) === structureEvent);
      record(claim, structureEvent, "برای رویداد ساختاری اعلام‌شده، شاهد دقیق کندلی ارائه نشده است.", "marketStructure");
    }
    if (["BUY_SIDE_SWEEP", "SELL_SIDE_SWEEP"].includes(item.liquidity)) {
      const claim = (provider.evidence || []).find(e => e.timeframe === timeframe && e.status === "CONFIRMED" && canonicalMarketEvent(e.event) === item.liquidity);
      record(claim, item.liquidity, "برای Sweep اعلام‌شده، شاهد دقیق شکست و بازپس‌گیری سطح ارائه نشده است.", "liquidity");
    }
  }
  for (const claim of provider.evidence || []) {
    if (claim.status !== "CONFIRMED") continue;
    const event = canonicalMarketEvent(claim.event);
    if (/^(?:BOS|CHOCH|MSS)_(?:BULLISH|BEARISH)$/.test(event)) {
      const declared = provider.timeframeAnalysis?.[claim.timeframe]?.structureEvent;
      if (declared !== event) {
        const key = `${claim.timeframe}:${event}`;
        if (!checked.has(key)) {
          checked.add(key);
          findings.push({timeframe:claim.timeframe,event,status:"INVALID",reason:"رویداد تأییدشده با رویداد اعلام‌شده برای همان تایم‌فریم تعارض دارد."});
          timeframeStatus[claim.timeframe] = "INVALID";
          factorStatus.marketStructure = "INVALID";
          if (timeframeFactorStatus[claim.timeframe]) timeframeFactorStatus[claim.timeframe].marketStructure = "INVALID";
        }
      } else record(claim,event,"شاهد رویداد تأییدشده قابل اعتبارسنجی نیست.","marketStructure");
    } else if (["BUY_SIDE_SWEEP","SELL_SIDE_SWEEP"].includes(event)) {
      const declared = provider.timeframeAnalysis?.[claim.timeframe]?.liquidity;
      if (declared !== event) {
        const key = `${claim.timeframe}:${event}`;
        if (!checked.has(key)) {
          checked.add(key);
          findings.push({timeframe:claim.timeframe,event,status:"INVALID",reason:"ادعای Sweep با وضعیت نقدینگی همان تایم‌فریم تعارض دارد."});
          timeframeStatus[claim.timeframe] = "INVALID";
          factorStatus.liquidity = "INVALID";
          if (timeframeFactorStatus[claim.timeframe]) timeframeFactorStatus[claim.timeframe].liquidity = "INVALID";
        }
      } else record(claim,event,"شاهد Sweep تأییدشده قابل اعتبارسنجی نیست.","liquidity");
    } else {
      // Do not silently trust provider-labelled CONFIRMED events outside the
      // candle-backed structural/sweep validators. Unsupported event classes
      // remain visible, but the provider cannot claim fully validated evidence.
      record(claim,event,"این نوع شاهد تأییدشده هنوز اعتبارسنجی کندلی مستقل ندارد.","otherEvidence");
    }
  }
  const statuses = Object.values(timeframeStatus);
  const status = statuses.includes("INVALID") ? "INVALID" : statuses.includes("UNVERIFIED") ? "UNVERIFIED" : "VALIDATED";
  return {status, timeframeStatus, timeframeFactorStatus, factorStatus, findings};
}

function atrFromCandles(candles, period = 14) {
  if (!Array.isArray(candles) || candles.length < 2) return null;
  const ranges = [];
  for (let i = 1; i < candles.length; i++) {
    const current = candles[i], previousClose = candles[i - 1].close;
    ranges.push(Math.max(current.high - current.low, Math.abs(current.high - previousClose), Math.abs(current.low - previousClose)));
  }
  const sample = ranges.slice(-period);
  if (!sample.length) return null;
  const value = sample.reduce((sum, x) => sum + x, 0) / sample.length;
  return Number.isFinite(value) && value > 0 ? value : null;
}

function validateExecutionPlanGeometry(bias, levels, verifiedPoi, history, referencePrice) {
  if (!['BUY', 'SELL'].includes(bias)) return {valid:true,status:'NOT_APPLICABLE',reasons:[]};
  const reasons = [];
  const anchor = Number(referencePrice);
  if (!Number.isFinite(anchor) || anchor <= 0) reasons.push('قیمت مرجع زنده برای اعتبارسنجی سطوح ورود در دسترس نیست.');
  const candles = decodeHistoryCandles(history?.['5m']);
  const atr = atrFromCandles(candles, 14);
  if (!atr) reasons.push('برای اعتبارسنجی فاصله ورود و حدضرر، ATR معتبر تایم‌فریم 5M موجود نیست.');
  const entry = Number(levels.Entry), stop = Number(levels.SL);
  const targets = ['TP1','TP2','TP3'].map(kind => Number(levels[kind]));
  if (![entry,stop,...targets].every(value => Number.isFinite(value) && value > 0)) reasons.push('یک یا چند سطح معاملاتی قیمت عددی معتبر ندارد.');
  if (reasons.length) return {valid:false,status:'INVALID',reasons,atr:atr || null,referencePrice:Number.isFinite(anchor)&&anchor>0?anchor:null};

  const side = bias === 'BUY' ? 'bullish' : 'bearish';
  const entryDistanceLimit = Math.max(atr * 1.5, anchor * 0.015);
  const entryDistance = Math.abs(entry - anchor);
  if (entryDistance > entryDistanceLimit) reasons.push('قیمت Entry بیش از حد از قیمت مرجع زنده فاصله دارد و احتمالاً سطح قدیمی یا اشتباه است.');
  // A buy entry materially above the live anchor (or sell entry materially below it)
  // is a stale/chasing level, not a currently executable 5m setup.
  if (bias === 'BUY' && entry > anchor + atr * 0.75) reasons.push('Entry خرید بیش از حد بالاتر از قیمت مرجع قرار گرفته است.');
  if (bias === 'SELL' && entry < anchor - atr * 0.75) reasons.push('Entry فروش بیش از حد پایین‌تر از قیمت مرجع قرار گرفته است.');

  const risk = Math.abs(entry - stop);
  if (risk < atr * 0.15) reasons.push('فاصله حدضرر نسبت به ATR بیش از حد کوچک و مستعد نویز است.');
  if (risk > atr * 4) reasons.push('فاصله حدضرر از Entry نسبت به نوسان 5M بیش از حد بزرگ است.');
  const targetAtrLimits = [5,8,12];
  targets.forEach((target,index) => {
    if (Math.abs(target - entry) > atr * targetAtrLimits[index]) {
      reasons.push(`فاصله TP${index+1} از Entry با دامنه نوسان مجاز 5M سازگار نیست.`);
    }
  });

  // The execution must be anchored to a candle-validated, active POI. Entry
  // should be near that POI and SL must sit beyond its invalidation boundary.
  const matchingPoi = (verifiedPoi || []).filter(item => item.direction === side && item.status === 'ACTIVE');
  const anchoredPoi = matchingPoi.some(item => {
    const distance = item.type === 'zone'
      ? Math.max(0, item.low - entry, entry - item.high)
      : Math.abs(item.price - entry);
    if (distance > atr * 1.5) return false;
    const buffer = atr * 0.05;
    if (bias === 'BUY') return item.type === 'zone' ? stop < item.low - buffer : stop < item.price - buffer;
    return item.type === 'zone' ? stop > item.high + buffer : stop > item.price + buffer;
  });
  if (!anchoredPoi) reasons.push('Entry و SL با یک POI فعال و تأییدشده از روی کندل‌ها هم‌مکان نیستند؛ حدضرر باید پشت مرز ابطال POI قرار گیرد.');

  return {
    valid:reasons.length===0,
    status:reasons.length===0?'VALIDATED':'INVALID',
    reasons,
    atr,
    referencePrice:anchor,
    entryDistance,
    entryDistanceLimit,
    riskDistance:risk,
    poiAnchored:anchoredPoi
  };
}

function validateProviderOverlays(provider, history, referencePrice = null) {
  if (provider?.status !== "ok") return provider;
  const bounds = historyPriceBounds(history);
  if (!bounds) return {...provider, overlays: []};
  const historicalFloor = bounds.min * 0.95, historicalCeiling = bounds.max * 1.05;
  const anchor = Number.isFinite(Number(referencePrice)) && Number(referencePrice) > 0 ? Number(referencePrice) : null;
  const withinHistorical = item => item.type === "line"
    ? item.price >= historicalFloor && item.price <= historicalCeiling
    : item.low >= historicalFloor && item.high <= historicalCeiling;
  const withinVolatilityEnvelope = item => {
    if (!anchor) return true;
    const candles = decodeHistoryCandles(history?.[item.timeframe]);
    const atr = atrFromCandles(candles, 14);
    if (!atr) return false;
    const distance = item.type === "line" ? Math.abs(item.price - anchor)
      : Math.max(Math.abs(item.low - anchor), Math.abs(item.high - anchor));
    const kind = item.kind;
    const atrMultiple = kind === "TP3" ? 12 : kind === "TP2" ? 8 : kind === "TP1" ? 5 :
      kind === "SL" ? 4.5 : kind === "Entry" ? 3 : item.type === "zone" ? 5 : 4;
    const percentFloor = kind === "TP3" ? 0.12 : kind === "TP2" ? 0.08 : kind === "TP1" ? 0.05 :
      kind === "SL" ? 0.045 : kind === "Entry" ? 0.03 : item.type === "zone" ? 0.06 : 0.04;
    return distance <= Math.max(anchor * percentFloor, atr * atrMultiple);
  };
  // Human-readable model prose must not smuggle in a second, stale market price.
  // Only numbers inside the submitted historical envelope are retained.
  let narrativePriceMismatch = false;
  const narrativeFloor = anchor ? Math.max(historicalFloor, anchor * 0.975) : historicalFloor;
  const narrativeCeiling = anchor ? Math.min(historicalCeiling, anchor * 1.025) : historicalCeiling;
  const sanitizeText = value => {
    // Narratives may describe market context, but must not introduce a second,
    // contradictory live price. Exact structural levels belong in overlays.
    const result = sanitizeNarrativePriceValues(value, narrativeFloor, narrativeCeiling);
    narrativePriceMismatch ||= result.mismatch;
    return result.text;
  };
  const safeProvider = {
    ...provider,
    summary: sanitizeText(provider.summary || ""),
    observations: (provider.observations || []).map(sanitizeText),
    risks: (provider.risks || []).map(sanitizeText),
    invalidation: sanitizeText(provider.invalidation || ""),
    evidence: (provider.evidence || []).map(item => ({...item, explanation:sanitizeText(item.explanation || "")})),
    timeframeAnalysis: Object.fromEntries(Object.entries(provider.timeframeAnalysis || {}).map(([tf,item]) => [tf,{...item,evidence:(item.evidence || []).map(sanitizeText)}]))
  };
  const priceFilteredOverlays = (provider.overlays || []).filter(item => withinHistorical(item) && withinVolatilityEnvelope(item));
  const rejectedItems = (provider.overlays || []).filter(item => !priceFilteredOverlays.includes(item));
  const overlays = [];
  const verifiedPoi = [];
  for (const item of priceFilteredOverlays) {
    const isZonePoi = item.type === "zone" && ["Bullish OB", "Bearish OB", "FVG", "Bullish FVG", "Bearish FVG"].includes(item.kind);
    const isSwingPoi = item.type === "line" && ["Swing High", "Swing Low", "EQH", "EQL"].includes(item.kind);
    if (isZonePoi || isSwingPoi) {
      const check = isZonePoi ? validatePoiOverlay(item, history) : validateSwingOverlay(item, history);
      if (!check.ok) {
        overlays.push({...item,validation:"UNVERIFIED",validationReason:check.reason,provenance:"provider_unverified"});
        continue;
      }
      overlays.push(check.item);
      if (check.eligible) verifiedPoi.push(check.item);
    } else overlays.push(item);
  }
  const rejected = rejectedItems.length;
  const evidenceValidation = validateProviderEvidence(safeProvider, history);
  const directional = provider.bias === "BUY" || provider.bias === "SELL";
  // Evidence validity is independent from POI / executable-plan completeness.
  const evidenceStatus = evidenceValidation.status === "INVALID" ? "INVALID" : evidenceValidation.status !== "VALIDATED" ? "UNVERIFIED" : "VALIDATED";
  const executionKinds = ["Entry", "SL", "TP1", "TP2", "TP3"];
  const executionRejected = rejectedItems.some(item => executionKinds.includes(item.kind));
  const side = provider.bias === "BUY" ? "bullish" : provider.bias === "SELL" ? "bearish" : "neutral";
  const hasValidOb = verifiedPoi.some(item => item.type === "zone" && item.kind === (provider.bias === "BUY" ? "Bullish OB" : "Bearish OB") && item.direction === side);
  const hasValidFvg = verifiedPoi.some(item => item.type === "zone" && ["FVG", provider.bias === "BUY" ? "Bullish FVG" : "Bearish FVG"].includes(item.kind) && item.direction === side);
  const hasValidRetest = verifiedPoi.some(item => item.type === "line" && item.direction === side &&
    (provider.bias === "BUY" ? ["Swing Low", "EQL"].includes(item.kind) : ["Swing High", "EQH"].includes(item.kind)));
  const hasValidPoi = hasValidOb || hasValidFvg || hasValidRetest;
  const marketBias = provider.bias;
  let finalBias = provider.bias;
  let finalConfidence = provider.confidence;
  let finalOverlays = narrativePriceMismatch ? overlays.filter(item => !executionKinds.includes(item.kind)) : overlays;
  const levels = Object.fromEntries(executionKinds.map(kind => [kind, overlays.find(item => item.kind === kind)?.price]));
  const completePlan = executionKinds.every(kind => Number.isFinite(levels[kind]));
  const executionItems = overlays.filter(item => executionKinds.includes(item.kind));
  const expectedDirection = provider.bias === "BUY" ? "bullish" : provider.bias === "SELL" ? "bearish" : "neutral";
  const executionMetadataValid = executionItems.length === 5 && executionItems.every(item => item.timeframe === "5m" && item.direction === expectedDirection);
  // A model-level directional call must be coherent with its own execution
  // timeframe. If both 1H and 15M oppose the trade, require a candle-validated
  // reversal event on 1H or 15M; a naked 5M counter-move is not enough.
  const timeframeData = provider.timeframeAnalysis || {};
  const expectedTrend = provider.bias === "BUY" ? "BULLISH" : "BEARISH";
  const oppositeTrend = provider.bias === "BUY" ? "BEARISH" : "BULLISH";
  const shiftPrefix = provider.bias === "BUY" ? /^(?:BOS|CHOCH|MSS)_BULLISH$/ : /^(?:BOS|CHOCH|MSS)_BEARISH$/;
  const validatedShift = (tf) => {
    const event = timeframeData[tf]?.structureEvent;
    return typeof event === "string" && shiftPrefix.test(event) &&
      evidenceValidation.findings.some(item => item.timeframe === tf && item.event === event && item.status === "VALIDATED");
  };
  const fiveMinuteAligned = timeframeData["5m"]?.trend === expectedTrend || validatedShift("5m");
  const bothHigherTimeframesOppose = timeframeData["1h"]?.trend === oppositeTrend && timeframeData["15m"]?.trend === oppositeTrend;
  const higherTimeframeReversalConfirmed = validatedShift("1h") || validatedShift("15m");
  const timeframeDirectionValid = !directional || (fiveMinuteAligned && (!bothHigherTimeframesOppose || higherTimeframeReversalConfirmed));
  const coherentPlan = provider.bias === "BUY"
    ? levels.SL < levels.Entry && levels.TP1 > levels.Entry && levels.TP2 > levels.TP1 && levels.TP3 > levels.TP2
    : provider.bias === "SELL"
      ? levels.SL > levels.Entry && levels.TP1 < levels.Entry && levels.TP2 < levels.TP1 && levels.TP3 < levels.TP2
      : true;
  const risk = completePlan ? Math.abs(levels.Entry - levels.SL) : NaN;
  const rewardRatios = ["TP1", "TP2", "TP3"].map(kind => completePlan && risk > 0 ? Math.abs(levels[kind] - levels.Entry) / risk : NaN);
  const riskRewardValid = Number.isFinite(risk) && risk > 0 && rewardRatios[0] >= 1 && rewardRatios[1] >= 1.5 && rewardRatios[2] >= 2;
  const executionPriceValidation = !directional
    ? {valid:true,status:'NOT_APPLICABLE',reasons:[]}
    : completePlan
      ? validateExecutionPlanGeometry(provider.bias, levels, verifiedPoi, history, referencePrice)
      : {valid:false,status:'INCOMPLETE',reasons:['برنامه معاملاتی برای اعتبارسنجی قیمت کامل نیست.']};
  // Re-check OB/FVG after the historical-price envelope filter. A plan whose
  // zones were rejected must not remain a BUY/SELL signal with an incomplete map.
  const executionEvidenceValid = evidenceValidation.timeframeFactorStatus?.["5m"]?.marketStructure === "VALIDATED";
  const invalidPlan = narrativePriceMismatch || ((provider.bias === "BUY" || provider.bias === "SELL") &&
    (executionRejected || !completePlan || !coherentPlan || !executionMetadataValid || !riskRewardValid || !executionPriceValidation.valid || !hasValidPoi || !executionEvidenceValid || !timeframeDirectionValid));
  if (invalidPlan) {
    // Executable bias is WAIT, while marketBias retains the model's independent
    // directional assessment for the separate AI market-consensus layer.
    finalBias = "WAIT";
    finalConfidence = 0;
    finalOverlays = overlays.filter(item => !executionKinds.includes(item.kind));
  }
  const colored = finalOverlays.map(item => ({...item, color: ["MITIGATED", "INVALIDATED"].includes(item.status) ? "#8792A2" : item.kind === "Entry" ? "#46D6B3" : item.kind === "SL" ? "#F05D6C" : item.kind.startsWith("TP") ? "#22C99A" : item.direction === "bullish" ? "#22C99A" : item.direction === "bearish" ? "#F05D6C" : "#B58BE8"}));
  const extraRisks = [];
  if (narrativePriceMismatch) extraRisks.push("عدد قیمتی خارج از تاریخچه بازار در متن مدل شناسایی و حذف شد؛ تحلیل به WAIT تنزل یافت.");
  if (rejected > 0) extraRisks.push(`${rejected} سطح خارج از محدوده مجاز قیمت تاریخی/مرجع بود و برای جلوگیری از ترسیم قیمت نامعتبر حذف شد.`);
  if (invalidPlan && !narrativePriceMismatch) extraRisks.push(!hasValidPoi
    ? "پس از کنترل قیمت و کندل‌ها، هیچ POI معتبر و فعال و منطبق با داده واقعی از نوع OB، FVG یا Swing تأیید نشد؛ سیگنال به انتظار تبدیل شد."
    : !executionPriceValidation.valid
      ? `اعتبارسنجی قیمت Entry/SL/TP با قیمت مرجع، ATR و مرز ابطال POI ناموفق بود: ${executionPriceValidation.reasons.join(' ')}`
    : !executionEvidenceValid
      ? "شواهد ساختاری تایم‌فریم اجرایی 5M قابل تأیید نبود؛ برنامه ورود به انتظار تبدیل شد."
      : !timeframeDirectionValid
        ? "جهت سیگنال با روند 5M یا ساختار تایم‌فریم‌های بالاتر سازگار نبود؛ سیگنال به انتظار تبدیل شد."
        : "برنامه ورود/حدضرر/اهداف پس از کنترل محدوده قیمت کامل یا سازگار نبود؛ سیگنال به انتظار تبدیل شد.");
  const analysisSectionStatus = provider.analysisSectionStatus || {};
  const timeframeVoteEligibility = Object.fromEntries(["1h", "15m", "5m"].map(tf => {
    const frame = timeframeData[tf];
    // The timeframe's own structure/event is validated below. Do not let the
    // aggregate `structure` narrative section suppress independently valid TF data.
    const sectionKeys = ["regime"];
    const sectionsValid = sectionKeys.every(key => analysisSectionStatus[key]?.valid === true && analysisSectionStatus[key]?.status === "AVAILABLE");
    const tfEvidenceStatus = evidenceValidation.timeframeFactorStatus?.[tf]?.marketStructure || "UNVERIFIED";
    const eligible = provider.status === "ok" && directional && !!frame && frame.provided !== false &&
      frame.narrativeOnly !== true && sectionsValid && tfEvidenceStatus === "VALIDATED" &&
      ["BULLISH", "BEARISH"].includes(frame.trend);
    return [tf, {eligible, trend:frame?.trend || "UNKNOWN", evidenceStatus:tfEvidenceStatus,
      reason:eligible ? "جهت و شواهد همین تایم‌فریم معتبر است." :
        !frame || frame.provided === false ? "داده ساختاریافته این تایم‌فریم موجود نیست." :
        frame.narrativeOnly ? "داده فقط از روایت بازیابی شده و برای رأی کافی نیست." :
        !sectionsValid ? "بخش مستقل رژیم بازار معتبر نیست." :
        tfEvidenceStatus !== "VALIDATED" ? "شواهد همین تایم‌فریم تأیید نشده است." :
        "جهت مستقل قابل رأی برای این تایم‌فریم وجود ندارد."}];
  }));
  const marketDirectionSupported = ["1h", "15m"].some(tf => {
    const vote = timeframeVoteEligibility[tf];
    return vote?.eligible === true && vote.trend === (marketBias === "BUY" ? "BULLISH" : "BEARISH");
  });
  const directionalVoteEligible = provider.status === "ok" && directional && marketDirectionSupported;
  const directionalVoteReason = directionalVoteEligible
    ? "حداقل یک تایم‌فریم بالاتر جهت اعلامی را با شواهد مستقل تأیید می‌کند؛ سایر عوامل و Trade Plan جداگانه ارزیابی می‌شوند."
    : !directional ? "مدل جهت BUY/SELL مشخصی اعلام نکرده است."
      : !marketDirectionSupported ? "هیچ‌یک از تایم‌فریم‌های 1H و 15M جهت اعلامی را با شواهد مستقل تأیید نکرده‌اند."
        : narrativePriceMismatch ? "ناسازگاری قیمت در روایت مدل، رأی جهت را غیرقابل‌اعتماد کرده است."
          : "جهت بازار برای رأی معتبر نیست.";
  return {
    ...safeProvider, bias: finalBias, marketBias, confidence: finalConfidence, overlays: colored,
    directionalVoteEligible, directionalVoteReason,
    timeframeEvidenceValidation: evidenceValidation.timeframeStatus || {},
    timeframeFactorEvidenceValidation: evidenceValidation.timeframeFactorStatus || {},
    timeframeVoteEligibility,
    factorEvidenceValidation: {
      trend: analysisSectionStatus.regime?.status || "INVALID",
      marketStructure: analysisSectionStatus.structure?.status !== "AVAILABLE" ? (analysisSectionStatus.structure?.status || "INVALID") : (evidenceValidation.factorStatus?.marketStructure || "UNVERIFIED"),
      liquidity: analysisSectionStatus.liquidity?.status !== "AVAILABLE" ? (analysisSectionStatus.liquidity?.status || "INVALID") : (evidenceValidation.factorStatus?.liquidity || "UNVERIFIED"),
      poi: analysisSectionStatus.poi?.status !== "AVAILABLE" ? (analysisSectionStatus.poi?.status || "INVALID") : hasValidPoi ? "VALIDATED" : directional ? "UNVERIFIED" : "NOT_APPLICABLE",
      premiumDiscount: analysisSectionStatus.premiumDiscount?.status || "INVALID",
      volumeMomentum: analysisSectionStatus.volumeMomentum?.status || "INVALID",
      scenarios: analysisSectionStatus.scenarios?.status || "INVALID",
      execution: analysisSectionStatus.execution?.status !== "AVAILABLE" ? (analysisSectionStatus.execution?.status || "INVALID") : executionPriceValidation.status,
      dataQuality: analysisSectionStatus.dataQuality?.status || "INVALID"
    },
    tradePlanEligible: !invalidPlan && directional,
    executionPriceValidation,
    schemaStatus: provider.contractStatus, evidenceStatus, evidenceValidation,
    contractStatus: provider.contractStatus,
    risks: [...(safeProvider.risks || []).slice(0, Math.max(0, 5-extraRisks.length)), ...extraRisks]
  };
}

function configuredModelList(provider, _env) {
  // The code-owned shortlist is authoritative. Old environment model lists
  // must not silently re-introduce retired/low-quality models or hide the
  // curated fallback after a temporary catalog outage.
  return [...(CURATED_MODEL_RANKING[provider] || [])];
}

// Fetch live catalogs server-side; provider API keys never leave the Worker.
async function fetchLiveModelCatalog(provider, env) {
  const key = PROVIDER_KEYS[provider];
  const apiKey = env[`${key}_API_KEY`];
  if (!apiKey) return { models: [], source: "not_configured", error: null };
  try {
    let models = [];
    if (provider === "gemini") {
      let pageToken = "";
      for (let page = 0; page < 3; page++) {
        const url = new URL("https://generativelanguage.googleapis.com/v1beta/models");
        url.searchParams.set("pageSize", "1000");
        if (pageToken) url.searchParams.set("pageToken", pageToken);
        const response = await fetchTimed(url.toString(), {headers:{"x-goog-api-key":apiKey}});
        const body = await readJsonResponse(response, "Gemini models");
        for (const item of body.models || []) {
          const modelId = String(item.name || "").replace(/^models\//, "");
          const nonTextOrSpecial = /(image|tts|transcrib|audio|speech|computer-use|deep-research|robotics|lyria|nano-banana|embedding|moderation)/i;
          if ((item.supportedGenerationMethods || []).includes("generateContent") &&
              /^(gemini|gemma)-/i.test(modelId) && !nonTextOrSpecial.test(modelId)) {
            models.push(modelId);
          }
        }
        pageToken = body.nextPageToken || "";
        if (!pageToken) break;
      }
    } else if (provider === "groq") {
      const response = await fetchTimed("https://api.groq.com/openai/v1/models", {headers:{Authorization:`Bearer ${apiKey}`}});
      const body = await readJsonResponse(response, "Groq models");
      models = (body.data || []).filter(item => item.active !== false && Number(item.context_window || 0) >= 8192 && !/(whisper|guard|embed|speech|transcri|moderation|tts)/i.test(item.id || "")).map(item => String(item.id));
    } else {
      const catalogUrl = new URL("https://openrouter.ai/api/v1/models");
      catalogUrl.searchParams.set("max_price", "0");
      catalogUrl.searchParams.set("context", "16384");
      catalogUrl.searchParams.set("sort", "throughput-high-to-low");
      const response = await fetchTimed(catalogUrl.toString(), {headers:{Authorization:`Bearer ${apiKey}`,"HTTP-Referer":"https://ai-crypto-analyst.app","X-Title":"AI Crypto Analyst"}});
      const body = await readJsonResponse(response, "OpenRouter models");
      const eligible = (body.data || []).filter(item => {
        const input = item.architecture?.input_modalities || [];
        const output = item.architecture?.output_modalities || [];
        const pricing = item.pricing || {};
        const promptPrice = Number(pricing.prompt);
        const completionPrice = Number(pricing.completion);
        const freeVariant = String(item.id || "").endsWith(":free");
        const zeroPriced = Number.isFinite(promptPrice) && Number.isFinite(completionPrice) && promptPrice === 0 && completionPrice === 0;
        // Trading analysis uses text-only LLMs. Reject multimodal models too,
        // not merely image-only/audio-only models; also reject router aliases
        // because they do not identify a concrete model for health/routing.
        const textOnly = input.length === 1 && input[0] === "text" && output.length === 1 && output[0] === "text";
        const concreteModel = String(item.id || "").length > 0 && item.id !== "openrouter/free";
        return concreteModel && textOnly && (freeVariant || zeroPriced) && Number(item.context_length || 0) >= 16384;
      });
      const curated = (CURATED_MODEL_RANKING.openrouter || []).filter(id => id !== "openrouter/free" && eligible.some(item => item.id === id));
      const discovered = eligible.map(item => String(item.id)).filter(id => !curated.includes(id));
      models = [...curated, ...discovered];
    }
    if (provider === "openrouter") {
      models = models.filter(model => model !== "openrouter/free");
    } else {
      models = (CURATED_MODEL_RANKING[provider] || []).filter(model => models.includes(model));
    }
    // OpenRouter exposes the full live free text catalog; other providers retain
    // their independently curated capability shortlist.
    return {models:[...new Set(models)].slice(0, 41),source:"live_ranked_catalog",error:null,rankingVersion:MODEL_RANKING_VERSION};
  } catch (error) {
    return {models:configuredModelList(provider, env),source:"worker_fallback",error:safeError(error)};
  }
}

function requestedModels(provider, input, env, liveCatalog = null) {
  const available = liveCatalog?.[provider] ? liveCatalog[provider].models : configuredModelList(provider, env);
  const primaryRaw = input?.modelSelection?.[provider];
  const fallbackRaw = input?.fallbackSelection?.[provider];
  // User-selected primary/fallback come first; then retain the rest of the
  // ranked live catalog as automatic fallbacks. Never stop at two candidates.
  const values = [primaryRaw == null || primaryRaw === "" ? available[0] : primaryRaw, fallbackRaw, ...available];
  const models = [];
  for (const raw of values) {
    if (raw == null || raw === "") continue;
    const model = String(raw).trim();
    if (model.length > 140 || !/^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$/.test(model)) {
      throw new Error(`Invalid ${provider} model identifier`);
    }
    if (!available.includes(model)) {
      throw new Error(`${provider} model is not in the current Worker candidate list or live provider catalog`);
    }
    if (!models.includes(model)) models.push(model);
  }
  if (models.length === 0) throw new Error(`No ${provider} model is configured`);
  // Bound sequential retries to keep worst-case latency and quota use predictable.
  return models.slice(0, 4);
}

async function runProviders(input, env) {
  const prompt = buildPrompt(input);
  const definitions = [
    ["gemini", callGemini],
    ["openrouter", callOpenRouter],
    ["groq", callGroq]
  ];
  const requested = Array.isArray(input?.selectedProviders)
    ? new Set(input.selectedProviders.filter(x => ["gemini","openrouter","groq"].includes(x)))
    : new Set(definitions.filter(([name]) => Boolean(env[`${PROVIDER_KEYS[name]}_API_KEY`])).map(([name]) => name));
  const liveCatalog = {};
  // Avoid an extra catalog request on every analysis when the selected IDs are
  // already in the local allow-list. Fetch live metadata only for newly selected IDs.
  const catalogNeeded = [...requested].filter(name => {
    const known = configuredModelList(name, env);
    const primary = input?.modelSelection?.[name];
    const fallback = input?.fallbackSelection?.[name];
    return [primary, fallback].some(value => value != null && value !== "" && !known.includes(String(value).trim()));
  });
  await Promise.all(catalogNeeded.map(async name => { liveCatalog[name] = await fetchLiveModelCatalog(name, env); }));
  const settled = await Promise.allSettled(definitions.map(async ([name, fn]) => {
    if (!requested.has(name)) return { skipped: true };
    const started = Date.now();
    try {
      if (!env[`${PROVIDER_KEYS[name]}_API_KEY`]) throw new Error(`${name} API key is not configured`);
      const circuitKey = `${name}:${input?.modelSelection?.[name] || configuredModelList(name,env)[0] || 'default'}`;
      const circuit = await acquireProviderCircuit(env,circuitKey);
      if (!circuit.allowed) throw new Error(`${circuit.halfOpenInProgress?'CIRCUIT_HALF_OPEN_PROBE_IN_PROGRESS':'CIRCUIT_OPEN'}; retryAt=${circuit.retryAt?new Date(circuit.retryAt).toISOString():'unknown'}`);
      const models = requestedModels(name, input, env, liveCatalog);
      const failures = [];
      for (let modelIndex = 0; modelIndex < models.length; modelIndex++) {
        const model = models[modelIndex];
        try {
          const modelEnv = { ...env, [`${PROVIDER_KEYS[name]}_MODEL`]: model };
          const value = await fn(prompt, modelEnv);
          await recordProviderCircuitSuccess(env,circuitKey);
          return { ...value, status: "ok", provider: name, providerModel: value.providerModel || model,
            attemptedModels: models.slice(0, modelIndex + 1), fallbackUsed: modelIndex > 0,
            responseTimeMs: Date.now() - started };
        } catch (error) {
          failures.push(`${model}: ${safeError(error)}`);
        }
      }
      if (failures.length) await recordProviderCircuitFailure(env,circuitKey,'ANALYSIS_REQUEST_FAILED');
      throw new Error(failures.join(" || ") || `${name} models failed`);
    } catch (error) {
      throw Object.assign(new Error(safeError(error)), {
        providerName: name,
        responseTimeMs: Date.now() - started
      });
    }
  }));

  const results = {};
  for (let i = 0; i < definitions.length; i++) {
    const [name] = definitions[i];
    const item = settled[i];
    if (item.status === "fulfilled" && item.value?.skipped) {
      results[name] = { status: "not_selected", provider: name, bias: "WAIT", summary: "این ارائه‌دهنده برای این درخواست انتخاب نشده است.", observations: [], risks: [], confidence: null, confidenceDeclared:false, analyticalWeights: {}, analyticalWeightsStatus:"NOT_PROVIDED", factorScores: {}, factorScoresStatus:"NOT_PROVIDED", weightsProvided: false, overlays: [] };
    } else {
      results[name] = item.status === "fulfilled"
        ? item.value
        : {
            status: "error", provider: name, bias: "WAIT", summary: `فراخوانی ${name} ناموفق بود.`,
            observations: [], risks: [], confidence: null, confidenceDeclared:false, analyticalWeights: {}, analyticalWeightsStatus:"NOT_PROVIDED", factorScores: {}, factorScoresStatus:"NOT_PROVIDED", weightsProvided: false, overlays: [],
            error: safeError(item.reason), responseTimeMs: Number(item.reason?.responseTimeMs || 0)
          };
    }
    results[name] = validateProviderOverlays(results[name], input.marketHistory, input.referencePrice);
  }
  return results;
}

function overlaysMatch(a, b) {
  if (a.type !== b.type || a.kind !== b.kind || a.direction !== b.direction || a.timeframe !== b.timeframe) return false;
  if (a.type === "line") {
    const mid = (a.price + b.price) / 2;
    return mid > 0 && Math.abs(a.price - b.price) / mid <= 0.0015;
  }
  const overlap = Math.min(a.high, b.high) - Math.max(a.low, b.low);
  const span = Math.max(a.high, b.high) - Math.min(a.low, b.low);
  return span > 0 && overlap / span >= 0.5;
}

function makeConsensus(providers) {
  const names = ["gemini", "openrouter", "groq"];
  const contractValid = names.filter(name => providers[name]?.status === "ok" && providers[name]?.contractStatus === "VALID");
  const eligible = names.filter(name => providers[name]?.directionalVoteEligible === true && ["BUY", "SELL"].includes(providers[name]?.marketBias || providers[name]?.bias));
  const conflicts = [];
  const votes = { BUY: 0, SELL: 0, WAIT: 0 };
  for (const name of eligible) votes[normalizeSignal(providers[name].marketBias || providers[name].bias)]++;
  const majority = votes.BUY >= 2 ? "BUY" : votes.SELL >= 2 ? "SELL" : "WAIT";
  if (eligible.length < 2) conflicts.push("کمتر از دو مدل دارای جهت ساختاریافته و شواهد کندلی معتبر هستند.");
  if (votes.BUY > 0 && votes.SELL > 0) conflicts.push("بین جهت مدل‌های معتبر اختلاف وجود دارد.");
  if (eligible.length < names.length) conflicts.push("حداقل یکی از ارائه‌دهندگان AI رأی جهت معتبر ندارد؛ مدل غایب یا ناقص رأی مخالف محسوب نمی‌شود.");
  const decision = ["BUY", "SELL"].includes(majority) ? majority : "WAIT";
  const agreeing = eligible.filter(name => normalizeSignal(providers[name].marketBias || providers[name].bias) === decision);

  const aiOverlays = [];
  // Consensus overlays remain execution/POI artifacts and are independently
  // corroborated; directional consensus does not imply a shared trade plan.
  const planAgreeing = agreeing.filter(name => providers[name]?.tradePlanEligible === true);
  const baseName = planAgreeing[0];
  if (baseName) {
    for (const a of (providers[baseName].overlays || [])) {
      const matching = planAgreeing.slice(1).map(name => (providers[name].overlays || []).find(b => overlaysMatch(a, b))).filter(Boolean);
      if (matching.length < 1) continue;
      if (a.type === "line") {
        const price = ([a.price, ...matching.map(x => x.price)].reduce((sum, value) => sum + value, 0)) / (matching.length + 1);
        aiOverlays.push({...a, price, color: a.direction === "bullish" ? "#22C99A" : a.direction === "bearish" ? "#F05D6C" : "#B58BE8", agreement: "multi"});
      } else {
        const low = Math.max(a.low, ...matching.map(x => x.low));
        const high = Math.min(a.high, ...matching.map(x => x.high));
        if (high > low) aiOverlays.push({...a, low, high, color: a.direction === "bullish" ? "#22C99A" : a.direction === "bearish" ? "#F05D6C" : "#B58BE8", agreement: "multi"});
      }
      if (aiOverlays.length >= MAX_AI_OVERLAYS) break;
    }
  }
  if (aiOverlays.length === 0) conflicts.push("اجماع جهت بازار به‌تنهایی برای ترسیم ناحیه یا برنامه معاملاتی مشترک کافی نیست.");
  return { decision, majority, votes, validProviders: eligible, contractValidProviders: contractValid, voteEligibleProviders: eligible, conflicts, aiOverlays };
}

async function readRequestBody(request) {
  const declared = Number(request.headers.get("Content-Length") || 0);
  if (declared > MAX_BODY_BYTES) throw new Error("Request body too large");

  const raw = await request.text();
  if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) {
    throw new Error("Request body too large");
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("Invalid JSON body");
  }
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function authorizedForProviderTest(request, env) {
  if (!env.GATEWAY_TOKEN) return false;
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  return constantTimeEqual(token, env.GATEWAY_TOKEN);
}

// Keep route buckets isolated so catalog/quota probes cannot consume the
// primary analysis allowance for the same client IP.
async function applyRateLimit(request, env, scope = 'analyze') {
  if (!env.RATE_LIMITER) {
    return { allowed: false, reason: "RATE_LIMITER binding is missing" };
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  try {
    const result = await env.RATE_LIMITER.limit({ key: `${scope}:${ip}` });
    return { allowed: Boolean(result?.success), reason: null };
  } catch (error) {
    return { allowed: false, reason: "Rate limiter binding failed" };
  }
}

function normalizeAltFinsSymbol(raw) {
  const value = String(raw || "").trim().toUpperCase().replace(/[^A-Z0-9_]/g, "");
  if (!value) return "";
  // altFINS crypto screener uses the base ticker (BTC), not Binance's BTCUSDT.
  for (const quote of ["USDT", "USDC", "BUSD", "FDUSD", "USD", "BTC", "ETH"]) {
    if (value.endsWith(quote) && value.length > quote.length) return value.slice(0, -quote.length);
  }
  return value;
}

function altFinsInterval(raw) {
  const value = String(raw || "15m").trim().toLowerCase();
  const map = { "15m": "MINUTES15", "15min": "MINUTES15", "1h": "HOURLY", "60m": "HOURLY", "4h": "HOURS4", "12h": "HOURS12", "1d": "DAILY" };
  return map[value] || null;
}

async function altFinsFetch(path, env, options = {}) {
  if (!env.ALTFINS_API_KEY) throw new Error("ALTFINS_NOT_CONFIGURED");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ALTFINS_TIMEOUT_MS);
  try {
    return await fetch(`${ALTFINS_BASE}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "X-API-KEY": env.ALTFINS_API_KEY,
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {})
      }
    });
  } finally { clearTimeout(timer); }
}

async function readAltFinsJson(response) {
  const raw = await response.text();
  let body;
  try { body = raw ? JSON.parse(raw) : {}; }
  catch { throw new Error(`ALTFINS_INVALID_RESPONSE_HTTP_${response.status}`); }
  if (!response.ok) {
    const code = response.status === 401 ? "ALTFINS_UNAUTHORIZED" :
      response.status === 403 ? "ALTFINS_PLAN_RESTRICTED" :
      response.status === 429 ? "ALTFINS_LIMIT_REACHED" : `ALTFINS_HTTP_${response.status}`;
    const error = new Error(code);
    error.status = response.status;
    throw error;
  }
  return body;
}

async function getAltFinsQuota(env) {
  const response = await altFinsFetch("/monthly-available-permits", env, { method: "GET" });
  const body = await readAltFinsJson(response);
  return {
    availablePermits: Number.isFinite(Number(body.availablePermits)) ? Number(body.availablePermits) : null,
    monthlyAvailablePermits: Number.isFinite(Number(body.monthlyAvailablePermits)) ? Number(body.monthlyAvailablePermits) : null,
    monthlyAvailableAiTradeSetupPrompts: Number.isFinite(Number(body.monthlyAvailableAiTradeSetupPrompts))
      ? Number(body.monthlyAvailableAiTradeSetupPrompts) : null
  };
}

async function getAltFinsValidation(input, env) {
  const symbol = normalizeAltFinsSymbol(input.symbol);
  const interval = altFinsInterval(input.timeframe);
  if (!symbol || symbol.length > 20 || !interval) {
    return { status: 400, body: { ok: false, source: "altfins", status: "INVALID_INPUT", error: "A valid crypto symbol and timeframe (15m, 1h, 4h, 12h, 1d) are required" } };
  }
  const exchange = String(input.exchange || "BINANCE").toUpperCase();
  const allowedExchanges = new Set(["BINANCE", "BYBIT", "OKX", "COINBASE", "KRAKEN", "KUCOIN", "MEXC", "GATEIO"]);
  if (!allowedExchanges.has(exchange)) return {status:400,body:{ok:false,source:"altfins",status:"UNSUPPORTED_EXCHANGE",exchange,marketType:"SPOT",affectsTradeDecision:false}};
  const safeExchange = exchange;
  const tradingType = String(input.tradingType || "SPOT").toUpperCase();
  const safeTradingType = ["SPOT", "FUTURES", "PERPETUAL", "FUTURES_OR_PERPETUAL", "ALL"].includes(tradingType) ? tradingType : "SPOT";
  const cacheKey = new Request(`https://altfins-cache.local/v1/${encodeURIComponent(symbol)}/${interval}/${safeExchange}/${safeTradingType}`);
  const diagnostic = input.diagnostic === true;
  const cache = globalThis.caches?.default;
  if (cache && !diagnostic) {
    const cached = await cache.match(cacheKey);
    if (cached) {
      const data = await cached.json();
      return { status: 200, body: { ...data, cached: true } };
    }
  }
  const payload = {
    symbols: [symbol],
    timeInterval: interval,
    displayType: ["RSI14", "ADX", "MACD", "MACD_SIGNAL_LINE", "EMA9", "EMA50", "EMA200", "ATR", "VOLUME", "VOLUME_RELATIVE", "SHORT_TERM_TREND", "MEDIUM_TERM_TREND", "LONG_TERM_TREND", "SUPPORT", "RESISTANCE"]
  };
  const params = new URLSearchParams({ page: "0", size: "1", sort: "TIME,desc" });
  // These filters constrain the listing to the requested venue and instrument class.
  const bodyPayload = { ...payload, exchangeFilter: safeExchange, tradingTypeFilter: safeTradingType };
  try {
    const response = await altFinsFetch(`/screener-data/search-requests?${params}`, env, {
      method: "POST", body: JSON.stringify(bodyPayload)
    });
    const data = await readAltFinsJson(response);
    const rows = Array.isArray(data) ? data : Array.isArray(data.content) ? data.content :
      Array.isArray(data.items) ? data.items : [];
    const item = rows.find(row => String(row.symbol || "").toUpperCase() === symbol) || rows[0] || null;
    if (!item) {
      return { status: 200, body: { ok: true, source: "altfins", status: "NO_MATCH", symbol, timeframe: input.timeframe, exchange:safeExchange, marketType:safeTradingType, refreshedAt: new Date().toISOString(), data: null, cached: false } };
    }
    // The official Screener API nests indicator values inside `additionalData`.
    // Older/alternate response shapes are also accepted for forward compatibility.
    const additional = item.additionalData || item.additional_data || {};
    // Diagnostic mode returns only support/resistance-related key names, types,
    // and bounded values. It never returns headers, API keys, or the full payload.
    const diagnosticKeys = diagnostic ? {
      itemKeys: Object.keys(item).filter(key => /support|resistance/i.test(key)),
      additionalDataKeys: Object.keys(additional).filter(key => /support|resistance/i.test(key)),
      supportCandidates: [],
      resistanceCandidates: []
    } : null;
    const safeDiagnosticValue = value => {
      if (value === null || value === undefined) return null;
      if (typeof value === "number" || typeof value === "boolean") return value;
      if (typeof value === "string") return value.slice(0, 160);
      try { return JSON.stringify(value).slice(0, 300); } catch (_) { return String(value).slice(0, 160); }
    };
    if (diagnostic) {
      for (const [key, value] of Object.entries({...item, ...additional})) {
        if (/support/i.test(key)) diagnosticKeys.supportCandidates.push({key, type: value === null ? "null" : Array.isArray(value) ? "array" : typeof value, value: safeDiagnosticValue(value)});
        if (/resistance/i.test(key)) diagnosticKeys.resistanceCandidates.push({key, type: value === null ? "null" : Array.isArray(value) ? "array" : typeof value, value: safeDiagnosticValue(value)});
      }
    }
    const metric = (...keys) => {
      for (const key of keys) {
        let value = item[key];
        if (value === undefined || value === null) value = additional[key];
        if (value === undefined || value === null) {
          const upper = String(key).toUpperCase();
          value = item[upper] ?? additional[upper];
        }
        if (value && typeof value === "object" && !Array.isArray(value)) {
          value = value.value ?? value.currentValue ?? value.numericValue ?? value.displayValue ?? null;
        }
        if (value !== undefined && value !== null && value !== "") return value;
      }
      return null;
    };
    // SUPPORT / RESISTANCE are nested objects (SUPPORT_1..6 / RESISTANCE_1..6),
    // not scalar metrics. Parse their formatted strings and select the nearest
    // valid level on the correct side of the current price.
    const parseAltFinsPrice = value => {
      if (typeof value === "number" && Number.isFinite(value)) return value;
      if (typeof value !== "string") return null;
      const cleaned = value.trim().replace(/,/g, "");
      if (!cleaned || cleaned === "-" || cleaned.toLowerCase() === "null") return null;
      const parsed = Number(cleaned);
      return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
    };
    const levelObject = (kind) => {
      const upper = kind.toUpperCase();
      const raw = item[upper] ?? item[kind.toLowerCase()] ?? additional[upper] ?? additional[kind.toLowerCase()];
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
      return raw;
    };
    const collectLevels = kind => {
      const raw = levelObject(kind);
      const levels = [];
      for (let i = 1; i <= 6; i++) {
        const key = `${kind.toUpperCase()}_${i}`;
        const price = parseAltFinsPrice(raw[key] ?? raw[key.toLowerCase()]);
        if (price !== null) levels.push({ index: i, price });
      }
      return levels.sort((a, b) => a.price - b.price);
    };
    const lastPrice = parseAltFinsPrice(metric("lastPrice", "LAST_PRICE"));
    const supportLevels = collectLevels("support");
    const resistanceLevels = collectLevels("resistance");
    const nearestSupport = lastPrice === null ? null : supportLevels
      .filter(level => level.price <= lastPrice)
      .sort((a, b) => b.price - a.price)[0] || null;
    const nearestResistance = lastPrice === null ? null : resistanceLevels
      .filter(level => level.price >= lastPrice)
      .sort((a, b) => a.price - b.price)[0] || null;
    const normalizedData = {
      symbol: item.symbol || symbol,
      name: item.name || null,
      lastPrice: metric("lastPrice", "LAST_PRICE"),
      rsi14: metric("rsi14", "RSI14"),
      adx: metric("adx", "ADX"),
      macd: metric("macd", "MACD"),
      macdSignal: metric("macdSignalLine", "macdSignal", "MACD_SIGNAL_LINE"),
      ema9: metric("ema9", "EMA9"),
      ema50: metric("ema50", "EMA50"),
      ema200: metric("ema200", "EMA200"),
      atr: metric("atr", "ATR"),
      volume: metric("volume", "VOLUME"),
      relativeVolume: metric("volumeRelative", "relativeVolume", "VOLUME_RELATIVE"),
      shortTermTrend: metric("shortTermTrend", "SHORT_TERM_TREND"),
      mediumTermTrend: metric("mediumTermTrend", "MEDIUM_TERM_TREND"),
      longTermTrend: metric("longTermTrend", "LONG_TERM_TREND"),
      support: nearestSupport ? nearestSupport.price : null,
      resistance: nearestResistance ? nearestResistance.price : null,
      supportLevels: supportLevels.map(level => level.price),
      resistanceLevels: resistanceLevels.map(level => level.price)
    };
    const metricCount = Object.entries(normalizedData).filter(([key, value]) => key !== "symbol" && key !== "name" && value !== null).length;
    const normalized = {
      ok: metricCount > 0, source: "altfins", status: metricCount > 0 ? "AVAILABLE" : "DATA_EMPTY", symbol,
      exchange:safeExchange, marketType:safeTradingType,
      timeframe: input.timeframe || "15m", interval,
      refreshedAt: new Date().toISOString(), cached: false,
      metricCount, data: normalizedData,
      ...(diagnostic ? { diagnostic: {
        responseContainer: Array.isArray(data) ? "array" : Array.isArray(data.content) ? "content[]" : Array.isArray(data.items) ? "items[]" : "unknown",
        additionalDataPresent: Boolean(item.additionalData || item.additional_data),
        supportResistanceKeys: diagnosticKeys,
        normalizedSupport: safeDiagnosticValue(normalizedData.support),
        normalizedResistance: safeDiagnosticValue(normalizedData.resistance),
        parsedSupportLevels: normalizedData.supportLevels,
        parsedResistanceLevels: normalizedData.resistanceLevels,
        selectedSupportIndex: nearestSupport?.index ?? null,
        selectedResistanceIndex: nearestResistance?.index ?? null,
        parsedLastPrice: lastPrice
      } } : {}),
      ...(metricCount === 0 ? { error: "ALT FINS returned an asset but no requested indicator values in additionalData", affectsTradeDecision: false } : {})
    };
    if (cache && !diagnostic) {
      const cacheResponse = new Response(JSON.stringify(normalized), { headers: { "Content-Type": "application/json", "Cache-Control": `public, max-age=${ALTFINS_CACHE_TTL_SECONDS}` } });
      await cache.put(cacheKey, cacheResponse);
    }
    return { status: 200, body: normalized };
  } catch (error) {
    const code = String(error?.message || "ALTFINS_UNAVAILABLE");
    const status = code === "ALTFINS_NOT_CONFIGURED" ? 503 :
      code === "ALTFINS_UNAUTHORIZED" ? 502 :
      code === "ALTFINS_PLAN_RESTRICTED" ? 200 :
      code === "ALTFINS_LIMIT_REACHED" ? 200 : 502;
    const state = code === "ALTFINS_NOT_CONFIGURED" ? "NOT_CONFIGURED" :
      code === "ALTFINS_UNAUTHORIZED" ? "INVALID_KEY" :
      code === "ALTFINS_PLAN_RESTRICTED" ? "PLAN_RESTRICTED" :
      code === "ALTFINS_LIMIT_REACHED" ? "LIMIT_REACHED" : "UNAVAILABLE";
    return { status, body: { ok: false, source: "altfins", status: state, symbol, timeframe: input.timeframe || "15m", error: code, affectsTradeDecision: false } };
  }
}

// Backward-compatible test hook; production circuit state lives only in Durable Object storage.
export function resetProviderCircuitState() {}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = getAllowedOrigin(request, env);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
          "Vary": "Origin"
        }
      });
    }

    if (origin === "null") {
      return responseJson({ ok: false, error: "Origin not allowed" }, 403, origin);
    }

    if (url.pathname === "/health" && request.method === "GET") {
      let circuitBreakerHealth = {bindingConfigured:Boolean(env.PROVIDER_CIRCUIT_BREAKER),reachable:false,status:'UNAVAILABLE',errorCode:null};
      if (!env.PROVIDER_CIRCUIT_BREAKER) {
        circuitBreakerHealth.errorCode = 'BINDING_MISSING';
      } else {
        try {
          await circuitRequest(env, 'status', {key:'_health_check_'});
          circuitBreakerHealth = {bindingConfigured:true,reachable:true,status:'READY',errorCode:null};
        } catch (error) {
          const message = safeError(error);
          circuitBreakerHealth = {bindingConfigured:true,reachable:false,status:'UNAVAILABLE',errorCode:message.includes('CIRCUIT_STORE_') ? 'DURABLE_OBJECT_REQUEST_FAILED' : message.includes('INVALID_RESPONSE') ? 'DURABLE_OBJECT_INVALID_RESPONSE' : 'DURABLE_OBJECT_UNREACHABLE'};
        }
      }
      return responseJson({
        ok: true,
        service: "AI Crypto Analyst Gateway",
        mode: "FREE_PROVIDERS",
        configured: {
          gemini: Boolean(env.GEMINI_API_KEY),
          openrouter: Boolean(env.OPENROUTER_API_KEY),
          groq: Boolean(env.GROQ_API_KEY),
          altfins: Boolean(env.ALTFINS_API_KEY),
          gateway: Boolean(env.GATEWAY_TOKEN),
          rateLimiter: Boolean(env.RATE_LIMITER),
          providerCircuitBreaker: circuitBreakerHealth.bindingConfigured
        },
        providerCircuitBreakerHealth: circuitBreakerHealth,
        models: {
          gemini: configuredModelList("gemini", env),
          openrouter: configuredModelList("openrouter", env),
          groq: configuredModelList("groq", env)
        },
        modelSelectionSupported: true,
        modelRankingVersion: MODEL_RANKING_VERSION,
        modelRankingNote: "Capability-based shortlist only; not a measured crypto-trading win-rate ranking."
      }, 200, origin);
    }

    if (url.pathname === "/providers/health" && request.method === "POST") {
      const rate = await applyRateLimit(request, env, "provider-health");
      if (!rate.allowed) return responseJson({ok:false,error:rate.reason || "Rate limit exceeded",code:rate.reason ? "RATE_LIMITER_UNAVAILABLE" : "RATE_LIMITED"},rate.reason ? 503 : 429,origin);
      let healthInput = {};
      try { const raw = await request.text(); if (raw) healthInput = JSON.parse(raw); }
      catch { return responseJson({ok:false,error:"Invalid JSON body"},400,origin); }
      const health = await checkProviderHealth(healthInput,env);
      return responseJson(health,200,origin);
    }

    if (url.pathname === "/models" && request.method === "GET") {
      const rate = await applyRateLimit(request, env, "models");
      if (!rate.allowed) return responseJson({ ok: false, error: rate.reason || "Rate limit exceeded", code: rate.reason ? "RATE_LIMITER_UNAVAILABLE" : "RATE_LIMITED" }, rate.reason ? 503 : 429, origin);
      const entries = await Promise.all(["gemini","openrouter","groq"].map(async name => [name, await fetchLiveModelCatalog(name, env)]));
      const providers = Object.fromEntries(entries.map(([name, catalog]) => [name, {
        configured: Boolean(env[`${PROVIDER_KEYS[name]}_API_KEY`]),
        source: catalog.source,
        error: catalog.error,
        models: catalog.models,
        modelPolicy: "free_or_low_cost_structured_text",
        maxAutoAttempts: 4
      }]));
      return responseJson({ ok: true, source: "live_provider_catalog", rankingVersion: MODEL_RANKING_VERSION, rankingNote: "Capability-based shortlist only; not a measured crypto-trading win-rate ranking.", refreshedAt: new Date().toISOString(), providers }, 200, origin);
    }

    if (url.pathname === "/altfins/quota" && request.method === "GET") {
      if (!env.ALTFINS_API_KEY) return responseJson({ ok: false, source: "altfins", status: "NOT_CONFIGURED" }, 200, origin);
      const rate = await applyRateLimit(request, env, "altfins-quota");
      if (!rate.allowed) return responseJson({ ok: false, source: "altfins", status: "RATE_LIMITED", error: rate.reason || "Rate limit exceeded" }, rate.reason ? 503 : 429, origin);
      try {
        const quota = await getAltFinsQuota(env);
        return responseJson({ ok: true, source: "altfins", status: "AVAILABLE", checkedAt: new Date().toISOString(), quota }, 200, origin);
      } catch (error) {
        const code = String(error?.message || "ALTFINS_UNAVAILABLE");
        const state = code === "ALTFINS_UNAUTHORIZED" ? "INVALID_KEY" : code === "ALTFINS_PLAN_RESTRICTED" ? "PLAN_RESTRICTED" : code === "ALTFINS_LIMIT_REACHED" ? "LIMIT_REACHED" : "UNAVAILABLE";
        return responseJson({ ok: false, source: "altfins", status: state, error: code }, 200, origin);
      }
    }

    if (url.pathname === "/altfins/diagnostics" && request.method === "GET") {
      if (!env.ALTFINS_API_KEY) return responseJson({ ok: false, source: "altfins", status: "NOT_CONFIGURED" }, 200, origin);
      const rate = await applyRateLimit(request, env, "altfins-diagnostics");
      if (!rate.allowed) return responseJson({ ok: false, source: "altfins", status: "RATE_LIMITED", error: rate.reason || "Rate limit exceeded" }, 200, origin);
      const result = await getAltFinsValidation({
        symbol: url.searchParams.get("symbol") || "BTCUSDT",
        timeframe: url.searchParams.get("timeframe") || "15m",
        exchange: url.searchParams.get("exchange") || "BINANCE",
        tradingType: url.searchParams.get("tradingType") || "SPOT",
        diagnostic: true
      }, env);
      return responseJson(result.body, result.status, origin);
    }

    if (url.pathname === "/altfins/validation") {
      if (request.method !== "POST") return responseJson({ ok: false, error: "Method not allowed" }, 405, origin);
      if (!env.ALTFINS_API_KEY) return responseJson({ ok: false, source: "altfins", status: "NOT_CONFIGURED", affectsTradeDecision: false }, 200, origin);
      const rate = await applyRateLimit(request, env, "altfins-validation");
      if (!rate.allowed) return responseJson({ ok: false, source: "altfins", status: "RATE_LIMITED", error: rate.reason || "Rate limit exceeded", affectsTradeDecision: false }, 200, origin);
      try {
        const body = await readRequestBody(request);
        const result = await getAltFinsValidation(body || {}, env);
        return responseJson(result.body, result.status, origin);
      } catch (error) {
        const code = String(error?.message || "ALTFINS_UNAVAILABLE");
        const status = code === "Invalid JSON body" ? 400 : code === "Request body too large" ? 413 : 200;
        return responseJson({ ok: false, source: "altfins", status: "UNAVAILABLE", error: code, affectsTradeDecision: false }, status, origin);
      }
    }

    if (url.pathname === "/provider-test") {
      if (request.method !== "POST") {
        return responseJson({ ok: false, error: "Method not allowed" }, 405, origin);
      }
      if (!authorizedForProviderTest(request, env)) {
        return responseJson({ ok: false, error: "Unauthorized" }, 401, origin);
      }
      const rate = await applyRateLimit(request, env, "provider-test");
      if (!rate.allowed) return responseJson({ ok: false, error: rate.reason || "Rate limit exceeded", code: rate.reason ? "RATE_LIMITER_UNAVAILABLE" : "RATE_LIMITED" }, rate.reason ? 503 : 429, origin);

      let testOptions = {};
      try { const rawOptions = await request.text(); if (rawOptions) testOptions = JSON.parse(rawOptions); }
      catch { return responseJson({ ok: false, error: "Invalid JSON body" }, 400, origin); }
      const testInput = {
        modelSelection: testOptions.modelSelection || {},
        fallbackSelection: testOptions.fallbackSelection || {},
        selectedProviders: testOptions.selectedProviders,
        exchange: "TEST",
        symbol: "BTCUSDT",
        technicalAnalysis: {
          signal: "WAIT",
          note: "Connectivity test only. Do not produce a trade signal."
        },
        marketHistory: {
          format: "delta OHLCV; price deltas in 0.01 bps; volume ratio x100",
          "1h": {timeStart:1700000000,intervalSeconds:3600,basePrice:100,baseVolumeMedian:10,rows:Array.from({length:60},(_,i)=>[i===0?0:3600,0,10000,-10000,5000,100])},
          "15m": {timeStart:1700000000,intervalSeconds:900,basePrice:100,baseVolumeMedian:10,rows:Array.from({length:60},(_,i)=>[i===0?0:900,0,10000,-10000,5000,100])},
          "5m": {timeStart:1700000000,intervalSeconds:300,basePrice:100,baseVolumeMedian:10,rows:Array.from({length:60},(_,i)=>[i===0?0:300,0,10000,-10000,5000,100])}
        }
      };

      const providers = await runProviders(testInput, env);
      const successCount = Object.values(providers).filter(item => item.status === "ok").length;
      const ok = successCount >= 1;

      return responseJson({
        ok, successCount, requiredForDisplay: 1, requiredForConsensus: 2,
        test: "provider-connectivity", providers
      }, ok ? 200 : 502, origin);
    }

    if (url.pathname !== "/analyze") {
      return responseJson({ ok: false, error: "Not found" }, 404, origin);
    }

    if (request.method !== "POST") {
      return responseJson({ ok: false, error: "Method not allowed" }, 405, origin);
    }

    const rate = await applyRateLimit(request, env, "analyze");
    if (!rate.allowed) {
      return responseJson({
        ok: false,
        error: rate.reason || "Rate limit exceeded",
        code: rate.reason ? "RATE_LIMITER_UNAVAILABLE" : "RATE_LIMITED"
      }, rate.reason ? 503 : 429, origin);
    }

    if (!env.GEMINI_API_KEY && !env.OPENROUTER_API_KEY && !env.GROQ_API_KEY) {
      return responseJson({
        ok: false,
        error: "No AI provider API key is configured (GEMINI_API_KEY, OPENROUTER_API_KEY, GROQ_API_KEY)"
      }, 503, origin);
    }

    try {
      const input = await readRequestBody(request);
      const marketHistory = input?.marketHistory;
      const historyChecks = {
        "1h": validateEncodedHistory(marketHistory?.["1h"], 3600),
        "15m": validateEncodedHistory(marketHistory?.["15m"], 900),
        "5m": validateEncodedHistory(marketHistory?.["5m"], 300)
      };
      const validHistory = Object.values(historyChecks).every(check => check.ok);

      if (
        !input ||
        typeof input !== "object" ||
        Array.isArray(input) ||
        typeof input.exchange !== "string" ||
        typeof input.symbol !== "string" ||
        !marketHistory || typeof marketHistory !== "object" ||
        !validHistory
      ) {
        return responseJson({
          ok: false,
          error: "exchange, symbol and valid 1h/15m/5m marketHistory are required",
          dataQuality: historyChecks
        }, 400, origin);
      }

      const referencePrice = Number(input.referencePrice);
      const lastClosed5mClose = Number(input.lastClosed5mClose);
      const decoded5m = decodeHistoryCandles(marketHistory["5m"]);
      const actualHistory5mClose = decoded5m.length ? decoded5m[decoded5m.length - 1].close : NaN;
      const actualLastClosed5mClose = Number.isFinite(actualHistory5mClose) ? actualHistory5mClose : null;
      if (Number.isFinite(lastClosed5mClose) && lastClosed5mClose > 0 && Number.isFinite(actualHistory5mClose)) {
        const snapshotGap = Math.abs(actualHistory5mClose - lastClosed5mClose) / actualHistory5mClose;
        if (snapshotGap > 0.001) return responseJson({ok:false,error:"The supplied lastClosed5mClose does not match the final 5m candle reconstructed from marketHistory.",code:"HISTORY_CLOSE_MISMATCH",actualHistory5mClose}, 409, origin);
      }
      if (Number.isFinite(referencePrice) && referencePrice > 0 && Number.isFinite(actualHistory5mClose)) {
        const historyAnchorGap = Math.abs(referencePrice - actualHistory5mClose) / actualHistory5mClose;
        if (historyAnchorGap > 0.025) return responseJson({ok:false,error:'Live reference price differs from the reconstructed latest closed 5m candle by more than 2.5%; analysis was blocked to prevent mixed-price snapshots.',code:'REFERENCE_PRICE_MISMATCH'}, 409, origin);
      }
      if (Number.isFinite(referencePrice) && referencePrice > 0 && Number.isFinite(lastClosed5mClose) && lastClosed5mClose > 0) {
        const gap = Math.abs(referencePrice - lastClosed5mClose) / lastClosed5mClose;
        if (gap > 0.025) return responseJson({ok:false,error:'Live reference price differs from the latest closed 5m close by more than 2.5%; analysis was blocked to prevent mixed-price snapshots.',code:'REFERENCE_PRICE_MISMATCH'}, 409, origin);
      }

      const providers = await runProviders({
        exchange: input.exchange.slice(0, 40),
        symbol: input.symbol.slice(0, 40),
        marketType: input.marketType === "FUTURES" ? "FUTURES" : "SPOT",
        marketHistory,
        referencePrice: Number.isFinite(Number(input.referencePrice)) && Number(input.referencePrice) > 0 ? Number(input.referencePrice) : null,
        lastClosed5mClose: Number.isFinite(Number(input.lastClosed5mClose)) && Number(input.lastClosed5mClose) > 0 ? Number(input.lastClosed5mClose) : null,
        asOfUtc: typeof input.asOfUtc === 'string' ? input.asOfUtc.slice(0, 40) : null,
        snapshotId: typeof input.snapshotId === "string" ? input.snapshotId.slice(0, 100) : null,
        modelSelection: input.modelSelection && typeof input.modelSelection === "object" ? input.modelSelection : {},
        fallbackSelection: input.fallbackSelection && typeof input.fallbackSelection === "object" ? input.fallbackSelection : {},
        selectedProviders: input.selectedProviders
      }, env);
      const { gemini, openrouter, groq } = providers;
      const successfulProviders = Object.values(providers).filter(provider => provider.status === "ok").length;
      if (successfulProviders === 0) {
        return responseJson({
          ok: false, decision: "WAIT", providers, gemini, openrouter, groq,
          snapshotId: typeof input.snapshotId === "string" ? input.snapshotId.slice(0,100) : null,
          marketType: input.marketType === "FUTURES" ? "FUTURES" : "SPOT",
          dataQuality: {status:"VALIDATED",timeframes:historyChecks,actualLastClosed5mClose,referencePriceValidated:true},
          error: "All configured AI providers failed; no independent AI assessment is available"
        }, 502, origin);
      }

      const consensus = makeConsensus(providers);
      const partial = successfulProviders < 3;
      return responseJson({
        ok: true,
        decision: consensus.decision,
        consensus,
        conflicts: consensus.conflicts,
        providers,
        gemini,
        openrouter,
        groq,
        analysisMode: successfulProviders < 2 ? "SINGLE_PROVIDER_INDEPENDENT" : partial ? "PARTIAL_MULTI_PROVIDER" : "TRIPLE_PROVIDER",
        priceLevelsSource: "SOURCE_SELECTOR",
        aiOverlays: consensus.aiOverlays,
        snapshotId: typeof input.snapshotId === "string" ? input.snapshotId.slice(0, 100) : null,
        marketType: input.marketType === "FUTURES" ? "FUTURES" : "SPOT",
        candleSource: input.exchange.slice(0, 40),
        dataQuality: {status:"VALIDATED",timeframes:historyChecks,actualLastClosed5mClose,referencePriceValidated:true},
        modelSelection: input.modelSelection || {},
        fallbackSelection: input.fallbackSelection || {},
        historyCounts: {
          "1h": marketHistory["1h"].rows.length,
          "15m": marketHistory["15m"].rows.length,
          "5m": marketHistory["5m"].rows.length
        }
      }, 200, origin);

    } catch (error) {
      const message = safeError(error);
      const status =
        message === "Request body too large" ? 413 :
        message === "Invalid JSON body" ? 400 : 502;

      return responseJson({
        ok: false,
        error: message,
        decision: "WAIT"
      }, status, origin);
    }
  }
};
