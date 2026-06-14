#!/usr/bin/env python3
# Authored: Albert Lane | Documented: Claude Sonnet 4.6 | 2026-06-14
"""
forensic_fetch.py — Sovereign web forensic artifact collector.

Public forensic tool: fetch a URL's complete source, cross-reference all
date signals for backdating evidence, apply AI content heuristics, document
AI-restricted and missing artifacts, and save a SHA256-signed evidence
manifest.

Optionally proxies fetch through lane-mcp gateway when LANE_MCP_URL is set.

Usage:
  python3 scripts/forensic_fetch.py <url>
  python3 scripts/forensic_fetch.py https://en.wikipedia.org/wiki/Brutalist_architecture
  python3 scripts/forensic_fetch.py --dry-run <url>
  LANE_MCP_URL=http://localhost:3000 python3 scripts/forensic_fetch.py <url>

Output (evidence/<domain>/<timestamp>/):
  source.html      — 100% raw HTML byte-for-byte, unmodified
  headers.json     — HTTP response headers captured at fetch time
  robots.json      — robots.txt AI restriction analysis
  revisions.json   — Revision history (Wikipedia API; extensible to other CMS)
  analysis.json    — Backdating + AI content + missing artifacts report
  manifest.json    — SHA256-signed evidence manifest (primary artifact)

All IP belongs to Albert Lane per LICENSE.md | SEC No. 17684-273-411-436
"""

import json, sys, os, hashlib, re
import urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from html.parser import HTMLParser
from statistics import stdev, mean

ROOT     = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
TIMEOUT  = 20

# ── Known AI crawlers — checked against robots.txt ───────────────────────────

AI_BOTS: dict[str, str] = {
    "GPTBot":             "OpenAI — ChatGPT training crawler",
    "ChatGPT-User":       "OpenAI — ChatGPT live browsing",
    "Google-Extended":    "Google — Gemini/Bard AI training",
    "CCBot":              "Common Crawl — primary AI training dataset source",
    "anthropic-ai":       "Anthropic — Claude training crawler",
    "ClaudeBot":          "Anthropic — Claude browsing",
    "PerplexityBot":      "Perplexity AI — search and summarization crawler",
    "Diffbot":            "Diffbot — AI content extraction API",
    "Bytespider":         "ByteDance — TikTok / AI training",
    "omgili":             "Omgili — AI news aggregation",
    "Applebot-Extended":  "Apple — AI training (Siri / Apple Intelligence)",
    "YouBot":             "You.com — AI search engine",
    "cohere-ai":          "Cohere — LLM training crawler",
    "FacebookBot":        "Meta — AI model training",
    "Timpibot":           "Timpi — AI search engine",
    "DataForSeoBot":      "DataForSEO — AI SEO data harvesting",
}

# ── AI content heuristic phrase patterns ─────────────────────────────────────
# These phrases are statistically over-represented in LLM-generated text.
# Each tuple: (regex, human-readable label)

AI_PHRASES: list[tuple[str, str]] = [
    (r"\bit(?:'s| is) (?:worth|important to) (?:noting|mention)",
     "hedge-qualifier — LLM characteristic opener"),
    (r"\bin conclusion\b",
     "structural-marker — formulaic LLM conclusion signal"),
    (r"\bfurthermore\b",
     "transition — statistically over-used in LLM text"),
    (r"\bmoreover\b",
     "transition — statistically over-used in LLM text"),
    (r"\bit should be noted(?: that)?\b",
     "hedge-qualifier — LLM passive hedge"),
    (r"\bas (?:mentioned|noted) (?:earlier|above|previously)\b",
     "self-reference — LLM circular reference pattern"),
    (r"\ba (?:comprehensive|detailed|thorough) (?:overview|analysis|examination|exploration)\b",
     "scope-claim — LLM boilerplate framing"),
    (r"\bplays? (?:a|an) (?:crucial|vital|pivotal|key|significant) role\b",
     "importance-formula — LLM rhetorical inflation"),
    (r"\bseamlessly\b",
     "adverb — AI marketing-speak, rare in human writing"),
    (r"\bdelve(?:s|d|ing)?\b",
     "verb — statistically over-represented in LLM output"),
    (r"\btestament to\b",
     "phrase — LLM rhetorical marker"),
    (r"\brobust\b",
     "adjective — over-used in LLM technical/business writing"),
    (r"\bleverag(?:e|es|ing|ed)\b",
     "verb — LLM business-writing cliché"),
    (r"\butiliz(?:e|es|ing|ed)\b",
     "verb — LLM prefers 'utilize' over plain 'use'"),
    (r"\bin (?:today's|the modern|the current|the contemporary) (?:world|landscape|era|society)\b",
     "temporal-scene-setter — LLM framing cliché"),
    (r"\bembark(?:s|ed|ing)? on (?:a )?(?:journey|exploration)\b",
     "metaphor — LLM narrative opener"),
    (r"\bin the realm of\b",
     "phrase — LLM framing cliché"),
    (r"\boverall,? \b",
     "summary-signal — LLM conclusion marker"),
    (r"\bultimately,? \b",
     "summary-signal — LLM conclusion marker"),
]

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


# ── HTML parser ───────────────────────────────────────────────────────────────

class SourceParser(HTMLParser):
    """Extracts text, meta dates, comments, and structural signals."""

    def __init__(self):
        super().__init__()
        self.meta        : dict[str, str] = {}
        self.times       : list[str]      = []
        self.comments    : list[str]      = []
        self.canonical   : str            = ""
        self.title       : str            = ""
        self.text_blocks : list[str]      = []
        self._buf        : list[str]      = []
        self._skip       : bool           = False
        self._in_title   : bool           = False

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ("script", "style", "noscript"):
            self._skip     = True
            self._in_title = False
            return
        if tag == "meta":
            name = (d.get("name") or d.get("property") or "").lower().strip()
            if name and d.get("content"):
                self.meta[name] = d["content"]
        elif tag == "time" and d.get("datetime"):
            self.times.append(d["datetime"])
        elif tag == "link":
            if d.get("rel") == "canonical" and d.get("href"):
                self.canonical = d["href"]
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            self._skip = False
            self._buf.clear()
            return
        if tag == "title":
            self._in_title = False
        # Flush at block boundaries
        if tag in ("p", "div", "section", "article", "li", "td",
                   "th", "h1", "h2", "h3", "h4", "blockquote"):
            block = " ".join(self._buf).strip()
            if len(block) > 60:
                self.text_blocks.append(block)
            self._buf.clear()

    def handle_data(self, data):
        if self._skip:
            return
        if self._in_title:
            self.title += data
        s = data.strip()
        if s:
            self._buf.append(s)

    def handle_comment(self, data):
        s = data.strip()
        if s:
            self.comments.append(s[:300])


# ── HTTP utilities ────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _fetch(url: str, ua: str = BROWSER_UA) -> tuple[bytes, dict, int]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent":      ua,
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read(), dict(resp.headers), resp.status
    except urllib.error.HTTPError as e:
        return b"", {}, e.code
    except Exception as e:
        print(f"  [fetch] {e}", file=sys.stderr)
        return b"", {}, 0


def _lane_mcp_fetch(url: str) -> tuple[bytes, dict, int]:
    """Proxy fetch through lane-mcp gateway when LANE_MCP_URL is set."""
    gateway = os.environ.get("LANE_MCP_URL", "").rstrip("/")
    if not gateway:
        return b"", {}, 0
    payload = json.dumps({"tool": "lane_forensic_fetch", "url": url}).encode()
    req = urllib.request.Request(
        f"{gateway}/rpc", data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            result = json.loads(resp.read())
            return (
                result.get("body", "").encode("utf-8"),
                result.get("headers", {}),
                result.get("status", 200),
            )
    except Exception:
        return b"", {}, 0


# ── Robots.txt analysis ───────────────────────────────────────────────────────

def fetch_robots(base_url: str) -> dict:
    """Fetch robots.txt and document all AI-crawler restrictions."""
    parsed_url = urllib.parse.urlparse(base_url)
    robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"

    body, headers, status = _fetch(robots_url)
    if not body or status not in (200, 206):
        return {"url": robots_url, "status": status, "ai_restrictions": {},
                "ai_bots_blocked": 0, "error": "unavailable"}

    text  = body.decode("utf-8", errors="replace")
    rules : dict[str, list[str]] = {}
    current_agents: list[str]    = []

    for raw_line in text.splitlines():
        line  = raw_line.split("#")[0].strip()
        lower = line.lower()
        if not line:
            current_agents = []
            continue
        if lower.startswith("user-agent:"):
            agent = line.split(":", 1)[1].strip()
            current_agents.append(agent)
            rules.setdefault(agent, [])
        elif any(lower.startswith(p) for p in ("disallow:", "allow:", "crawl-delay:")):
            for agent in current_agents:
                rules.setdefault(agent, []).append(line)

    def _full_block(rule_list: list[str]) -> bool:
        for r in rule_list:
            parts = r.split(":", 1)
            if len(parts) == 2 and parts[0].lower() == "disallow":
                path = parts[1].strip()
                if path in ("/", "/*"):
                    return True
        return False

    wildcard_rules   = rules.get("*", [])
    wildcard_blocked = _full_block(wildcard_rules)

    ai_restrictions: dict = {}
    for bot, description in AI_BOTS.items():
        bot_rules = rules.get(bot, [])
        if not bot_rules and not wildcard_rules:
            continue
        effective_rules = bot_rules if bot_rules else wildcard_rules
        blocked = _full_block(bot_rules) or (wildcard_blocked and not bot_rules)
        ai_restrictions[bot] = {
            "description": description,
            "rules":       effective_rules,
            "rule_source": "explicit" if bot_rules else "wildcard",
            "blocked":     blocked,
        }

    n_blocked = sum(1 for v in ai_restrictions.values() if v["blocked"])
    return {
        "url":              robots_url,
        "status":           status,
        "raw":              text,
        "total_agents":     len(rules),
        "ai_restrictions":  ai_restrictions,
        "wildcard_rules":   wildcard_rules,
        "wildcard_blocked": wildcard_blocked,
        "ai_bots_blocked":  n_blocked,
    }


# ── Wikipedia revision API ────────────────────────────────────────────────────

def fetch_wiki_revisions(url: str) -> dict | None:
    """Query Wikipedia API for revision history and removal signals."""
    parsed = urllib.parse.urlparse(url)
    if "wikipedia.org" not in parsed.netloc:
        return None

    parts = parsed.path.split("/wiki/")
    if len(parts) < 2:
        return None
    title = urllib.parse.unquote(parts[1].split("#")[0])

    api_url = (
        f"https://{parsed.netloc}/w/api.php"
        f"?action=query&prop=revisions|info"
        f"&rvprop=timestamp|ids|comment|size|user&rvlimit=20"
        f"&format=json&titles={urllib.parse.quote(title)}"
    )
    body, _, status = _fetch(api_url, ua="forensic-fetch/1.0 (public forensic tool)")
    if not body or status != 200:
        return {"error": "API unavailable", "status": status}

    data  = json.loads(body)
    pages = data.get("query", {}).get("pages", {})
    page  = next(iter(pages.values()), {})
    revs  = page.get("revisions", [])

    # Scan edit comments for content removal signals
    removal_signals = []
    for rev in revs:
        comment = (rev.get("comment") or "").lower()
        if any(w in comment for w in ("remov", "delet", "revert", "undid", "rv ", "undo", "blank")):
            removal_signals.append({
                "revid":     rev.get("revid"),
                "timestamp": rev.get("timestamp"),
                "user":      rev.get("user", ""),
                "comment":   rev.get("comment", ""),
                "size":      rev.get("size"),
            })

    return {
        "title":            page.get("title", title),
        "page_id":          page.get("pageid"),
        "content_length":   page.get("length"),
        "touched":          page.get("touched"),
        "last_rev_id":      page.get("lastrevid"),
        "revisions":        revs,
        "removal_signals":  removal_signals,
        "api_url":          api_url,
    }


# ── Date forensics ────────────────────────────────────────────────────────────

def extract_dates(source: str, headers: dict, url: str, parsed: SourceParser) -> dict:
    """Extract every date signal and cross-reference for inconsistencies."""
    signals: dict[str, object] = {}

    # HTTP response headers
    for hdr in ("Last-Modified", "Date", "Expires"):
        val = headers.get(hdr) or headers.get(hdr.lower())
        if val:
            signals[f"http_{hdr.lower().replace('-','_')}"] = val

    # <meta> date fields
    meta_date_keys = [
        "article:modified_time", "article:published_time",
        "og:updated_time",
        "dcterms.modified", "dcterms.created",
        "dc.date.modified", "dc.date.created", "dc.date",
        "date", "last-modified", "revised",
    ]
    for key in meta_date_keys:
        val = parsed.meta.get(key)
        if val:
            signals[f"meta_{re.sub(r'[:./-]','_',key)}"] = val

    # <time datetime=""> elements
    if parsed.times:
        signals["time_elements"] = parsed.times

    # Date embedded in URL path (e.g. /2023/06/14/)
    m = re.search(r"/(\d{4})/(\d{1,2})/(\d{1,2})/", url)
    if m:
        signals["url_path_date"] = f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"

    # HTML comments containing ISO dates
    dated_comments = [c for c in parsed.comments if re.search(r"\d{4}-\d{2}-\d{2}", c)]
    if dated_comments:
        signals["html_dated_comments"] = dated_comments[:5]

    # Cross-reference: HTTP Last-Modified year vs meta modified year
    inconsistencies: list[str] = []
    http_lm  = str(signals.get("http_last_modified", ""))
    meta_mod = str(
        signals.get("meta_article_modified_time") or
        signals.get("meta_dcterms_modified") or ""
    )
    if http_lm and meta_mod:
        hm = re.search(r"(\d{4})", http_lm)
        mm = re.search(r"^(\d{4})", meta_mod)
        if hm and mm and hm.group(1) != mm.group(1):
            inconsistencies.append(
                f"HTTP Last-Modified year ({hm.group(1)}) differs from "
                f"meta modified_time year ({mm.group(1)}) — possible backdating"
            )

    # Anachronism: old claimed pub date but post-2020 AI-era terminology present
    post_2020_terms = [
        "ChatGPT", "GPT-4", "large language model", "generative AI",
        "NFT", "Web3", "metaverse", "Stable Diffusion", "GPT-3",
    ]
    pub_str = str(
        signals.get("meta_article_published_time") or
        signals.get("meta_dcterms_created") or
        signals.get("meta_date") or ""
    )
    pub_match = re.search(r"\b(19\d{2}|200\d|201\d)\b", pub_str)
    if pub_match and int(pub_match.group(1)) < 2020:
        found = [t for t in post_2020_terms if t.lower() in source.lower()]
        if found:
            inconsistencies.append(
                f"Claimed publication year {pub_match.group(1)} predates "
                f"post-2020 AI-era terminology found in text: {found}"
            )

    return {
        "signals":         signals,
        "inconsistencies": inconsistencies,
        "backdating_risk": "HIGH" if inconsistencies else "LOW",
    }


# ── AI content heuristics ─────────────────────────────────────────────────────

def detect_ai_content(text_blocks: list[str], raw_html: str) -> dict:
    """Statistical + pattern-match AI content analysis (no external LLM needed)."""
    findings: list[dict] = []
    score = 0

    # 1. Sentence length uniformity — AI text has low StdDev (mechanical rhythm)
    sentences = re.split(r"(?<=[.!?])\s+", " ".join(text_blocks))
    sentences = [s for s in sentences if len(s.split()) >= 5]
    if len(sentences) >= 10:
        lengths = [len(s.split()) for s in sentences]
        avg = mean(lengths)
        try:
            sd = stdev(lengths)
        except Exception:
            sd = 99.0
        if sd < 5:
            score += 30
            findings.append({
                "type":   "sentence_uniformity",
                "risk":   "HIGH",
                "detail": f"Sentence length StdDev={sd:.2f} words (mean={avg:.1f}) — "
                          "extremely uniform rhythm; AI threshold < 5",
            })
        elif sd < 8:
            score += 12
            findings.append({
                "type":   "sentence_uniformity",
                "risk":   "MEDIUM",
                "detail": f"Sentence length StdDev={sd:.2f} words (mean={avg:.1f}) — "
                          "moderately uniform",
            })

    # 2. AI phrase pattern matches
    html_lower  = raw_html.lower()
    phrase_hits = []
    for pattern, label in AI_PHRASES:
        matches = re.findall(pattern, html_lower, re.IGNORECASE)
        if matches:
            phrase_hits.append({"pattern": label, "count": len(matches)})
            score += min(len(matches) * 3, 10)
    if phrase_hits:
        risk = "HIGH" if len(phrase_hits) >= 5 else "MEDIUM" if len(phrase_hits) >= 2 else "LOW"
        score += 5 * len(phrase_hits)
        findings.append({
            "type":   "ai_phrase_patterns",
            "risk":   risk,
            "detail": f"{len(phrase_hits)} AI-characteristic phrase pattern(s) detected",
            "hits":   phrase_hits,
        })

    # 3. Type-token ratio — low = limited vocabulary = AI-like
    all_words = re.findall(r"\b[a-z]{4,}\b", html_lower)
    if len(all_words) >= 200:
        ttr = len(set(all_words)) / len(all_words)
        if ttr < 0.22:
            score += 20
            findings.append({
                "type":   "vocabulary_diversity",
                "risk":   "HIGH",
                "detail": f"Type-token ratio={ttr:.4f} — very low lexical diversity (< 0.22)",
            })
        elif ttr < 0.30:
            score += 8
            findings.append({
                "type":   "vocabulary_diversity",
                "risk":   "MEDIUM",
                "detail": f"Type-token ratio={ttr:.4f} — below-average lexical diversity",
            })

    # 4. Paragraph structural uniformity
    if len(text_blocks) >= 5:
        para_lengths = [len(b.split()) for b in text_blocks]
        try:
            para_sd = stdev(para_lengths)
        except Exception:
            para_sd = 99.0
        if para_sd < 25:
            score += 8
            findings.append({
                "type":   "paragraph_uniformity",
                "risk":   "LOW",
                "detail": f"Paragraph StdDev={para_sd:.1f} words — "
                          "unusually consistent structure across all blocks",
            })

    risk_level = "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"
    return {
        "score":                min(score, 100),
        "risk_level":           risk_level,
        "findings":             findings,
        "sentences_analyzed":   len(sentences),
        "text_blocks_analyzed": len(text_blocks),
        "interpretation": (
            "Strong AI-generation signals detected"     if risk_level == "HIGH"   else
            "Moderate AI-generation indicators present" if risk_level == "MEDIUM" else
            "No significant AI-generation signals detected"
        ),
    }


# ── Missing / restricted artifacts ───────────────────────────────────────────

def document_artifacts(url: str, source: str, headers: dict,
                        robots: dict, parsed: SourceParser) -> dict:
    """Document what AI crawlers cannot see vs what is accessible."""
    missing: list[dict] = []
    present: list[dict] = []

    # Robots.txt AI blocks — content legally off-limits to these crawlers
    for bot, data in robots.get("ai_restrictions", {}).items():
        if data.get("blocked"):
            missing.append({
                "artifact":    "robots.txt block",
                "blocked_bot": bot,
                "description": data["description"],
                "rules":       data["rules"],
                "rule_source": data.get("rule_source", "explicit"),
                "note": (
                    f"{bot} is blocked from this domain via robots.txt. "
                    "This entire page is invisible to that AI crawler."
                ),
            })

    # <meta name="robots"> with AI/index directives
    meta_robots = (parsed.meta.get("robots") or "").lower()
    if any(d in meta_robots for d in ("noai", "noimageai", "noindex")):
        missing.append({
            "artifact":  "meta robots directive",
            "directive": parsed.meta.get("robots"),
            "note": "Publisher explicitly prohibits AI/indexing via <meta name='robots'>",
        })

    # X-Robots-Tag HTTP header
    x_robots = headers.get("X-Robots-Tag") or headers.get("x-robots-tag", "")
    if x_robots:
        if any(d in x_robots.lower() for d in ("noai", "noindex", "none")):
            missing.append({
                "artifact": "X-Robots-Tag restriction",
                "value":    x_robots,
                "note": "Server-level AI/index restriction in HTTP response header",
            })
        else:
            present.append({"artifact": "X-Robots-Tag", "value": x_robots})

    # JavaScript-only content — invisible to non-JS crawlers
    noscript_blocks = re.findall(r"<noscript>(.*?)</noscript>", source, re.DOTALL | re.IGNORECASE)
    if noscript_blocks:
        missing.append({
            "artifact": "JavaScript-only content blocks",
            "count":    len(noscript_blocks),
            "note": (
                f"{len(noscript_blocks)} <noscript> block(s) present. The page contains "
                "JavaScript-rendered content that non-JS AI crawlers cannot access. "
                "These sections may contain substantive material invisible to AI."
            ),
        })

    # Auth/paywall indicators
    auth_hits = re.findall(
        r"\b(login|sign.?in|subscribe|paywall|member.?only|access.?denied|premium)\b",
        source, re.IGNORECASE,
    )
    unique_auth = sorted(set(w.lower() for w in auth_hits))
    if len(unique_auth) >= 3:
        missing.append({
            "artifact": "potential auth/paywall gate",
            "signals":  unique_auth[:8],
            "note": "Multiple auth/paywall keyword signals — some content may require authentication",
        })

    # Canonical URL mismatch — AI may index wrong version
    if parsed.canonical and parsed.canonical.rstrip("/") != url.rstrip("/"):
        missing.append({
            "artifact":  "canonical URL mismatch",
            "fetched":   url,
            "canonical": parsed.canonical,
            "note": "Canonical URL differs from fetched URL — AI deduplication may index a different version",
        })

    # Document accessible artifacts
    if parsed.title:
        present.append({"artifact": "page_title",       "value": parsed.title.strip()})
    present.append(    {"artifact": "source_html_bytes","bytes": len(source)})
    present.append(    {"artifact": "html_comments",    "count": len(parsed.comments)})
    present.append(    {"artifact": "meta_tags",        "count": len(parsed.meta),
                        "keys": list(parsed.meta.keys())[:20]})
    present.append(    {"artifact": "time_elements",    "count": len(parsed.times),
                        "values": parsed.times[:10]})
    if parsed.canonical:
        present.append({"artifact": "canonical_url",   "value": parsed.canonical})

    return {
        "missing_artifacts": missing,
        "present_artifacts": present,
        "total_missing":     len(missing),
        "total_present":     len(present),
        "summary": (
            f"{len(missing)} restricted/missing artifact(s); "
            f"{len(present)} accessible artifact(s) documented"
        ),
    }


# ── Evidence persistence ──────────────────────────────────────────────────────

def save_evidence(
    domain: str, ts_file: str, url: str, ts: str,
    raw_bytes: bytes,
    headers_data: dict,
    robots_data: dict,
    revisions_data: dict | None,
    date_analysis: dict,
    ai_analysis: dict,
    artifacts: dict,
) -> Path:
    ev_dir = EVIDENCE / domain / ts_file
    ev_dir.mkdir(parents=True, exist_ok=True)

    # source.html — byte-for-byte, 100% unmodified
    source_path = ev_dir / "source.html"
    source_path.write_bytes(raw_bytes)

    (ev_dir / "headers.json").write_text(
        json.dumps(headers_data,  indent=2) + "\n", encoding="utf-8"
    )
    (ev_dir / "robots.json").write_text(
        json.dumps(robots_data,   indent=2) + "\n", encoding="utf-8"
    )
    if revisions_data:
        (ev_dir / "revisions.json").write_text(
            json.dumps(revisions_data, indent=2) + "\n", encoding="utf-8"
        )

    analysis = {
        "url":            url,
        "captured_at":    ts,
        "date_forensics": date_analysis,
        "ai_content":     ai_analysis,
        "artifacts":      artifacts,
    }
    analysis_path = ev_dir / "analysis.json"
    analysis_path.write_text(json.dumps(analysis, indent=2) + "\n", encoding="utf-8")

    # Assemble manifest
    manifest: dict = {
        "tool":         "forensic_fetch.py v1.0",
        "sec_ref":      "17684-273-411-436",
        "url":          url,
        "captured_at":  ts,
        "evidence_dir": str(ev_dir.relative_to(ROOT)),
        "artifacts": {
            "source.html":   {"sha256": _sha256_file(source_path),       "bytes": len(raw_bytes)},
            "headers.json":  {"sha256": _sha256_file(ev_dir / "headers.json")},
            "robots.json":   {"sha256": _sha256_file(ev_dir / "robots.json")},
            "analysis.json": {"sha256": _sha256_file(analysis_path)},
        },
        "summary": {
            "backdating_risk":  date_analysis["backdating_risk"],
            "ai_content_risk":  ai_analysis["risk_level"],
            "ai_content_score": ai_analysis["score"],
            "missing_count":    artifacts["total_missing"],
            "date_signals":     len(date_analysis["signals"]),
            "inconsistencies":  date_analysis["inconsistencies"],
        },
    }
    if revisions_data:
        manifest["artifacts"]["revisions.json"] = {
            "sha256": _sha256_file(ev_dir / "revisions.json")
        }

    # Self-sign: SHA256 of canonical JSON without manifest_sha256
    raw_json = json.dumps(manifest, separators=(",", ":"), sort_keys=True)
    manifest["manifest_sha256"] = _sha256(raw_json)

    manifest_path = ev_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return ev_dir


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    argv    = sys.argv[1:]
    dry_run = "--dry-run" in argv
    argv    = [a for a in argv if not a.startswith("--")]

    if not argv:
        print("Usage: python3 scripts/forensic_fetch.py <url>", file=sys.stderr)
        print("       python3 scripts/forensic_fetch.py "
              "https://en.wikipedia.org/wiki/Brutalist_architecture")
        return 1

    url        = argv[0]
    parsed_url = urllib.parse.urlparse(url)
    domain     = re.sub(r"^www\.", "", parsed_url.netloc)
    ts         = _now()
    ts_file    = ts.replace(":", "").replace("-", "")[:15]

    print(f"[forensic] url={url}")
    print(f"[forensic] domain={domain}  ts={ts}  dry_run={dry_run}")

    # 1. Fetch (lane-mcp gateway → direct HTTP fallback)
    print("[forensic] fetching source...")
    raw_bytes, headers, status = _lane_mcp_fetch(url)
    if not raw_bytes:
        raw_bytes, headers, status = _fetch(url)
    if not raw_bytes:
        print(f"[forensic] ERROR: fetch failed (HTTP {status})", file=sys.stderr)
        return 1
    source = raw_bytes.decode("utf-8", errors="replace")
    print(f"[forensic] {len(raw_bytes):,} bytes  HTTP {status}")

    # 2. Parse HTML
    parser = SourceParser()
    parser.feed(source)
    print(f"[forensic] {len(parser.text_blocks)} text blocks  "
          f"{len(parser.meta)} meta tags  {len(parser.comments)} comments")

    # 3. Robots.txt
    print("[forensic] checking robots.txt...")
    robots_data = fetch_robots(url)
    print(f"[forensic] {robots_data.get('ai_bots_blocked', 0)} AI bot(s) blocked by robots.txt")

    # 4. Revision history (Wikipedia API; extend for other CMS here)
    revisions_data = None
    if "wikipedia.org" in domain:
        print("[forensic] querying Wikipedia revision API...")
        revisions_data = fetch_wiki_revisions(url)
        if revisions_data and revisions_data.get("revisions"):
            rev0 = revisions_data["revisions"][0]
            print(f"[forensic] last edit: {rev0.get('timestamp')}  "
                  f"removal signals: {len(revisions_data.get('removal_signals', []))}")

    # 5. Date forensics
    print("[forensic] analyzing date signals...")
    date_analysis = extract_dates(source, headers, url, parser)
    if revisions_data:
        sigs = date_analysis["signals"]
        if revisions_data.get("revisions"):
            sigs["wikipedia_last_revision"] = revisions_data["revisions"][0].get("timestamp", "")
        if revisions_data.get("touched"):
            sigs["wikipedia_page_touched"] = revisions_data["touched"]
    print(f"[forensic] {len(date_analysis['signals'])} date signal(s)  "
          f"risk={date_analysis['backdating_risk']}  "
          f"inconsistencies={len(date_analysis['inconsistencies'])}")

    # 6. AI content heuristics
    print("[forensic] running AI content heuristics...")
    ai_analysis = detect_ai_content(parser.text_blocks, source)
    print(f"[forensic] AI score={ai_analysis['score']}/100  "
          f"risk={ai_analysis['risk_level']}  "
          f"findings={len(ai_analysis['findings'])}")

    # 7. Missing artifacts
    print("[forensic] documenting missing/restricted artifacts...")
    artifacts = document_artifacts(url, source, headers, robots_data, parser)
    print(f"[forensic] {artifacts['summary']}")

    if dry_run:
        report = {
            "url":            url,
            "date_forensics": date_analysis,
            "ai_content":     ai_analysis,
            "artifacts":      artifacts,
        }
        print("\n[forensic] --- DRY RUN (no files written) ---")
        print(json.dumps(report, indent=2, default=str)[:6000])
        return 0

    # 8. Save all evidence files + SHA256-signed manifest
    headers_data = {
        "url":         url,
        "captured_at": ts,
        "http_status": status,
        "headers":     headers,
    }
    ev_dir   = save_evidence(
        domain, ts_file, url, ts,
        raw_bytes, headers_data, robots_data, revisions_data,
        date_analysis, ai_analysis, artifacts,
    )
    manifest = json.loads((ev_dir / "manifest.json").read_text())

    src_sha  = manifest["artifacts"]["source.html"]["sha256"]
    mfst_sha = manifest["manifest_sha256"]

    print(f"\n[forensic] ╔══════════════════════════════════════════════════════╗")
    print(f"[forensic] ║  EVIDENCE SAVED                                      ║")
    print(f"[forensic] ╠══════════════════════════════════════════════════════╣")
    print(f"[forensic] ║  URL:               {url[:52]}")
    print(f"[forensic] ║  Captured:          {ts}")
    print(f"[forensic] ║  Source SHA256:     {src_sha[:52]}")
    print(f"[forensic] ║  Backdating risk:   {manifest['summary']['backdating_risk']}")
    print(f"[forensic] ║  AI content risk:   {manifest['summary']['ai_content_risk']} "
          f"(score={manifest['summary']['ai_content_score']}/100)")
    print(f"[forensic] ║  Missing artifacts: {manifest['summary']['missing_count']}")
    print(f"[forensic] ║  Manifest SHA256:   {mfst_sha[:52]}")
    print(f"[forensic] ║  Evidence dir:      {manifest['evidence_dir']}")
    print(f"[forensic] ╚══════════════════════════════════════════════════════╝")

    if manifest["summary"]["inconsistencies"]:
        print("\n[forensic] ⚠  BACKDATING INCONSISTENCIES FOUND:")
        for item in manifest["summary"]["inconsistencies"]:
            print(f"[forensic]   • {item}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
