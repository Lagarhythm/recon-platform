"""Web crawler (passive content discovery).

BFS-crawls in-scope web hosts starting from known URLs and host roots. Stays on
the host it started on: a link to a *different* host is recorded as a ``url``
finding but not followed by this pass. Emits discovered URLs, forms, script
sources, distinct query-parameter names, and the contents of ``robots.txt`` /
``sitemap.xml`` for downstream modules (``js_analyzer`` consumes ``js_file``).
"""

from __future__ import annotations

import re
from collections import deque
from urllib.parse import parse_qs, urldefrag, urljoin, urlsplit

from bs4 import BeautifulSoup

from recon.models.enums import ModulePhase
from recon.modules._live_hosts import probed_hosts
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.http_client import ReconRequestError, ScopeViolation

MAX_PAGES = 150
MAX_DEPTH = 4
MAX_PAGES_PER_HOST = 40
MAX_SITEMAP_LOCS = 50

_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
_SKIP_SCHEMES = {"mailto", "tel", "javascript", "data", "ftp", "file", "about"}


def _norm_url(url: str) -> str:
    """Strip the fragment; leave everything else intact."""
    clean, _ = urldefrag(url.strip())
    return clean


def _host_of(url: str) -> str | None:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return None
    return host or None


def _is_http(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))


@register
class CrawlerModule(ReconModule):
    name = "crawler"
    phase = ModulePhase.PASSIVE
    depends_on = ("http_analyzer", "probe_http")
    description = "BFS-crawl in-scope web hosts for URLs, forms, scripts, robots/sitemap"

    async def run(self, ctx: ModuleContext) -> None:
        seeds: list[str] = []
        seen_seed: set[str] = set()

        def _add_seed(raw: str) -> None:
            n = _norm_url(raw)
            if n and _is_http(n) and _host_of(n) and n not in seen_seed:
                seen_seed.add(n)
                seeds.append(n)

        for u in await ctx.known_values("url"):
            _add_seed(u)

        hosts: set[str] = {
            h.strip().lower().rstrip(".")
            for h in await ctx.known_values("subdomain", "domain")
            if h and h.strip()
        }
        hosts.update(h.strip().lower().rstrip(".") for h in ctx.roe.scope.in_scope.hosts)
        # If probe_http ran, it already told us which hosts answer HTTP - those
        # are seeded above via their `url` evidence, and a host it probed but
        # that stayed silent is dead, so skip the speculative scheme guesses for
        # it. Hosts probe_http never saw (or a scan without probe_http) still get
        # both-scheme guesses - the fallback path.
        live_checked = await probed_hosts(ctx)
        # Seed both schemes: an internal service may serve only HTTP. The dead
        # scheme costs one fast connection error, not a 15s-per-request stall
        # (which is what hard-coding https:// here used to cause on a LAN).
        for h in sorted(hosts):
            if h and h not in live_checked:
                _add_seed(f"https://{h}/")
                _add_seed(f"http://{h}/")

        if not seeds:
            await ctx.progress("crawler: no seed URLs or in-scope hosts")
            return

        queue: deque[tuple[str, int]] = deque((s, 0) for s in seeds)
        visited: set[str] = set()
        per_host: dict[str, int] = {}
        meta_done: set[str] = set()
        #: hosts we've already fetched a root page for - a second seed for the
        #: same host on the other scheme is redundant (redirects are followed).
        rooted_hosts: set[str] = set()
        params_by_host: dict[str, set[str]] = {}
        emitted_urls: set[tuple[str, str]] = set()
        emitted_js: set[tuple[str, str]] = set()
        pages = 0

        await ctx.progress(f"crawler: {len(seeds)} seed(s)", count=len(seeds))

        while queue and pages < MAX_PAGES:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            host = _host_of(url)
            if host is None:
                continue

            ctx.check_alive()

            # A depth-0 seed for a host we've already rooted (on the other
            # scheme) adds nothing - skip it before spending a request.
            if depth == 0 and host in rooted_hosts:
                continue

            if per_host.get(host, 0) >= MAX_PAGES_PER_HOST:
                continue

            try:
                resp = await ctx.http.get(url, follow_redirects=True)
            except (ScopeViolation, ReconRequestError) as exc:
                await ctx.add_error(
                    subject_value=url,
                    summary=f"crawl fetch failed: {type(exc).__name__}",
                    raw_data={"url": url, "error": str(exc)},
                )
                continue

            if depth == 0:
                rooted_hosts.add(host)

            # robots.txt / sitemap.xml, once per host, on the scheme that just
            # worked (final URL after any redirects).
            if host not in meta_done:
                meta_done.add(host)
                try:
                    final_url = str(resp.url)
                except Exception:  # noqa: BLE001 - fake/edge responses lack a request
                    final_url = url
                scheme = urlsplit(final_url).scheme or urlsplit(url).scheme or "https"
                await self._host_meta(ctx, scheme, host, params_by_host)

            pages += 1
            per_host[host] = per_host.get(host, 0) + 1
            ct = resp.headers.get("content-type", "") or ""
            status = resp.status_code

            self._collect_params(url, params_by_host)
            await ctx.add_evidence(
                subject_type="url",
                subject_value=url,
                raw_data={"status": status, "content_type": ct, "depth": depth},
                summary=f"crawled {url} ({status})",
            )

            if pages == 1 or pages % 5 == 0:
                # estimate: pages done + still queued, capped at the hard limit
                est_total = min(MAX_PAGES, pages + len(queue)) or 1
                await ctx.progress(
                    f"crawled {pages} page(s)", current=pages, total=est_total
                )

            if "text/html" not in ct.lower():
                continue

            try:
                soup = BeautifulSoup(resp.text, "html.parser")
            except Exception as exc:  # noqa: BLE001 - never let a parse error abort the crawl
                await ctx.add_error(
                    subject_value=url,
                    summary=f"crawl parse failed: {type(exc).__name__}",
                    raw_data={"url": url, "error": str(exc)},
                )
                continue

            await self._parse_page(
                ctx,
                page_url=url,
                page_host=host,
                depth=depth,
                soup=soup,
                queue=queue,
                visited=visited,
                params_by_host=params_by_host,
                emitted_urls=emitted_urls,
                emitted_js=emitted_js,
            )

        await ctx.progress(
            f"crawler done: {pages} page(s)", current=pages, total=pages or 1
        )

        for h, names in sorted(params_by_host.items()):
            if not names:
                continue
            ctx.check_alive()
            await ctx.add_evidence(
                subject_type="param_names",
                subject_value=h,
                raw_data={"host": h, "params": sorted(names)},
                summary=f"{len(names)} distinct query param name(s) on {h}",
            )

    # -- helpers -------------------------------------------------------

    def _collect_params(self, url: str, params_by_host: dict[str, set[str]]) -> None:
        host = _host_of(url)
        if not host:
            return
        query = urlsplit(url).query
        if not query:
            return
        for name in parse_qs(query, keep_blank_values=True):
            params_by_host.setdefault(host, set()).add(name)

    async def _parse_page(
        self,
        ctx: ModuleContext,
        *,
        page_url: str,
        page_host: str,
        depth: int,
        soup: BeautifulSoup,
        queue: deque[tuple[str, int]],
        visited: set[str],
        params_by_host: dict[str, set[str]],
        emitted_urls: set[tuple[str, str]],
        emitted_js: set[tuple[str, str]],
    ) -> None:
        # --- links ---------------------------------------------------
        for anchor in soup.find_all("a", href=True):
            ctx.check_alive()
            href = (anchor["href"] or "").strip()
            if not href:
                continue
            if urlsplit(href).scheme.lower() in _SKIP_SCHEMES:
                continue
            resolved = _norm_url(urljoin(page_url, href))
            if not _is_http(resolved):
                continue
            link_host = _host_of(resolved)
            if link_host is None:
                continue

            self._collect_params(resolved, params_by_host)
            key = (resolved, page_url)
            if key not in emitted_urls:
                emitted_urls.add(key)
                await ctx.add_evidence(
                    subject_type="url",
                    subject_value=resolved,
                    raw_data={"discovered_on": page_url},
                    summary=f"link to {resolved}",
                )

            if (
                link_host == page_host
                and depth < MAX_DEPTH
                and resolved not in visited
                and ctx.scope.classify(resolved).is_in_scope
            ):
                queue.append((resolved, depth + 1))

        # --- forms -------------------------------------------------
        for form in soup.find_all("form"):
            ctx.check_alive()
            action = (form.get("action") or "").strip()
            resolved_action = _norm_url(urljoin(page_url, action)) if action else page_url
            method = (form.get("method") or "GET").strip().upper() or "GET"
            inputs = [
                {"name": el.get("name"), "type": (el.get("type") or el.name)}
                for el in form.find_all(["input", "textarea", "select"])
            ]
            await ctx.add_evidence(
                subject_type="form",
                subject_value=resolved_action,
                raw_data={
                    "url": page_url,
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                },
                summary=f"{method} form on {page_url} -> {resolved_action}",
            )

        # --- script src -------------------------------------------
        for script in soup.find_all("script", src=True):
            ctx.check_alive()
            src = (script["src"] or "").strip()
            if not src:
                continue
            js_url = _norm_url(urljoin(page_url, src))
            if not _is_http(js_url):
                continue
            key = (js_url, page_url)
            if key in emitted_js:
                continue
            emitted_js.add(key)
            await ctx.add_evidence(
                subject_type="js_file",
                subject_value=js_url,
                raw_data={"url": js_url, "discovered_on": page_url},
                summary=f"script {js_url}",
            )

        # --- <link> stylesheets / icons: counted only (optional) ---
        stylesheet_count = len(soup.find_all("link", href=True))
        if stylesheet_count:
            await ctx.progress(
                f"{page_url}: {stylesheet_count} <link> ref(s)", count=stylesheet_count
            )

    async def _host_meta(
        self,
        ctx: ModuleContext,
        scheme: str,
        host: str,
        params_by_host: dict[str, set[str]],
    ) -> None:
        # Use the scheme we actually reached this host on - not a hard-coded
        # https:// that dead-ends (and trips the backoff) on HTTP-only hosts.
        base = f"{scheme}://{host}/"
        await self._robots(ctx, host, base, params_by_host)
        await self._sitemap(ctx, host, base, params_by_host)

    async def _robots(
        self,
        ctx: ModuleContext,
        host: str,
        base: str,
        params_by_host: dict[str, set[str]],
    ) -> None:
        robots_url = urljoin(base, "/robots.txt")
        try:
            resp = await ctx.http.get(robots_url, follow_redirects=True)
        except (ScopeViolation, ReconRequestError) as exc:
            await ctx.add_error(
                subject_value=robots_url,
                summary=f"robots.txt fetch failed: {type(exc).__name__}",
                raw_data={"host": host, "url": robots_url, "error": str(exc)},
            )
            return
        if resp.status_code != 200:
            return

        disallow: list[str] = []
        sitemaps: list[str] = []
        for raw_line in (resp.text or "").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            field, _, value = line.partition(":")
            field = field.strip().lower()
            value = value.strip()
            if not value:
                continue
            if field == "disallow":
                disallow.append(value)
            elif field == "sitemap":
                sitemaps.append(value)

        await ctx.add_evidence(
            subject_type="robots",
            subject_value=host,
            raw_data={
                "host": host,
                "url": robots_url,
                "disallow": disallow,
                "sitemaps": sitemaps,
            },
            summary=(
                f"robots.txt for {host}: {len(disallow)} Disallow, "
                f"{len(sitemaps)} Sitemap"
            ),
        )
        for path in disallow:
            ctx.check_alive()
            target = _norm_url(urljoin(base, path))
            if not _is_http(target):
                continue
            self._collect_params(target, params_by_host)
            await ctx.add_evidence(
                subject_type="url",
                subject_value=target,
                raw_data={"source": "robots", "interest": "notable"},
                summary=f"robots Disallow on {host}: {path}",
            )

    async def _sitemap(
        self,
        ctx: ModuleContext,
        host: str,
        base: str,
        params_by_host: dict[str, set[str]],
    ) -> None:
        sitemap_url = urljoin(base, "/sitemap.xml")
        try:
            resp = await ctx.http.get(sitemap_url, follow_redirects=True)
        except (ScopeViolation, ReconRequestError) as exc:
            await ctx.add_error(
                subject_value=sitemap_url,
                summary=f"sitemap.xml fetch failed: {type(exc).__name__}",
                raw_data={"host": host, "url": sitemap_url, "error": str(exc)},
            )
            return
        if resp.status_code != 200:
            return

        locs = [m.strip() for m in _LOC_RE.findall(resp.text or "") if m.strip()]
        await ctx.add_evidence(
            subject_type="sitemap",
            subject_value=host,
            raw_data={"host": host, "url": sitemap_url, "loc_count": len(locs)},
            summary=f"sitemap.xml for {host}: {len(locs)} loc(s)",
        )
        for loc in locs[:MAX_SITEMAP_LOCS]:
            ctx.check_alive()
            target = _norm_url(loc)
            if not _is_http(target):
                continue
            self._collect_params(target, params_by_host)
            await ctx.add_evidence(
                subject_type="url",
                subject_value=target,
                raw_data={"source": "sitemap", "discovered_on": sitemap_url},
                summary=f"sitemap loc: {target}",
            )
