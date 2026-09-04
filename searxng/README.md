# SearXNG backend

Self-hosted metasearch for the `search` OSINT module. See
[`../docs/GUIDE.md`](../docs/GUIDE.md) §7 for the full rationale.

## Start

```bash
cd searxng
# set a real secret key first:
sed -i "s/CHANGE-ME.*/$(openssl rand -hex 32)/" config/settings.yml
docker compose up -d
```

Then in the project `.env`:

```
RECON_SEARCH_BACKEND=searxng
RECON_SEARXNG_URL=http://127.0.0.1:8888
```

## Verify

```bash
curl -s 'http://127.0.0.1:8888/search?q=site:github.com+fastapi&format=json' \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d["results"]),"via",sorted({r["engine"] for r in d["results"]}))'
```

~15–20 results via `['bing', 'qwant']`. Empty with `unresponsive_engines` full of
"CAPTCHA" / "too many requests" → the engines are throttling this IP; wait it out
or enable another tolerant engine in `config/settings.yml` (then
`docker compose restart`).

## Notes

- `config/settings.yml` is tracked; everything else SearXNG writes into
  `config/` is gitignored.
- Bound to `127.0.0.1` only. Do not expose it.
- Changing the published port: edit `docker-compose.yml`, then
  `docker compose up -d --force-recreate`.
