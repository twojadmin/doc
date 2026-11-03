/**
 * Własny pośrednik CORS dla strony „Przegląd bezpieczeństwa” (Cloudflare Workers, plan darmowy).
 *
 * Przepuszcza WYŁĄCZNIE kanały RSS z listy ALLOWED i tylko dla strony z ALLOWED_ORIGINS,
 * więc nie da się go użyć jako otwartego pośrednika do czegokolwiek innego.
 * Odpowiedzi są buforowane przez 15 minut (mniej zapytań do serwisów źródłowych).
 *
 * Uruchomienie (jednorazowo):
 *   1. https://dash.cloudflare.com → Workers & Pages → Create → Worker → nazwa np. "security-news".
 *   2. Edit code → wklej ten plik → Deploy.
 *   3. Skopiuj adres (np. https://security-news.twoja-nazwa.workers.dev) do stałej OWN_PROXY w index.html.
 */
const ALLOWED_ORIGINS = ["https://twojadmin.github.io"];
const ALLOWED = new Set([
  "https://cert.pl/rss.xml",
  "https://cert.europa.eu/publications/security-advisories-rss",
  "https://www.cert.ssi.gouv.fr/avis/feed/",
  "https://www.cert.ssi.gouv.fr/alerte/feed/",
  "https://wid.cert-bund.de/content/public/securityAdvisory/rss",
  "https://advisories.ncsc.nl/rss/advisories",
  "https://sekurak.pl/feed/",
  "https://niebezpiecznik.pl/feed/",
  "https://zaufanatrzeciastrona.pl/feed/",
  "https://cyberdefence24.pl/rss",
  "https://www.bleepingcomputer.com/feed/",
  "https://feeds.feedburner.com/TheHackersNews",
  "https://www.securityweek.com/feed/",
  "https://therecord.media/feed",
  "https://www.helpnetsecurity.com/feed/",
  "https://krebsonsecurity.com/feed/",
  "https://isc.sans.edu/rssfeed_full.xml",
]);

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "";
    const allowOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
    const cors = { "Access-Control-Allow-Origin": allowOrigin, "Vary": "Origin" };
    if (request.method === "OPTIONS") return new Response(null, { headers: { ...cors, "Access-Control-Allow-Methods": "GET" } });
    if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: cors });

    const target = new URL(request.url).searchParams.get("url") || "";
    if (!ALLOWED.has(target)) return new Response("Forbidden", { status: 403, headers: cors });

    const cache = caches.default;
    const key = new Request("https://cache.local/?url=" + encodeURIComponent(target));
    let res = await cache.match(key);
    if (!res) {
      const upstream = await fetch(target, { headers: { "User-Agent": "security-news-proxy (+https://twojadmin.github.io/doc/)" } });
      if (!upstream.ok) return new Response("Upstream error " + upstream.status, { status: 502, headers: cors });
      res = new Response(await upstream.text(), {
        headers: { "Content-Type": upstream.headers.get("Content-Type") || "application/xml; charset=utf-8", "Cache-Control": "public, max-age=900" },
      });
      ctx.waitUntil(cache.put(key, res.clone()));
    }
    const out = new Response(res.body, res);
    Object.entries(cors).forEach(([k, v]) => out.headers.set(k, v));
    return out;
  },
};
