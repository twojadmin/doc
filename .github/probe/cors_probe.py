import re, urllib.request, urllib.parse, urllib.error
O = "https://twojadmin.github.io"
FEEDS = ['https://cert.pl/rss.xml', 'https://cert.europa.eu/publications/security-advisories-rss', 'https://www.cert.ssi.gouv.fr/avis/feed/', 'https://www.cert.ssi.gouv.fr/alerte/feed/', 'https://wid.cert-bund.de/content/public/securityAdvisory/rss', 'https://advisories.ncsc.nl/rss/advisories', 'https://sekurak.pl/feed/', 'https://niebezpiecznik.pl/feed/', 'https://zaufanatrzeciastrona.pl/feed/', 'https://cyberdefence24.pl/rss', 'https://www.bleepingcomputer.com/feed/', 'https://feeds.feedburner.com/TheHackersNews', 'https://www.securityweek.com/feed/', 'https://therecord.media/feed', 'https://www.helpnetsecurity.com/feed/', 'https://krebsonsecurity.com/feed/', 'https://isc.sans.edu/rssfeed_full.xml']
def get(u):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, headers={"Origin": O, "User-Agent": "security-news-probe"}), timeout=12)
        return r.status, dict((k.lower(), v) for k, v in r.headers.items()), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict((k.lower(), v) for k, v in e.headers.items()), ""
    except Exception as e:
        return "ERR " + repr(e)[:60], {}, ""
def items(b): return len(re.findall(r"<item[ >]|<entry[ >]", b))
from concurrent.futures import ThreadPoolExecutor, wait
def one(u):
    q = urllib.parse.quote(u, safe="")
    res = []
    for name, url in (("direct", u), ("allorigins", "https://api.allorigins.win/raw?url=" + q), ("corsproxy", "https://corsproxy.io/?url=" + q), ("codetabs", "https://api.codetabs.com/v1/proxy/?quest=" + q)):
        with ThreadPoolExecutor(1) as ex:
            f = ex.submit(get, url)
            done, _ = wait([f], timeout=15)
            st, h, b = f.result() if done else ("TIMEOUT", {}, "")
        res.append(f"{name}={st}/acao={h.get('access-control-allow-origin','-')}/items={items(b)}")
    return u + " | " + " | ".join(res)
with ThreadPoolExecutor(17) as ex:
    for line in ex.map(one, FEEDS):
        print(line, flush=True)
for u in ("https://euvd.enisa.europa.eu/vulnerability/CVE-2024-3400", "https://euvd.enisa.europa.eu/search?text=tomcat"):
    st, h, b = get(u)
    m = re.search(r"<title>([^<]*)", b)
    print(u, st, m.group(1) if m else "")
