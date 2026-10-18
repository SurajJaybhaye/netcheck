#!/usr/bin/env python3
"""netcheck: DNS, TCP, TLS and HTTP health checker for a list of domains.

Emits one JSON line per domain (easy to ship to logs/metrics) and exits
non-zero if any check fails, so it works from cron or a systemd timer.
Standard library only; TTL/CNAME are read if `dnspython` is installed.
"""
import argparse, json, socket, ssl, sys, time, http.client
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:
    import dns.resolver  # optional
except ImportError:
    dns = None


def check_dns(host):
    t = time.perf_counter()
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    out = {"ms": round((time.perf_counter() - t) * 1000, 1),
           "addresses": sorted({i[4][0] for i in infos})}
    if dns:
        try:
            ans = dns.resolver.resolve(host, "A")
            out["ttl"] = ans.rrset.ttl
            if ans.canonical_name.to_text().rstrip(".") != host:
                out["cname"] = ans.canonical_name.to_text().rstrip(".")
        except Exception:
            pass
    return out


def check_tcp(host, port, timeout):
    t = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout):
        return {"connect_ms": round((time.perf_counter() - t) * 1000, 1)}


def check_tls(host, port, timeout, verify=True):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            cert = s.getpeercert()
            out = {"version": s.version(), "cipher": s.cipher()[0]}
            if not cert:
                out["note"] = "cert details unavailable (verification disabled)"
            else:
                exp = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
                out["expires"] = exp.date().isoformat()
                out["days_left"] = (exp - datetime.now(timezone.utc)).days
            return out


def check_http(host, port, timeout, tls, verify=True):
    if tls:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    t = time.perf_counter()
    conn.request("HEAD", "/", headers={"User-Agent": "netcheck/1.0"})
    r = conn.getresponse()
    out = {"status": r.status, "ms": round((time.perf_counter() - t) * 1000, 1)}
    conn.close()
    return out


def run_checks(target, args):
    host, _, p = target.partition(":")
    port = int(p) if p else args.port
    tls = port != 80
    res = {"host": host, "port": port,
           "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "ok": True, "errors": []}
    steps = [("dns", lambda: check_dns(host)),
             ("tcp", lambda: check_tcp(host, port, args.timeout))]
    if tls:
        steps.append(("tls", lambda: check_tls(host, port, args.timeout, not args.insecure)))
    steps.append(("http", lambda: check_http(host, port, args.timeout, tls, not args.insecure)))
    for name, fn in steps:
        try:
            res[name] = fn()
        except Exception as e:
            res[name] = None
            res["errors"].append(f"{name}: {type(e).__name__}: {e}")
            res["ok"] = False
            break  # later layers depend on earlier ones
    d = (res.get("tls") or {}).get("days_left")
    if d is not None and d < args.warn_days:
        res["errors"].append(f"tls: certificate expires in {d} days")
        res["ok"] = False
    st = (res.get("http") or {}).get("status")
    if st is not None and st >= 400:
        res["errors"].append(f"http: status {st}")
        res["ok"] = False
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("domains", nargs="*", help="host or host:port")
    ap.add_argument("-f", "--file", help="file with one domain per line")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--warn-days", type=int, default=14,
                    help="fail if TLS cert expires sooner than this")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--insecure", action="store_true",
                    help="skip certificate verification")
    args = ap.parse_args()
    targets = list(args.domains)
    if args.file:
        with open(args.file) as f:
            targets += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not targets:
        ap.error("no domains given")
    with ThreadPoolExecutor(args.workers) as ex:
        results = list(ex.map(lambda t: run_checks(t, args), targets))
    for r in results:
        print(json.dumps(r))
    failed = sum(not r["ok"] for r in results)
    print(json.dumps({"summary": {"checked": len(results), "failed": failed}}),
          file=sys.stderr)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
