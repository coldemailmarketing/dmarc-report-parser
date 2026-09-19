#!/usr/bin/env python3
"""Read DMARC aggregate reports and answer the question you actually have:
is it safe to move this domain off p=none?

Receivers send aggregate reports as XML, usually gzipped inside an email.
The XML is technically readable and practically not. This reads whatever you
point it at -- a .xml, a .gz, a .zip, a raw .eml, or a whole Maildir -- and
prints who is sending as your domain, whether it aligned, and what that means
for enforcement.

Usage:
    dmarc_report.py report.xml.gz
    dmarc_report.py ~/Maildir/new
    dmarc_report.py reports/ --json

MIT licensed. No network access, no telemetry: it only reads local files.
"""

import argparse
import email
import gzip
import io
import json
import os
import sys
import zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict

LOOKUP_SUFFIXES = (".xml", ".gz", ".zip", ".eml")


def _iter_candidate_files(path):
    """Yield every file worth trying under path (a file or a directory)."""
    if os.path.isfile(path):
        yield path
        return
    for root, _dirs, names in os.walk(path):
        for name in names:
            # Dovecot/Maildir index files are not reports.
            if name.startswith("dovecot"):
                continue
            yield os.path.join(root, name)


def _xml_blobs(path):
    """Yield raw report XML from a file, unwrapping mail and compression."""
    with open(path, "rb") as fh:
        raw = fh.read()

    # A bare, possibly compressed, report.
    for opener in (_maybe_gzip, _maybe_zip, _maybe_xml):
        blob = opener(raw)
        if blob is not None:
            yield blob
            return

    # Otherwise treat it as an email and look at the attachments.
    try:
        msg = email.message_from_bytes(raw)
    except Exception:
        return
    for part in msg.walk():
        name = (part.get_filename() or "").lower()
        if not name.endswith(LOOKUP_SUFFIXES):
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if payload is None:
            continue
        for opener in (_maybe_gzip, _maybe_zip, _maybe_xml):
            blob = opener(payload)
            if blob is not None:
                yield blob
                break


def _maybe_gzip(raw):
    if raw[:2] != b"\x1f\x8b":
        return None
    try:
        return gzip.decompress(raw)
    except Exception:
        return None


def _maybe_zip(raw):
    if raw[:2] != b"PK":
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        names = zf.namelist()
        return zf.read(names[0]) if names else None
    except Exception:
        return None


def _maybe_xml(raw):
    head = raw.lstrip()[:200].lower()
    if head.startswith(b"<?xml") or b"<feedback" in head:
        return raw
    return None


def parse_report(xml_bytes):
    """Turn one aggregate report into a dict, or None if it is not one."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None
    if root.tag != "feedback":
        return None

    meta = root.find("report_metadata")
    published = root.find("policy_published")
    if meta is None or published is None:
        return None

    rows = []
    for rec in root.findall("record"):
        row = rec.find("row")
        if row is None:
            continue
        evaluated = row.find("policy_evaluated")
        ids = rec.find("identifiers")
        auth = rec.find("auth_results")

        dkim_eval = evaluated.findtext("dkim") if evaluated is not None else None
        spf_eval = evaluated.findtext("spf") if evaluated is not None else None

        rows.append({
            "source_ip": row.findtext("source_ip"),
            "count": int(row.findtext("count") or 0),
            "header_from": ids.findtext("header_from") if ids is not None else None,
            "dkim_aligned": dkim_eval == "pass",
            "spf_aligned": spf_eval == "pass",
            "disposition": evaluated.findtext("disposition") if evaluated is not None else None,
            "dkim_auth": [
                {"domain": d.findtext("domain"), "result": d.findtext("result")}
                for d in (auth.findall("dkim") if auth is not None else [])
            ],
            "spf_auth": [
                {"domain": s.findtext("domain"), "result": s.findtext("result")}
                for s in (auth.findall("spf") if auth is not None else [])
            ],
        })

    return {
        "report_id": meta.findtext("report_id"),
        "org_name": meta.findtext("org_name"),
        "policy": {
            "domain": published.findtext("domain"),
            "p": published.findtext("p"),
            "sp": published.findtext("sp"),
            "pct": published.findtext("pct"),
            "adkim": published.findtext("adkim") or "r",
            "aspf": published.findtext("aspf") or "r",
        },
        "rows": rows,
    }


def collect(paths):
    reports, seen = [], set()
    for path in paths:
        for candidate in _iter_candidate_files(path):
            for blob in _xml_blobs(candidate):
                report = parse_report(blob)
                if report is None:
                    continue
                rid = report["report_id"]
                if rid and rid in seen:
                    continue  # the same report often arrives twice
                if rid:
                    seen.add(rid)
                reports.append(report)
    return reports


def summarise(reports):
    by_source = defaultdict(lambda: {"pass": 0, "fail": 0, "from": set(), "why": set()})
    total = passed = 0

    for report in reports:
        for row in report["rows"]:
            n = row["count"]
            total += n
            aligned = row["dkim_aligned"] or row["spf_aligned"]
            key = row["source_ip"]
            by_source[key]["from"].add(row["header_from"] or "?")
            if aligned:
                passed += n
                by_source[key]["pass"] += n
            else:
                by_source[key]["fail"] += n
                if not row["dkim_auth"]:
                    by_source[key]["why"].add("no DKIM signature")
                else:
                    for d in row["dkim_auth"]:
                        if d["result"] != "pass":
                            by_source[key]["why"].add("DKIM %s" % d["result"])
                for s in row["spf_auth"]:
                    if s["result"] not in ("pass",):
                        by_source[key]["why"].add("SPF %s" % (s["result"] or "none"))
    return total, passed, by_source


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+", help="report files, .eml files, or directories")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    reports = collect(args.paths)
    if not reports:
        print("No DMARC aggregate reports found in: %s" % ", ".join(args.paths),
              file=sys.stderr)
        return 2

    total, passed, by_source = summarise(reports)

    if args.json:
        print(json.dumps({
            "reports": len(reports),
            "messages": total,
            "aligned": passed,
            "failing": total - passed,
            "sources": {
                ip: {"pass": v["pass"], "fail": v["fail"],
                     "header_from": sorted(v["from"]), "reasons": sorted(v["why"])}
                for ip, v in by_source.items()
            },
        }, indent=2))
        return 0

    policies = {r["policy"]["p"] for r in reports if r["policy"]["p"]}
    domains = {r["policy"]["domain"] for r in reports if r["policy"]["domain"]}
    orgs = sorted({r["org_name"] for r in reports if r["org_name"]})

    print("Domain        : %s" % ", ".join(sorted(domains)))
    print("Published p=  : %s" % ", ".join(sorted(policies)))
    print("Reporters     : %s" % ", ".join(orgs))
    print("Reports read  : %d  (%d messages)" % (len(reports), total))
    print()

    width = max((len(ip) for ip in by_source), default=15)
    print("%-*s  %7s  %7s  %s" % (width, "SOURCE IP", "ALIGNED", "FAILING", "HEADER FROM"))
    for ip, v in sorted(by_source.items(), key=lambda kv: -kv[1]["fail"]):
        print("%-*s  %7d  %7d  %s" % (width, ip, v["pass"], v["fail"],
                                      ", ".join(sorted(v["from"]))))
        if v["why"]:
            print("%-*s  %s" % (width, "", "why: " + "; ".join(sorted(v["why"]))))

    print()
    failing = total - passed
    pct = (passed / total * 100) if total else 0.0
    print("Aligned: %d of %d (%.1f%%)" % (passed, total, pct))

    if failing == 0:
        print("\nVERDICT: every reported message aligned. Moving off p=none is safe")
        print("         on this evidence. Check you have enough of it first --")
        print("         a few days from one reporter is a thin sample.")
    else:
        print("\nVERDICT: %d message(s) did not align. Identify each source above" % failing)
        print("         before enforcing, or you will quarantine your own mail.")
        print("         A subdomain in HEADER FROM can be spared with sp=none.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
