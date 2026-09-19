# dmarc-report-parser

Read DMARC aggregate reports and answer the question you actually have: **is it
safe to move this domain off `p=none`?**

Receivers send aggregate reports as XML, gzipped, attached to an email. The XML
is technically readable and practically not, so most domains publish `p=none`,
collect reports for a year, never open one, and stay at `p=none` forever.

This reads whatever you point it at — a `.xml`, a `.gz`, a `.zip`, a raw
`.eml`, or an entire Maildir — and tells you who is sending as your domain,
whether it aligned, and what that means for enforcement.

## Install

None. Python 3.6+, standard library only. No dependencies, no network access,
no telemetry — it reads local files and prints to stdout.

```
curl -O https://raw.githubusercontent.com/coldemailtool/dmarc-report-parser/main/dmarc_report.py
chmod +x dmarc_report.py
```

## Use

```bash
# a single report
./dmarc_report.py report.xml.gz

# the mailbox your rua= address delivers to
./dmarc_report.py ~/Maildir/new ~/Maildir/cur

# a folder of saved reports, as JSON
./dmarc_report.py reports/ --json
```

## Output

```
Domain        : example.com
Published p=  : none
Reporters     : google.com
Reports read  : 3  (13 messages)

SOURCE IP        ALIGNED  FAILING  HEADER FROM
203.0.113.199          0        1  mail-1.example.com
                 why: SPF none; no DKIM signature
203.0.113.10          12        0  example.com

Aligned: 12 of 13 (92.3%)

VERDICT: 1 message(s) did not align. Identify each source above
         before enforcing, or you will quarantine your own mail.
         A subdomain in HEADER FROM can be spared with sp=none.
```

That last line is the point. A failure on a *subdomain* is a different problem
from a failure on the organizational domain: subdomains inherit the
organizational policy unless you publish an `sp=` tag, so you can enforce the
brand domain and leave a stray subdomain at monitoring while you deal with it.

## What it handles

- Reports as `.xml`, `.gz`, `.zip`, or attached to `.eml` / Maildir messages
- **Deduplication by `report_id`** — the same report commonly arrives twice
- Both alignment results per row, plus the underlying `auth_results`, so a
  `dkim=pass` that aligned to the *wrong* domain is reported as a failure
- Directories walked recursively, with Dovecot index files skipped

## What it does not do

- It does not fetch anything. Point it at files you already have.
- It does not parse forensic (`ruf`) reports, only aggregate (`rua`).
- It cannot see mail nobody reported on. A verdict of "safe to enforce" is only
  as good as your sample — a few days from one reporter is thin.

## Reading the verdict honestly

DMARC enforcement fails people in one specific way: they enforce on a sample
that did not include a legitimate sender. Before you move to `p=quarantine`,
make sure the reports you are reading actually cover every stream that puts
your domain in the From header — your app, your invoicing, your helpdesk, your
newsletter, and anything a vendor sends on your behalf.

## Related

- [spf-audit](https://github.com/coldemailtool/spf-audit) — counts every
  `v=spf1` record and walks the whole include tree for the ten-lookup limit
- [Free SPF, DKIM and DMARC checker](https://emailcampaign.ai/tools/dns-checker)
  — the same checks against live DNS, in a browser

## Licence

MIT. See [LICENSE](LICENSE).
