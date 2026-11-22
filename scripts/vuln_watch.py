#!/usr/bin/env python3
"""Watch official feeds and publish factual alert pages for exploited / critical
vulnerabilities in the stacks errorbudget covers.

Sources:
  - CISA Known Exploited Vulnerabilities (KEV) catalog  -> confirmed exploitation
  - GitHub reviewed security advisories, severity critical, ecosystems maven + composer

Alert pages contain only facts copied from those official sources plus links.
A reviewed, full fix guide replaces the alert later (status: guide).

Writes new/updated files under FIXES_DIR (default src/content/fixes/) and prints their file
names, one per line, prefixed with NEW or UPDATED. State lives in STATE_FILE.

Env: GITHUB_TOKEN (raises the advisories API rate limit), DRY_RUN=1, MAX_NEW (default 5).
"""

import datetime as dt
import json
import os
import re
import sys

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXES = os.environ.get("FIXES_DIR") or os.path.join(ROOT, "src", "content", "fixes")
STATE = os.environ.get("STATE_FILE") or os.path.join(ROOT, "data", "vuln-watch-state.json")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_URL = "https://api.github.com/advisories"
DRY = os.environ.get("DRY_RUN") == "1"
MAX_NEW = int(os.environ.get("MAX_NEW", "5"))
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

# Stacks the site covers. Matched against KEV vendorProject + product (lowercase).
KEV_KEYWORDS = [
    "apache", "tomcat", "struts", "spring", "log4j", "jboss", "wildfly", "weblogic", "java",
    "php", "wordpress", "drupal", "joomla", "laravel", "magento", "craft cms",
    "nginx", "f5", "big-ip", "citrix", "netscaler", "fortinet", "fortios", "fortigate", "ivanti",
    "palo alto", "pan-os", "sonicwall", "juniper", "cisco asa", "check point",
    "vmware", "broadcom", "esxi", "vcenter", "veeam", "commvault", "nakivo",
    "atlassian", "confluence", "jira", "jenkins", "gitlab", "teamcity",
    "exchange", "sharepoint", "moveit", "goanywhere", "crushftp",
    "langflow", "ollama", "litellm", "dify", "open webui",
]
GHSA_ECOSYSTEMS = ["maven", "composer"]


def log(*a):
    print(*a, file=sys.stderr)


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80]


def yaml_str(s):
    return json.dumps(s, ensure_ascii=False)  # JSON strings are valid YAML scalars


def load_state():
    if os.path.exists(STATE):
        return json.load(open(STATE))
    return None


def save_state(state):
    if DRY:
        return
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(state, open(STATE, "w"), indent=1, sort_keys=True)


def existing_by_cve():
    """Map CVE/GHSA id -> fix file path, from existing fix pages."""
    found = {}
    if not os.path.isdir(FIXES):
        return found
    for name in os.listdir(FIXES):
        if not name.endswith(".md"):
            continue
        path = os.path.join(FIXES, name)
        head = open(path, encoding="utf-8").read().split("\n---", 1)[0]
        for ident in re.findall(r"(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", head):
            found.setdefault(ident, path)
    return found


# ------------------------------------------------------------------ feeds

def fetch_kev():
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    return r.json()["vulnerabilities"]


def kev_relevant(v):
    hay = f"{v.get('vendorProject', '')} {v.get('product', '')}".lower()
    return any(k in hay for k in KEV_KEYWORDS)


def fetch_ghsa():
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    out = []
    for eco in GHSA_ECOSYSTEMS:
        r = requests.get(
            GHSA_URL,
            headers=headers,
            params={"type": "reviewed", "severity": "critical", "ecosystem": eco,
                    "sort": "published", "direction": "desc", "per_page": 30},
            timeout=60,
        )
        r.raise_for_status()
        out.extend(r.json())
    return out


# ------------------------------------------------------------------ page writers

def frontmatter(fields):
    lines = ["---"]
    for k, v in fields.items():
        if isinstance(v, bool):
            lines.append(f"{k}: {'true' if v else 'false'}")
        elif isinstance(v, list):
            if v and isinstance(v[0], dict):
                lines.append(f"{k}:")
                for item in v:
                    lines.append(f"  - name: {yaml_str(item['name'])}")
                    lines.append(f"    url: {yaml_str(item['url'])}")
            else:
                lines.append(f"{k}: [{', '.join(yaml_str(x) for x in v)}]")
        else:
            lines.append(f"{k}: {yaml_str(v) if isinstance(v, str) else v}")
    lines.append("---")
    return "\n".join(lines)


def kev_page(v):
    cve = v["cveID"]
    vendor, product = v.get("vendorProject", "").strip(), v.get("product", "").strip()
    name = v.get("vulnerabilityName", "").strip() or f"{vendor} {product} vulnerability"
    ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
    notes = [u.strip() for u in re.split(r"[;\s]+", v.get("notes", "")) if u.strip().startswith("http")]
    sources = [{"name": f"CISA KEV entry for {cve}", "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}"},
               {"name": f"NVD: {cve}", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}]
    for i, u in enumerate(notes[:4]):
        sources.append({"name": f"Vendor / reference link {i + 1}", "url": u})
    fields = {
        "title": f"{cve}: {name} — exploited, what to do now",
        "description": f"CISA has confirmed active exploitation of {cve} in {vendor} {product}. Affected scope, the official fix, and how to check for compromise.",
        "cve": [cve],
        "vendor": vendor,
        "product": product,
        "severity": "critical",
        "status": "alert",
        "exploited": True,
        "kev": True,
        "published": NOW.isoformat(),
        "updated": NOW.isoformat(),
        "sources": sources,
        "keywords": [f"{cve} fix", f"{cve} mitigation", f"{cve} exploited", f"{vendor} {product} vulnerability fix"],
        "social": f"Exploited now: {cve} in {vendor} {product}. CISA has added it to KEV. What we know and the official fix:",
        "hashtags": ["infosec", "vulnmanagement", "blueteam"],
    }
    body = f"""
**Status: alert.** This page was published automatically within minutes of CISA confirming exploitation. A reviewed fix guide with detection steps and workarounds will replace it shortly. Facts below are quoted from official sources only.

## What is affected

**{vendor} {product}** — {v.get('shortDescription', '').strip()}

## What to do now

CISA's required action: *{v.get('requiredAction', '').strip()}*

1. Identify every instance of {vendor} {product} you run, including internet-facing, vendor-managed and test systems.
2. Apply the vendor's fix or mitigation from the advisory linked below. If you cannot patch yet, restrict exposure of the affected service and follow the vendor's interim guidance.
3. Treat any instance that was exposed before patching as possibly compromised: review logs, look for unexpected files and processes, and rotate credentials it could reach.

## Key facts

| Field | Value |
| --- | --- |
| CVE | {cve} |
| Added to CISA KEV | {v.get('dateAdded', '')} |
| CISA remediation due date (US federal agencies) | {v.get('dueDate', '')} |
| Known ransomware campaign use | {ransomware} |
| Weakness | {', '.join(v.get('cwes', []) or ['Not listed'])} |
"""
    return f"{slugify(cve)}-{slugify(product)}", frontmatter(fields) + "\n" + body


def ghsa_page(a):
    ids = [i["value"] for i in a.get("identifiers", []) if i.get("type") == "CVE"] or [a["ghsa_id"]]
    vulns = a.get("vulnerabilities", [])
    pkgs = sorted({f"{x['package']['ecosystem']}:{x['package']['name']}" for x in vulns if x.get("package")})
    product = vulns[0]["package"]["name"] if vulns else a["ghsa_id"]
    rows = "\n".join(
        f"| `{x['package']['name']}` | {x.get('vulnerable_version_range') or '—'} | {x.get('first_patched_version') or 'No fix yet'} |"
        for x in vulns if x.get("package")
    )
    sources = [{"name": f"GitHub advisory {a['ghsa_id']}", "url": a["html_url"]}]
    for ident in ids:
        if ident.startswith("CVE-"):
            sources.append({"name": f"NVD: {ident}", "url": f"https://nvd.nist.gov/vuln/detail/{ident}"})
    for u in (a.get("references") or [])[:3]:
        if u.startswith("http") and u not in {s["url"] for s in sources}:
            sources.append({"name": "Reference", "url": u})
    main = ids[0]
    summary = a.get("summary", "").strip()
    fields = {
        "title": f"{main}: {summary} — how to fix",
        "description": f"Critical vulnerability in {product}. Vulnerable and patched versions, and what to do if you cannot upgrade yet.",
        "cve": ids if ids[0].startswith("CVE-") else [],
        "vendor": {"maven": "Java (Maven)", "composer": "PHP (Composer)"}.get(pkgs[0].split(":")[0], "") if pkgs else "",
        "product": product,
        "severity": "critical",
        "status": "alert",
        "exploited": False,
        "kev": False,
        "published": NOW.isoformat(),
        "updated": NOW.isoformat(),
        "sources": sources,
        "keywords": [f"{main} fix", f"{product} vulnerability", f"{product} upgrade {main}"],
        "social": f"Critical: {main} in {product}. Vulnerable and patched versions:",
        "hashtags": ["infosec", "appsec", "vulnmanagement"],
    }
    body = f"""
**Status: alert.** Published automatically from the GitHub reviewed advisory database. A reviewed fix guide with detection steps and workarounds will replace it. No exploitation in the wild had been confirmed by CISA when this page was created.

## What is affected

{summary}

| Package | Vulnerable versions | Patched version |
| --- | --- | --- |
{rows}

## What to do now

1. Search your dependency trees and SBOMs for the package above, including transitive dependencies and vendored copies.
2. Upgrade to the patched version. For Java, check every deployed WAR/JAR, not only the build file; for PHP, check `composer.lock` on each server.
3. If you cannot upgrade yet, follow the mitigation in the advisory linked below and restrict exposure of the affected endpoints.
"""
    return f"{slugify(main)}-{slugify(product)}", frontmatter(fields) + "\n" + body


def mark_exploited(path, v):
    text = open(path, encoding="utf-8").read()
    head, body = text.split("\n---\n", 1)
    head = re.sub(r"^exploited: .*$", "exploited: true", head, flags=re.M)
    head = re.sub(r"^kev: .*$", "kev: true", head, flags=re.M)
    head = re.sub(r"^updated: .*$", f"updated: {yaml_str(NOW.isoformat())}", head, flags=re.M)
    note = (f"\n> **Update {NOW.strftime('%Y-%m-%d %H:%M')} UTC:** CISA added {v['cveID']} to the Known Exploited "
            f"Vulnerabilities catalog, so exploitation in the wild is confirmed. Required action: "
            f"*{v.get('requiredAction', '').strip()}*\n")
    return head + "\n---\n" + note + body


# ------------------------------------------------------------------ main

def main():
    state = load_state()
    kev = fetch_kev()
    ghsa = fetch_ghsa()

    if state is None:
        # First run: remember what already exists so we do not flood the site with old items.
        state = {"kev": sorted(v["cveID"] for v in kev), "ghsa": sorted(a["ghsa_id"] for a in ghsa),
                 "seeded": NOW.isoformat()}
        save_state(state)
        log(f"seeded state: {len(state['kev'])} KEV, {len(state['ghsa'])} GHSA")
        return

    seen_kev, seen_ghsa = set(state["kev"]), set(state["ghsa"])
    existing = existing_by_cve()
    created, updated = [], []

    for v in kev:
        cve = v["cveID"]
        if cve in seen_kev:
            continue
        seen_kev.add(cve)
        if not kev_relevant(v):
            continue
        if cve in existing:
            path = existing[cve]
            if not DRY:
                new_text = mark_exploited(path, v)
                open(path, "w", encoding="utf-8").write(new_text)
            updated.append(path)
            continue
        if len(created) >= MAX_NEW:
            log(f"MAX_NEW reached, deferring {cve}")
            seen_kev.discard(cve)
            continue
        slug, content = kev_page(v)
        path = os.path.join(FIXES, slug + ".md")
        if not DRY:
            os.makedirs(FIXES, exist_ok=True)
            open(path, "w", encoding="utf-8").write(content)
        created.append(path)
        existing[cve] = path

    cutoff = NOW - dt.timedelta(days=3)
    for a in ghsa:
        gid = a["ghsa_id"]
        if gid in seen_ghsa:
            continue
        seen_ghsa.add(gid)
        published = dt.datetime.fromisoformat(a["published_at"].replace("Z", "+00:00"))
        ids = [i["value"] for i in a.get("identifiers", []) if i.get("type") == "CVE"]
        if published < cutoff or any(i in existing for i in ids + [gid]):
            continue
        if len(created) >= MAX_NEW:
            log(f"MAX_NEW reached, deferring {gid}")
            seen_ghsa.discard(gid)
            continue
        slug, content = ghsa_page(a)
        path = os.path.join(FIXES, slug + ".md")
        if not DRY:
            os.makedirs(FIXES, exist_ok=True)
            open(path, "w", encoding="utf-8").write(content)
        created.append(path)
        for i in ids + [gid]:
            existing[i] = path

    state["kev"], state["ghsa"] = sorted(seen_kev), sorted(seen_ghsa)
    save_state(state)
    for p in created:
        print("NEW", os.path.basename(p))
    for p in updated:
        print("UPDATED", os.path.basename(p))
    log(f"created {len(created)}, updated {len(updated)}")


if __name__ == "__main__":
    main()
