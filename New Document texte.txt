#!/usr/bin/env python3
"""
Build a Nessus policy with ONLY the plugins that match a filter enabled
(Exploited By Malware = true, or a list of CVEs). Import the output via GUI.

Steps:
  1. GUI: build an Advanced Scan policy (settings/creds as you like), Disable All plugins, save.
  2. GUI: Policies -> tick it -> More/Export -> save as base.nessus
  3. GUI: Settings -> My Account -> API Keys -> Generate
  4. export NESSUS_AK=...; export NESSUS_SK=...   (keeps keys out of shell history / ps)
     Run:
     python3 nessus_filter_policy.py --url https://127.0.0.1:8834 \
         --base base.nessus --out ransomware.nessus --name "Ransomware Exposure" --malware
     python3 nessus_filter_policy.py --url https://127.0.0.1:8834 \
         --base base.nessus --out log4shell.nessus --name "Log4Shell Ecosystem" \
         --cve CVE-2021-44228 CVE-2021-45046 CVE-2021-44832 CVE-2021-4104
  5. GUI: Policies -> Import -> pick the output. Re-enter credential passwords (exports strip them).
"""
import argparse
import concurrent.futures as cf
import os
import sys
import xml.etree.ElementTree as ET

import requests
import urllib3

urllib3.disable_warnings()


def get(s, base, path, params=None):
    r = s.get(base + path, params=params, timeout=120)
    r.raise_for_status()
    return r.json()


def filter_params(args):
    rules = ([("exploited_by_malware", "eq", "true")] if args.malware
             else [("cve", "eq", c) for c in args.cve])
    p = {"filter.search_type": "or"}
    for i, (f, q, v) in enumerate(rules):
        p[f"filter.{i}.filter"], p[f"filter.{i}.quality"], p[f"filter.{i}.value"] = f, q, v
    return p


def plugin_matches(s, base, pid, args):
    d = get(s, base, f"/plugins/plugin/{pid}")
    attrs = {}
    for a in d.get("attributes", []):
        attrs.setdefault(a["attribute_name"], []).append(str(a["attribute_value"]).strip())
    if args.malware:
        return any(v.lower() == "true" for v in attrs.get("exploited_by_malware", []))
    return bool(set(attrs.get("cve", [])) & set(args.cve))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--ak", default=os.environ.get("NESSUS_AK"), help="or env NESSUS_AK")
    ap.add_argument("--sk", default=os.environ.get("NESSUS_SK"), help="or env NESSUS_SK")
    ap.add_argument("--ca", help="CA/cert file to verify the Nessus TLS cert (default: no verification)")
    ap.add_argument("--base", required=True, help="exported .nessus policy (all plugins disabled)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--malware", action="store_true")
    g.add_argument("--cve", nargs="+")
    ap.add_argument("--verify", action="store_true",
                    help="force per-plugin attribute check (slow, always accurate)")
    ap.add_argument("--threads", type=int, default=20)
    args = ap.parse_args()

    if not (args.ak and args.sk):
        sys.exit("[-] set NESSUS_AK / NESSUS_SK env vars (or --ak/--sk)")
    base = args.url.rstrip("/")
    s = requests.Session()
    s.verify = args.ca if args.ca else False
    s.headers["X-ApiKeys"] = f"accessKey={args.ak}; secretKey={args.sk}"

    fp = filter_params(args)
    all_fams = get(s, base, "/plugins/families")["families"]
    flt_fams = get(s, base, "/plugins/families", fp)["families"]

    total_all = sum(f.get("count", 0) for f in all_fams)
    total_flt = sum(f.get("count", 0) for f in flt_fams)
    server_filters = total_flt < total_all and not args.verify
    print(f"[*] {total_all} plugins total, filtered view: {total_flt} "
          f"-> {'server-side filter OK' if server_filters else 'verifying per plugin'}")

    cand_fams = flt_fams if server_filters else all_fams
    selected = {}  # family name -> {pid: name}
    for fam in cand_fams:
        if not fam.get("count"):
            continue
        params = fp if server_filters else None
        plugins = get(s, base, f"/plugins/families/{fam['id']}", params).get("plugins", [])
        if server_filters:
            hits = {p["id"]: p["name"] for p in plugins}
        else:
            hits = {}
            with cf.ThreadPoolExecutor(args.threads) as ex:
                futs = {ex.submit(plugin_matches, s, base, p["id"], args): p for p in plugins}
                for f in cf.as_completed(futs):
                    p = futs[f]
                    try:
                        if f.result():
                            hits[p["id"]] = p["name"]
                    except Exception as e:
                        print(f"[!] {p['id']}: {e}", file=sys.stderr)
        if hits:
            selected[fam["name"]] = hits
            print(f"[+] {fam['name']}: {len(hits)}")

    if not selected:
        sys.exit("[-] nothing matched")

    # full plugin lists for selected families, so non-matching ones are explicitly disabled
    fam_ids = {f["name"]: f["id"] for f in all_fams}
    tree = ET.parse(args.base)
    policy = tree.getroot().find("Policy")
    if policy is None:
        sys.exit("[-] no <Policy> in base file")
    pn = policy.find("policyName")
    if pn is None:
        pn = ET.SubElement(policy, "policyName")
    pn.text = args.name

    for tag in ("FamilySelection", "IndividualPluginSelection"):
        for el in policy.findall(tag):
            policy.remove(el)

    fs = ET.SubElement(policy, "FamilySelection")
    for f in all_fams:
        fi = ET.SubElement(fs, "FamilyItem")
        ET.SubElement(fi, "FamilyName").text = f["name"]
        ET.SubElement(fi, "Status").text = "mixed" if f["name"] in selected else "disabled"

    ips = ET.SubElement(policy, "IndividualPluginSelection")
    n = 0
    for fam_name, hits in selected.items():
        fam_plugins = get(s, base, f"/plugins/families/{fam_ids[fam_name]}").get("plugins", [])
        for p in fam_plugins:
            pi = ET.SubElement(ips, "PluginItem")
            ET.SubElement(pi, "PluginId").text = str(p["id"])
            ET.SubElement(pi, "PluginName").text = p["name"]
            ET.SubElement(pi, "Family").text = fam_name
            on = p["id"] in hits
            ET.SubElement(pi, "Status").text = "enabled" if on else "disabled"
            n += on

    tree.write(args.out, encoding="utf-8", xml_declaration=True)
    print(f"[*] {n} plugins enabled across {len(selected)} families -> {args.out}")


if __name__ == "__main__":
    main()
