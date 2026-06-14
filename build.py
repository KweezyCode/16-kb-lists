import urllib.request
import json
import ipaddress
import re
import os
import subprocess

OUTPUT_DIR = "."

# ─── Source registry ──────────────────────────────────────────────────────────
#
# Чтобы добавить новый список — достаточно добавить запись в SOURCES.
#
# Типы источников:
#   "asn_json"  — JSON-файл с полями ip/asn → резолвим через RIPE, получаем CIDR
#   "cidr_txt"  — plain-text файл, одна CIDR-запись на строку (# — комментарии)
#
SOURCES = {
    "16-kb": {
        "type": "asn_json",
        "url": "https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/tcp16.json",
        "description": "16-kb CDN IPs via DPI detector",
    },
    "telegram": {
        "type": "cidr_txt",
        "url": "https://core.telegram.org/resources/cidr.txt",
        "description": "Telegram official CIDR ranges",
    },
    # Примеры будущих источников (раскомментировать при необходимости):
    #
    # "youtube": {
    #     "type": "cidr_txt",
    #     "url": "https://example.com/youtube-cidrs.txt",
    #     "description": "YouTube / Google Video CIDR ranges",
    # },
    # "cloudflare": {
    #     "type": "cidr_txt",
    #     "url": "https://www.cloudflare.com/ips-v4",
    #     "description": "Cloudflare IPv4 ranges",
    # },
}


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8")


def fetch_json(url: str) -> dict | list:
    return json.loads(fetch_url(url))


# ─── RIPE helpers (используются типом asn_json) ───────────────────────────────

def resolve_asn_for_ip(ip: str) -> list[str]:
    url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
    try:
        data = fetch_json(url)
        return [str(a) for a in data.get("data", {}).get("asns", [])]
    except Exception:
        return []


def fetch_prefixes_for_asn(asn: str) -> list[str]:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    try:
        data = fetch_json(url)
        return [item.get("prefix") for item in data.get("data", {}).get("prefixes", [])]
    except Exception as e:
        print(f"    ⚠️  AS{asn}: {e}")
        return []


# ─── CIDR helpers ─────────────────────────────────────────────────────────────

def is_valid_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def sort_cidrs(cidrs: list[str]) -> list[str]:
    def key(c):
        try:
            net = ipaddress.ip_network(c, strict=False)
            return (net.version, net.network_address)
        except ValueError:
            return (0, ipaddress.ip_address("0.0.0.0"))
    return sorted(set(filter(None, cidrs)), key=key)


# ─── Source handlers ──────────────────────────────────────────────────────────

def build_asn_json(name: str, source: dict) -> list[str]:
    """Fetch JSON → extract ASN / IP → query RIPE → return sorted CIDRs."""
    print(f"  🌐 Fetching JSON: {source['url']}")
    data = fetch_json(source["url"])
    print(f"  ✅ Loaded {len(data)} entries")

    asns: set[str] = set()
    for item in data:
        ip = item.get("ip")
        raw_asn = re.sub(r"\D", "", str(item.get("asn", "")))
        if raw_asn:
            asns.add(raw_asn)
        elif ip:
            asns.update(resolve_asn_for_ip(ip))

    print(f"  🔍 Found {len(asns)} unique ASNs — resolving prefixes via RIPE ...")

    all_cidrs: set[str] = set()
    for i, asn in enumerate(sorted(asns), 1):
        prefixes = fetch_prefixes_for_asn(asn)
        all_cidrs.update(p for p in prefixes if p)
        print(f"  [{i:>3}/{len(asns)}] AS{asn}: {len(prefixes)} prefixes")

    return sort_cidrs(list(all_cidrs))


def build_cidr_txt(name: str, source: dict) -> list[str]:
    """Fetch plain-text CIDR list → parse → return sorted CIDRs."""
    print(f"  🌐 Fetching CIDR list: {source['url']}")
    raw = fetch_url(source["url"])

    cidrs = []
    for line in raw.splitlines():
        line = line.split("#")[0].strip()   # strip inline comments
        if line and is_valid_cidr(line):
            cidrs.append(line)
        elif line:
            print(f"  ⚠️  Skipping invalid line: {line!r}")

    print(f"  ✅ Parsed {len(cidrs)} CIDRs")
    return sort_cidrs(cidrs)


HANDLERS = {
    "asn_json": build_asn_json,
    "cidr_txt": build_cidr_txt,
}


# ─── Output writers ───────────────────────────────────────────────────────────

def write_cidr_txt(name: str, cidrs: list[str]) -> str:
    path = os.path.join(OUTPUT_DIR, f"{name}-cidrs.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(cidrs) + "\n")
    print(f"  📄 {path}  ({len(cidrs)} CIDRs)")
    return path


def write_srs(name: str, cidrs: list[str]) -> str:
    json_path = os.path.join(OUTPUT_DIR, f"{name}-rules.json")
    srs_path  = os.path.join(OUTPUT_DIR, f"{name}.srs")

    ruleset = {"version": 1, "rules": [{"ip_cidr": cidrs}]}
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(ruleset, f, indent=2)

    print(f"  ⚙️  Compiling {srs_path} ...")
    try:
        subprocess.run(
            ["sing-box", "rule-set", "compile", "--output", srs_path, json_path],
            check=True,
            capture_output=True,
        )
        print(f"  🎉 {srs_path}")
    except subprocess.CalledProcessError as e:
        print(f"  ❌ sing-box compile failed:\n{e.stderr.decode()}")
        raise
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

    return srs_path


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    errors: list[str] = []

    for name, source in SOURCES.items():
        sep = "─" * 60
        print(f"\n{sep}")
        print(f"📦  {name}  —  {source['description']}")
        print(sep)

        handler = HANDLERS.get(source["type"])
        if handler is None:
            print(f"  ⚠️  Unknown source type '{source['type']}', skipping.")
            continue

        try:
            cidrs = handler(name, source)
            write_cidr_txt(name, cidrs)
            write_srs(name, cidrs)
        except Exception as e:
            print(f"  ❌ Failed: {e}")
            errors.append(name)

    print(f"\n{'═' * 60}")
    if errors:
        print(f"⚠️  Finished with errors in: {', '.join(errors)}")
        raise SystemExit(1)
    else:
        print("✅  All sources processed successfully!")


if __name__ == "__main__":
    main()
