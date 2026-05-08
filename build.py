import urllib.request
import json
import ipaddress
import re
import os
import subprocess

SOURCE_URL = "https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/tcp16.json"
OUTPUT_DIR = "."

def fetch_json(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode('utf-8'))

def fetch_current_asn(ip):
    url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
    try:
        data = fetch_json(url)
        asns = data.get('data', {}).get('asns', [])
        return [str(asn) for asn in asns]
    except Exception:
        return []

def fetch_prefixes_from_ripe(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    try:
        data = fetch_json(url)
        prefixes = []
        for item in data.get('data', {}).get('prefixes', []):
            prefixes.append(item.get('prefix'))
        return prefixes
    except Exception as e:
        print(f"❌ Error getting prefixes for ASN {asn}: {e}")
        return []

def main():
    print(f"🌐 Fetching {SOURCE_URL}...")
    try:
        target_data = fetch_json(SOURCE_URL)
        print(f"✅ Loaded {len(target_data)} entries.")
    except Exception as e:
        print(f"❌ Failed to fetch JSON: {e}")
        return

    asns = set()
    ips = set()
    
    print("🔍 Extracting ASNs and IPs...")
    for item in target_data:
        ip = item.get('ip')
        if ip:
            ips.add(ip)
            
        raw_asn = str(item.get('asn', ''))
        clean_asn = re.sub(r'\D', '', raw_asn)
        
        if clean_asn:
            asns.add(clean_asn)
        elif ip:
            current_asns = fetch_current_asn(ip)
            for a in current_asns:
                asns.add(a)

    print(f"✅ Found {len(asns)} unique ASNs and {len(ips)} individual test IPs.")
    
    # Save IPs flat list
    ips_file = os.path.join(OUTPUT_DIR, '16-kb-ips.txt')
    with open(ips_file, 'w', encoding='utf-8') as f:
        for ip in sorted(ips):
            f.write(ip + '\n')
            
    all_cidrs = set()
    print(f"🌐 Loading CIDR prefixes for {len(asns)} ASNs. Please wait...")
    for i, asn in enumerate(sorted(asns), 1):
        prefixes = fetch_prefixes_from_ripe(asn)
        for p in prefixes:
            all_cidrs.add(p)
            
    def sort_key(cidr):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            return (net.version, net.network_address)
        except ValueError:
            return (0, 0)
            
    sorted_cidrs = sorted(list(all_cidrs), key=sort_key)
    
    cidr_file = os.path.join(OUTPUT_DIR, '16-kb-cidrs.txt')
    with open(cidr_file, 'w', encoding='utf-8') as f:
        for c in sorted_cidrs:
            if c:
                f.write(c + '\n')
                
    print(f"✅ Collected {len(sorted_cidrs)} CIDRs.")
    
    # Create sing-box json ruleset
    json_path = os.path.join(OUTPUT_DIR, '16-kb-rules.json')
    ruleset = {
        "version": 1,
        "rules": [
            {
                "ip_cidr": sorted_cidrs
            }
        ]
    }
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(ruleset, f, indent=2)
        
    srs_file = os.path.join(OUTPUT_DIR, '16-kb.srs')
    print(f"⚙️ Compiling {srs_file}...")
    try:
        subprocess.run(['sing-box', 'rule-set', 'compile', '--output', srs_file, json_path], check=True)
        print("🎉 Compile success!")
        os.remove(json_path) # cleanup json
    except subprocess.CalledProcessError as e:
        print(f"❌ sing-box compile failed: {e}")

if __name__ == "__main__":
    main()
