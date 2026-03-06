======================
Silicon Purity Test

Joseph R Goydish II
======================


import re
import struct
import csv
import os
import tarfile
import sys
from urllib.parse import urlparse
import hashlib # Added for SHA256 hash matching

# --- Patterns ---

# UUID in log text (with or without dashes)
ID_RE = re.compile(
    r'\b([a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}|[a-fA-F0-9]{32})\b'
)

# Scan binary for 32-char hex UUID blobs (no dashes)
UUID_SCAN_RE = re.compile(rb'[0-9a-fA-F]{32}', re.IGNORECASE)

# Hex-encoded IP immediately followed by port 443 (decimal or hex)
ANCHOR_RE = re.compile(rb'([0-9a-fA-F]{8})[:.](?:443|01bb)', re.IGNORECASE)

# Embedded HTTP/S URLs in binary
ASCII_URL_RE = re.compile(rb'https?://([a-zA-Z0-9._:/?&=%~-]{4,128})')

# Private/loopback ranges to ignore
IGNORED_IPS = {
    "0.0.0.0", "255.255.255.255", "127.0.0.1",
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
}

# Known bad SHA256 hashes for binary detection
KNOWN_BAD_SHA256S = {
    '38a723210c18e81de8f33db79cfe8bae050a98d9d2eacdeb4f35dabbf7bd0cee',
    'ac746508938646c0cfae3f1d33f15bae718efbc7f0972426c41555e02e6f9770'
}

# --- Helpers ---

def hex_to_ip(h):
    try:
        return ".".join(map(str, struct.pack(">I", int(h, 16))))
    except:
        return None

def is_valid_public_ip(ip):
    if not ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        if not all(0 <= int(p) <= 255 for p in parts):
            return False
    except ValueError:
        return False
    for prefix in IGNORED_IPS:
        if ip == prefix or ip.startswith(prefix):
            return False
    return True

# Domains and hostnames to be filtered out from URLs
IGNORED_URL_DOMAINS = {
    'apple.com', 'icloud.com', 'me.com', 'mac.com',
    'cdn-apple.com', 'apps.apple.com', 'itunes.apple.com',
    'mzstatic.com', 'aaplimg.com', 'appleid.apple.com',
    'www.apple.com', 'support.apple.com', 'developer.apple.com', 'itunes.com',
    'schema.org', 'hl7.org', 'w3.org', 'schemas.microsoft.com',
    'schemas.openxmlformats.org', 'purl.org', 'purl.oclc.org',
    'ns.adobe.com', 'ns.apple.com',
    # Explicitly added from previous output and user request:
    'edge.apple', # For croissant.edge.apple
    'apple.news', # For apple.news/familysetup
    'digitalhub.com', # For idmsa-uat.digitalhub.com
    'unitsofmeasure.org',
    'crl.comodo.net',
    'partner.barrons.com', # barrons.com for /apple/web_access, etc.
    'digicert.com',
    'radio.itunes.apple.com',
    'gateway.icloud.com',
    'tether.edge.apple',
    'radio-activity.itunes.apple.com',
    'snomed.info',
    'ncimeta.nci.nih.gov',
    'tools.ietf.org',
    'smarthealth.cards',
    'www.ama-assn.org',
    'www.whocc.no',
    'www.google.com',
    'openusd.org',
    'open.fda.gov',
    'r3.o.lencr.org',
    'x1.c.lencr.org',
    'ocsp.digicert.com',
    'us-pst.exp.fastly-masque.net',
    'r3.i.lencr.org',
    'crl.comodoca.com',
    'acsegateway.icloud.com',
    'idmsa-uat.digitalhub.com',
    'accounts.barrons.com',
    'nema.org',
    'developers.google.com',
    'www.nlm.nih.gov',
    'q1.us-pst.gh-g.v1.akaquill.net',
    'ocsp.comodoca.com',
    'www.instapaper.com',
    'pinboard.in',
    'wordpress.com',
    'trello.com',
    'vp25q03ad-app037.iad.apple.com',
    'www.showtime.com',
    'www.hulu.com',
    'en.wikipedia.org',
    'www.cgal.org',
    'ml-explore.github.io',
    'github.com',
    'login.live.com',
    'outlook.office.com',
    'login.microsoftonline.com',
    'mdm.example.com',
    'eas.outlook.com',
    'outlook.office365.com',
    'www.britannica.com',
    'www.investopedia.com',
    'www.beatsbydre.com',
    'covid-19-diagnostics.jrc.ec.europa.eu',
    'ec.europa.eu',
    'spor.ema.europa.eu',
    'fhir.org',
    'commonmark.org',
    'jwxkwap.miit.gov.cn',
    'migrate.google',
    'raptor-dr.apple.com',
    'starbucks.com',
    'passman.apple.com',
    'docs.oasis-open.org'
}

IGNORED_URL_EXACT_MATCHES = {
    'localhost', '127.0.0.1', 'example.com', 'pcmdestination.example',
    # Explicitly added from previous output and user request:
    'user:password',
    '%s:%s',
    '%s:%u',
    'host.com%',
    'autodiscover.%',
    'localhost:%li%',
    'jwxkwap.miit.gov.cn/eauthenticityquerydetails?type=1&r=%',
    '17.253.144.13', # specific IP that is not a C2
    'networkquality/.well-known/nq',
    'macvmlschemauri'
}

# Regex for common format strings in URLs
# Updated to match specific format specifiers including %ld, %lu
FORMAT_STRING_RE = re.compile(r'%(?:s|d|f|@|ld|lu)', re.IGNORECASE)

def is_ignored_url(url_value):
    try:
        url_lower = url_value.lower()

        # Check for exact matches (host or full URL part) directly against the raw URL string
        if url_lower in IGNORED_URL_EXACT_MATCHES:
            return True

        # Check for format strings
        if FORMAT_STRING_RE.search(url_lower):
            return True

        # To robustly parse the domain, ensure the URL has a scheme
        parsed_url = urlparse(url_lower if '://' in url_lower else 'http://' + url_lower)
        host_to_check = parsed_url.hostname # Use .hostname to get the host without the port

        if host_to_check is None: # If no valid hostname could be parsed (e.g., 'user:password' or malformed)
            return False

        for domain in IGNORED_URL_DOMAINS:
            if host_to_check == domain or host_to_check.endswith('.' + domain): # Handle subdomains as well
                return True
        return False
    except Exception:
        return False

def extract_hardcoded_c2(binary_data):
    """
    Scan a zombie binary for embedded C2 indicators.
    Returns list of dicts with type, value, confidence.
    """
    seen = set()
    results = []

    def add(entry_type, value, confidence):
        key = (entry_type, value)
        if key not in seen:
            seen.add(key)
            results.append({'type': entry_type, 'value': value, 'confidence': confidence})

    # HIGH confidence: hex-encoded IP paired with HTTPS port — almost certainly intentional
    for match in ANCHOR_RE.finditer(binary_data):
        ip = hex_to_ip(match.group(1).decode('ascii').lower())
        if is_valid_public_ip(ip):
            add('hex_ip_port443', ip, 'HIGH')

    # MEDIUM confidence: embedded URLs (catches domain-based C2 too)
    for match in ASCII_URL_RE.finditer(binary_data):
        try:
            url = match.group(1).decode('ascii', errors='ignore').strip()
            if url and not is_ignored_url(url): # Apply the new, enhanced filtering here
                add('suspicious_url', url, 'MEDIUM') # Changed type label to suspicious_url
        except:
            pass

    return results

# --- Main ---

def analyze_sysdiagnose_tarball(archive_path):
    print(f"[*] ZOMBIE DETECTOR v3.0")
    print(f"[*] Target: {archive_path}")
    print()

    if not os.path.exists(archive_path):
        print(f"[!] File not found: {archive_path}")
        return

    out_dir = "zombie_evidence"
    os.makedirs(out_dir, exist_ok=True)

    all_harvested_ids = set()   # 32-char hex, lowercase, no dashes
    id_to_log_map = {}          # uuid32 -> tracev3 filename
    zombie_uuids = set()        # confirmed zombie uuid32s (from UUID_MATCH detections)

    # New data structure to store details for each detected zombie binary
    zombie_binary_details = {} # binary_name -> {uuids_matched, sha256_hash, detection_methods, c2_hits}

    # -------------------------------------------------------------------------
    # SINGLE PASS: harvest UUIDs from tracev3, detect zombies in dsc/uuidtext,
    # and immediately scan confirmed zombie binaries for hardcoded C2
    # -------------------------------------------------------------------------
    print("[*] Phase 1+2: Single-pass tar scan (UUID & SHA256 detection)..."

    try:
        with tarfile.open(archive_path, "r:*") as tar:
            for m in tar.getmembers():
                if not m.isfile():
                    continue
                f_obj = tar.extractfile(m)
                if not f_obj:
                    continue
                data = f_obj.read()

                if m.name.endswith('.tracev3'):
                    text = data.decode('ascii', errors='ignore')
                    for uid in ID_RE.findall(text):
                        norm = uid.lower().replace('-', '')
                        all_harvested_ids.add(norm)
                        id_to_log_map[norm] = m.name

                elif 'dsc' in m.name or 'uuidtext' in m.name:
                    binary_name = m.name

                    # Calculate SHA256 hash for the binary content
                    sha256_hash = hashlib.sha256(data).hexdigest()

                    # Initialize/get details for this binary
                    current_binary_details = zombie_binary_details.setdefault(binary_name, {
                        'uuids_matched': set(),
                        'sha256_hash': sha256_hash,
                        'detection_methods': set(),
                        'c2_hits': []
                    })

                    # --- UUID Detection Logic ---
                    data_lower = data.lower()
                    found_in_binary = {
                        hit.group(0).decode('ascii')
                        for hit in UUID_SCAN_RE.finditer(data_lower)
                    }
                    matches = found_in_binary & all_harvested_ids

                    if matches:
                        for uid in matches:
                            zombie_uuids.add(uid) # Add to global set of zombie UUIDs
                            current_binary_details['uuids_matched'].add(uid) # Add to binary-specific set
                        current_binary_details['detection_methods'].add('UUID_MATCH')

                    # --- SHA256 Hash Matching Logic ---
                    if sha256_hash in KNOWN_BAD_SHA256S:
                        current_binary_details['detection_methods'].add('HASH_MATCH')

                    # If this binary is identified as a zombie by *any* method
                    if current_binary_details['detection_methods']:
                        print(f"  [!] ZOMBIE BINARY: {binary_name}")
                        print(f"      SHA256: {sha256_hash}")
                        print(f"      Detection Method(s): {', '.join(sorted(list(current_binary_details['detection_methods'])))}")
                        if current_binary_details['uuids_matched']:
                            print(f"      Matched UUIDs: {len(current_binary_details['uuids_matched'])}")

                        c2_hits = extract_hardcoded_c2(data_lower)
                        current_binary_details['c2_hits'] = c2_hits

                        if c2_hits:
                            num_c2_ips = len([hit for hit in c2_hits if hit['type'] == 'hex_ip_port443'])
                            num_suspicious_urls = len([hit for hit in c2_hits if hit['type'] == 'suspicious_url'])
                            print(f"      Hardcoded C2 indicators found: {num_c2_ips} (IPs) / {num_suspicious_urls} (Suspicious URLs) (filtered)")
                            for hit in c2_hits:
                                if hit['type'] == 'hex_ip_port443':
                                    print(f"        [{hit['confidence']}] C2 indicator: {hit['value']}")
                                elif hit['type'] == 'suspicious_url':
                                    print(f"        [{hit['confidence']}] Suspicious URL: {hit['value']}")
                        else:
                            print(f"      No relevant hardcoded C2 or suspicious URLs found in binary (after filtering)")

                        # Write the original binary data, not lowercased
                        out_bin = os.path.join(out_dir, f"ZOMBIE_{os.path.basename(binary_name)}.bin")
                        if not os.path.exists(out_bin):
                            with open(out_bin, 'wb') as df:
                                df.write(data)

    except Exception as e:
        print(f"[!] Error during scan: {e}")
        raise

    print()
    print(f"[*] {len(all_harvested_ids)} UUIDs harvested from logs")

    # Calculate summary counts for detected binaries and methods
    total_zombie_binaries = len(zombie_binary_details)
    num_hash_only_matches = 0
    num_uuid_only_matches = 0
    num_both_matches = 0

    for binary_name, details in zombie_binary_details.items():
        is_uuid = 'UUID_MATCH' in details['detection_methods']
        is_hash = 'HASH_MATCH' in details['detection_methods']

        if is_uuid and is_hash:
            num_both_matches += 1
        elif is_uuid:
            num_uuid_only_matches += 1
        elif is_hash:
            num_hash_only_matches += 1

    print(f"[*] {total_zombie_binaries} zombie binaries detected by any method")
    print()

    if not zombie_binary_details: # Check if any binaries were detected as zombie
        print("[+] No zombies detected — device clean")
        return

    print("=" * 70)
    print("  ZOMBIE CONFIRMED")
    print("=" * 70)
    print()

    # -------------------------------------------------------------------------
    # PHASE 4: Write reports
    # -------------------------------------------------------------------------
    print("[*] Phase 4: Writing evidence...")

    report_path = os.path.join(out_dir, "ZOMBIE_REPORT.txt")
    with open(report_path, "w", encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("  ZOMBIE DETECTOR v3.0 — FORENSIC REPORT\n")
        f.write(
