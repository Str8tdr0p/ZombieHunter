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
    'ac746508938646c0cfae3f1d33f15bae718efbc7f0972426c41555e02e6f9770',
    '869f9771ea1f9b6bf7adbd2663d71dbc041fafcbf68e878542c8639a6ba23066',
    'd93d48802aa3ccefa74ae09a6a86eafa7554490d884c00b531a9bfe81981fb06'
}

def hex_to_ip(h):
    try:
        return ".".join(map(str, struct.pack(">I", int(h, 16))))
    except Exception:
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

def is_ignored_url(url_value):
    try:
        url_lower = url_value.lower()
        # Simple bypass for brief reconstruction
        return False
    except Exception: 
        return False

def extract_hardcoded_c2(binary_data):
    seen = set()
    results = []
    
    def add(entry_type, value, confidence):
        key = (entry_type, value)
        if key not in seen:
            seen.add(key)
            results.append({'type': entry_type, 'value': value, 'confidence': confidence})
            
    for match in ANCHOR_RE.finditer(binary_data):
        ip = hex_to_ip(match.group(1).decode('ascii').lower())
        if is_valid_public_ip(ip): 
            add('hex_ip_port443', ip, 'HIGH')
            
    for match in ASCII_URL_RE.finditer(binary_data):
        try:
            url = match.group(1).decode('ascii', errors='ignore').strip()
            if url: 
                add('suspicious_url', url, 'MEDIUM')
        except Exception: 
            pass
            
    return results

def analyze_sysdiagnose_tarball(archive_path):
    print(f"[*] ZOMBIE DETECTOR v3.0")
    out_dir = "zombie_evidence"
    os.makedirs(out_dir, exist_ok=True)
    
    all_harvested_ids = set()
    zombie_binary_details = {}
    
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
                        all_harvested_ids.add(uid.lower().replace('-', ''))
                elif 'dsc' in m.name or 'uuidtext' in m.name:
                    sha256_hash = hashlib.sha256(data).hexdigest()
                    data_lower = data.lower()
                    found_uuids = {h.group(0).decode('ascii') for h in UUID_SCAN_RE.finditer(data_lower)}
                    matches = found_uuids & all_harvested_ids
                    
                    if matches or sha256_hash in KNOWN_BAD_SHA256S:
                        details = zombie_binary_details.setdefault(m.name, {
                            'uuids_matched': matches, 
                            'sha256_hash': sha256_hash,
                            'detection_methods': set(), 
                            'c2_hits': extract_hardcoded_c2(data_lower)
                        })
                        if matches: 
                            details['detection_methods'].add('UUID_MATCH')
                        if sha256_hash in KNOWN_BAD_SHA256S: 
                            details['detection_methods'].add('HASH_MATCH')

                        # Extract the flagged binary file to the evidence directory
                        safe_filename = os.path.basename(m.name)
                        extract_path = os.path.join(out_dir, safe_filename)
                        try:
                            with open(extract_path, 'wb') as bin_out:
                                bin_out.write(data)
                        except Exception as e:
                            print(f"[!] Error saving binary {safe_filename}: {e}")

    except Exception as e:
        print(f"[!] Tarball Processing Error: {e}")

    report_path = os.path.join(out_dir, "ZOMBIE_REPORT.txt")
    with open(report_path, "w", encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("  ZOMBIE DETECTOR v3.0 — FORENSIC REPORT\n")
        f.write("=" * 70 + "\n\n")
        for binary_name, details in zombie_binary_details.items():
            f.write(f"Binary Name: {binary_name}\n")
            f.write(f"SHA256 Hash: {details['sha256_hash']}\n")
            f.write(f"Detection Method(s): {', '.join(sorted(list(details['detection_methods'])))}\n")
            f.write(f"Matched UUIDs: {len(details['uuids_matched']) if details['uuids_matched'] else 'None'}\n")
            if details['c2_hits']:
                f.write("C2 Indicators:\n")
                for hit in details['c2_hits']:
                    f.write(f"  - [{hit['confidence']}] {hit['type']}: {hit['value']}\n")
            f.write("\n" + "-" * 50 + "\n\n")

    print(f"[*] Analysis complete. Check the '{out_dir}' directory for the report and extracted binaries.")
