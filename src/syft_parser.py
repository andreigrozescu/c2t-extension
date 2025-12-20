#!/usr/bin/env python3
import json
import logging
from pathlib import Path
from urllib.parse import unquote

def sanitize(s: str) -> str:
    if s is None: return ""
    return str(s).replace(":", "_").replace("/", "_")

def clean_purl(purl: str) -> str:
    """Removes query params from PURL."""
    if not purl: return ""
    base_purl = purl.split('?')[0]
    return unquote(base_purl)

def parse_image_artifacts(syft_path: str, grype_path: str, image_identifier: str) -> dict:
    """
    Reads Syft and Grype JSON outputs.
    Extracts OS, Packages, Layers, and Vulnerabilities.
    """
    os_info, packages, layers = None, [], []
    syft_file = Path(syft_path)
    grype_file = Path(grype_path)

    # --- PARSE SYFT ---
    try:
        with open(syft_file, 'r', encoding='utf-8') as f:
            syft_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        syft_data = {}

    if syft_data:
        # Distro
        distro = syft_data.get('distro') or syft_data.get('source', {}).get('metadata', {}).get('distro')
        if distro:
            name = distro.get('name', '') if isinstance(distro, dict) else str(distro)
            version = distro.get('version', '') if isinstance(distro, dict) else ""
            id_like = distro.get('idLike', '') if isinstance(distro, dict) else ""
            
            full_name = name
            if not full_name and id_like: full_name = str(id_like)
            if not full_name: full_name = "Linux"

            os_info = {
                "name": full_name.strip(),
                "version": str(version),
                "image_identifier": sanitize(image_identifier)
            }

        # Layers
        source_meta = syft_data.get('source', {}).get('metadata', {})
        raw_layers = source_meta.get('layers', [])
        for l in raw_layers:
            lid = l.get('digest') or l.get('id')
            lsize = l.get('size')
            if lid and lsize is not None:
                layers.append({
                    "id": sanitize(lid),
                    "size": int(lsize),
                    "image_identifier": sanitize(image_identifier)
                })

        # Packages
        if syft_data.get('artifacts'):
            for artifact in syft_data['artifacts']:
                raw_purl = artifact.get('purl') or artifact.get('id') or ""
                purl = clean_purl(raw_purl)
                name = artifact.get('name') or ""
                version = artifact.get('version') or ""
                pkg_type = artifact.get('type') or artifact.get('pkg_type') or ""
                layer_id = ""
                
                locations = artifact.get('locations') or []
                if locations and isinstance(locations, list):
                    for loc in locations:
                        lid = loc.get('layerID')
                        if lid:
                            layer_id = sanitize(lid)
                            break
                
                if purl:
                    packages.append({
                        "purl": purl,
                        "name": name,
                        "version": version,
                        "packageType": pkg_type,
                        "layer_id": layer_id,
                        "image_identifier": sanitize(image_identifier)
                    })

    logging.info(f"Parsed Syft for '{image_identifier}': {len(packages)} packages and {len(layers)} layers info found.")

    # --- PARSE GRYPE ---
    vulnerabilities = []
    try:
        with open(grype_file, 'r', encoding='utf-8') as f:
            grype_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        grype_data = {}

    if grype_data and grype_data.get('matches'):
        for match in grype_data['matches']:
            artifact = match.get('artifact', {})
            raw_purl = artifact.get('purl')
            if raw_purl:
                clean = clean_purl(raw_purl)
                vuln = match.get('vulnerability', {})
                vid = vuln.get('id')
                severity = vuln.get('severity', 'Unknown')
                description = vuln.get('description', '')
                
                if vid and clean:
                    vulnerabilities.append({
                        "id": vid,
                        "severity": severity.capitalize(),
                        "description": str(description).replace('\n', ' ').replace('"', "'"),
                        "hasAffectedPackage": clean,
                        "image_identifier": sanitize(image_identifier)
                    })

    logging.info(f"Parsed Grype for '{image_identifier}': {len(vulnerabilities)} vulnerabilities found.")

    return {"os": os_info, "packages": packages, "layers": layers, "vulnerabilities": vulnerabilities}