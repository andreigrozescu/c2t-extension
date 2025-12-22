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

def extract_cvss(vuln_obj):
    """
    Helper to extract the best CVSS Score and Vector from a vulnerability object.
    Prioritizes CVSS v3 over v2.
    """
    score = 0.0
    vector = ""
    cvss_list = vuln_obj.get('cvss', [])
    
    if cvss_list:
        selected = cvss_list[0]
        for cv in cvss_list:
            if cv.get('version', '').startswith('3'):
                selected = cv
                break
        
        metrics = selected.get('metrics', {})
        # Score
        val = metrics.get('baseScore')
        if val: 
            try: score = float(val)
            except: pass
        
        # Vector
        vector = metrics.get('vectorString') or metrics.get('vector') or ""
        
    return score, vector

def parse_image_artifacts(syft_path: str, grype_path: str, image_identifier: str) -> dict:
    """
    Reads Syft and Grype JSON outputs.
    Extracts OS, Packages, Layers, and Vulnerabilities with robust fallback logic.
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
                cvss_score, cvss_vector = extract_cvss(vuln)
                
                if not description or not cvss_vector:
                    relateds = vuln.get('relatedVulnerabilities', [])
                    for rel in relateds:
                        if not description and rel.get('description'):
                            description = rel.get('description')
                        
                        if not cvss_vector:
                            r_score, r_vector = extract_cvss(rel)
                            if r_vector:
                                cvss_vector = r_vector
                                if cvss_score == 0.0: cvss_score = r_score
                        
                        if description and cvss_vector:
                            break

                if not description and vuln.get('detail'):
                     description = vuln.get('detail')
                
                # Fields
                fixed_in = ""
                if vuln.get('fix'):
                    versions = vuln.get('fix', {}).get('versions', [])
                    if versions: fixed_in = versions[0]
                    else: fixed_in = vuln.get('fixedInVersion', "")
                
                namespace = vuln.get('namespace', 'unknown')
                
                if vid and clean:
                    vulnerabilities.append({
                        "id": vid,
                        "severity": severity.capitalize(),
                        "description": str(description).replace('\n', ' ').replace('"', "'"),
                        "fixedIn": fixed_in,
                        "score": cvss_score,
                        "vector": cvss_vector, 
                        "type": namespace,
                        "hasAffectedPackage": clean,
                        "image_identifier": sanitize(image_identifier)
                    })

    logging.info(f"Parsed Grype for '{image_identifier}': {len(vulnerabilities)} vulnerabilities found.")

    return {"os": os_info, "packages": packages, "layers": layers, "vulnerabilities": vulnerabilities}