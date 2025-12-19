#!/usr/bin/env python3
import json
import logging
from pathlib import Path

def sanitize(s: str) -> str:
    if s is None: return ""
    return s.replace(":", "_").replace("/", "_")

def parse_inspect_file(file_path: str) -> dict | None:
    try:
        path = Path(file_path)
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not data:
            return None
        
        info = data[0]
        
        name = info.get("Name", "").lstrip('/')
        
        raw_image = info.get("Config", {}).get("Image", "")
        if not raw_image and "RepoTags" in info and info["RepoTags"]:
             raw_image = info["RepoTags"][0]
        image_sanitized = sanitize(raw_image)
        
        ports = info.get("NetworkSettings", {}).get("Ports", {})
        if not ports:
            ports = info.get("Config", {}).get("ExposedPorts", {})
        
        created = info.get("Created")
        if not created or created == "null":
             created = info.get("Config", {}).get("Created", "")
        if created is None: created = ""

        size = info.get("Size", 0)
        arch = info.get("Architecture", "unknown")
        
        return {
            "id": info.get("Id", ""),
            "name": name,
            "image_raw": raw_image,
            "image_name": image_sanitized,
            "status": info.get("State", {}).get("Status", "unknown"),
            "created": str(created),
            "ports": ports,
            "arch": arch,
            "size": size
        }

    except (json.JSONDecodeError, IndexError, FileNotFoundError) as e:
        logging.error(f"Error parsing inspect file '{file_path}': {e}")
        return None