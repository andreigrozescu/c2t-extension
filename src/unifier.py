import subprocess
import shutil
import json
import logging
import socket
import re
from pathlib import Path
from . import inspect_parser, syft_parser
import morph_kgc
import rdflib

MAPPINGS_DIR = Path(__file__).parent.parent / "mappings"

def sanitize(s: str) -> str:
    """Make strings URI-safe."""
    if s is None: return ""
    return str(s).replace(":", "_").replace("/", "_")

def clean_rdf_string(s: str) -> str:
    """Escape special characters for RDF."""
    return str(s).replace('"', "'").replace("\\", "\\\\").replace("\n", "\\n").replace("\t", " ")

def clean_docker_command(cmd: str) -> str:
    """Cleans Dockerfile commands for display (removes /bin/sh wrapper)."""
    if not cmd: return "Unknown"
    c = cmd.replace("/bin/sh -c #(nop) ", "").replace("/bin/sh -c ", "RUN ")
    return clean_rdf_string(c).strip()

def parse_docker_history_jsonl(history_path: Path):
    """Parses docker history output (JSON Lines). Returns list of dicts."""
    items = []
    if not history_path.exists():
        return []
    try:
        with open(history_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        items.append(json.loads(line))
                    except: pass
    except Exception as e:
        logging.error(f"Error reading history file: {e}")
    return items

def parse_size_string(size_str: str) -> int:
    """Converts Docker history size strings (e.g., '10MB', '4KB', '0B') to bytes."""
    if not size_str or size_str == "0B":
        return 0
    
    units = {"B": 1, "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4}
    match = re.match(r"([\d\.]+)\s*([A-Za-z]+)", size_str)
    if match:
        val = float(match.group(1))
        unit = match.group(2).upper()
        multiplier = units.get(unit, 1)
        return int(val * multiplier)
    return 0

def is_physical_layer(cmd_raw: str, size_str: str) -> bool:
    """
    Determines if a docker history item represents a physical layer.
    1. If Size > 0: physical layer.
    2. If Size == 0: physical layer only if it is a filesystem command (RUN/COPY/ADD).
    3. Metadata commands (CMD, ENV, LABEL) are excluded if size is 0.
    """
    size = parse_size_string(size_str)
    if size > 0:
        return True
    
    cmd = clean_docker_command(cmd_raw).upper()
    metadata_instructions = [
        "CMD", "ENV", "LABEL", "EXPOSE", "ENTRYPOINT", 
        "USER", "MAINTAINER", "ARG", "STOPSIGNAL", 
        "HEALTHCHECK", "SHELL"
    ]
    
    # If it's a pure metadata command, it doesn't create a layer
    for m in metadata_instructions:
        if cmd.startswith(m + " ") or cmd == m:
            return False
        
    # Assume everything else creates a layer (RUN, COPY, ADD, WORKDIR, VOLUME)
    return True

def generate_unified_json(temp_dir: Path, containers_data: list, images_to_analyze: list) -> rdflib.Graph:
    """
    Adds parsed data from Syft, Grype, and Docker into a single JSON structure.
    Prepares data for Morph-KGC mapping.
    """
    unified_data = {
        "host": [], "containers": [], "images": [], "layers": [],
        "image_layer_relations": [], "os": [], "packages": [], "vulnerabilities": [], "pkg_vuln_relations": [] 
    }

    hostname = socket.gethostname().strip()
    unified_data["host"].append({"id": hostname, "ip": "127.0.0.1", "architecture": "x86_64"})

    # --- PROCESS CONTAINERS ---
    for container in containers_data:
        inspect_path = temp_dir / f"inspect_{container['id']}.json"
        parsed = inspect_parser.parse_inspect_file(str(inspect_path))
        if parsed:
            c_date = str(parsed.get("created", ""))
            if c_date.lower() == "none" or not c_date: c_date = ""

            unified_data["containers"].append({
                "id": parsed.get("id"),
                "name": parsed.get("name"),
                "status": parsed.get("status"),
                "isInstanceOf": parsed.get("image_name"),
                "isDeployedOn": hostname,
                "ports": str(parsed.get("ports")),
                "created": c_date 
            })

    # --- PROCESS IMAGES ---
    for image_name in images_to_analyze:
        safe_name = sanitize(image_name)
        
        image_layers_ids = []
        created = ""
        arch = "unknown"
        size = 0
        
        # 1. Inspect
        inspect_file_path = temp_dir / f"image_inspect_{safe_name}.json"
        if inspect_file_path.exists():
            parsed_img = inspect_parser.parse_inspect_file(str(inspect_file_path))
            if parsed_img:
                if parsed_img.get("created"): created = str(parsed_img.get("created"))
                if parsed_img.get("arch"): arch = str(parsed_img.get("arch"))
                if parsed_img.get("size"): size = int(parsed_img.get("size"))
            
            try:
                with open(inspect_file_path, 'r', encoding='utf-8') as f:
                    idata = json.load(f)
                    if isinstance(idata, list) and idata: idata = idata[0]
                    # Extract Physical Layers (RootFS)
                    raw_layers = idata.get('RootFS', {}).get('Layers', [])
                    image_layers_ids = [sanitize(l) for l in raw_layers]
            except: pass

        if not created or created.lower() == "none": created = "Unknown"
        
        # 2. Syft / Grype
        syft_file = temp_dir / f"syft_{safe_name}.json"
        grype_file = temp_dir / f"grype_{safe_name}.json"
        artifacts = syft_parser.parse_image_artifacts(str(syft_file), str(grype_file), image_name)

        # Fallback layers if inspect failed
        if not image_layers_ids and artifacts.get("layers"):
            logging.info(f"Using Syft layers fallback for {image_name}")
            image_layers_ids = [l["id"] for l in artifacts["layers"]]

        # 3. Process docker history
        history_file = temp_dir / f"history_{safe_name}.json"
        raw_history = parse_docker_history_jsonl(history_file)
        
        # Reverse history to match Base -> top order of RootFS
        raw_history.reverse()
        
        # Reconstruct build history
        full_history_text = "\n".join([clean_docker_command(h.get("CreatedBy", "")) for h in raw_history])
        
        # Filter history items to align with physical layers
        physical_history_data = []
        for h in raw_history:
            cmd_raw = h.get("CreatedBy", "")
            sz_str = h.get("Size", "0B")
            
            if is_physical_layer(cmd_raw, sz_str):
                physical_history_data.append({
                    "cmd": clean_docker_command(cmd_raw),
                    "size": parse_size_string(sz_str)
                })

        unified_data["images"].append({
            "identifier": safe_name, 
            "raw_identifier": image_name,
            "architecture": arch, 
            "created": created,
            "size": size,
            "history": full_history_text
        })

        # --- MAP LAYERS AND COMMANDS ---
        for i, layer_id in enumerate(image_layers_ids):
            unified_data["image_layer_relations"].append({
                "image_identifier": safe_name, "layer_id": layer_id
            })
            
            # Map command
            cmd = "Unknown Instruction"
            history_size = 0
            
            if i < len(physical_history_data):
                cmd = physical_history_data[i]["cmd"]
                history_size = physical_history_data[i]["size"]

            # Populate layer info
            layer_size = 0
            if artifacts.get("layers"):
                for al in artifacts["layers"]:
                    if al["id"] == layer_id:
                        layer_size = al["size"]
                        break
            
            if layer_size == 0 and history_size > 0:
                layer_size = history_size

            if not any(l['id'] == layer_id for l in unified_data["layers"]):
                 unified_data["layers"].append({
                     "id": layer_id, 
                     "size": layer_size,
                     "command": cmd,
                     "index": i 
                 })

        if artifacts.get("os"): 
            unified_data["os"].append(artifacts["os"])
        
        if artifacts.get("packages"):
            for p in artifacts["packages"]:
                p["image_identifier"] = safe_name
                if not p.get("layer_id") and image_layers_ids:
                    p["layer_id"] = image_layers_ids[-1]
                elif not p.get("layer_id"):
                     p["layer_id"] = "unknown_layer"
                unified_data["packages"].append(p)

        if artifacts.get("vulnerabilities"):
            for v in artifacts["vulnerabilities"]:
                unified_data["vulnerabilities"].append(v)
                unified_data["pkg_vuln_relations"].append({
                    "purl": v["hasAffectedPackage"],
                    "vuln_id": v["id"]
                })

    # --- GENERATE RDF ---
    mapping_file = MAPPINGS_DIR / "mapping_host.yarrrrml.yaml"
    if not mapping_file.exists():
         logging.error(f"Mapping file not found at {mapping_file}")
    else:
         shutil.copy(mapping_file, temp_dir / "mapping.yaml")

    json_path = temp_dir / "unified_data.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(unified_data, f, indent=4)

    config_content = f"""
    [CONFIGURATION]
    output_format = N-TRIPLES
    [data_source]
    mappings = {temp_dir}/mapping.yaml
    file_path = {json_path}
    """
    config_path = temp_dir / "config.ini"
    with open(config_path, "w") as f:
        f.write(config_content)

    logging.info("Generating RDF triples...")
    return morph_kgc.materialize(str(config_path))