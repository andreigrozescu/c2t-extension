import subprocess
import shutil
import json
import logging
import socket
from pathlib import Path
from . import inspect_parser, syft_parser
import morph_kgc
import rdflib

MAPPINGS_DIR = Path(__file__).parent.parent / "mappings"

def sanitize(s: str) -> str:
    if s is None: return ""
    return str(s).replace(":", "_").replace("/", "_")

def clean_rdf_string(s: str) -> str:
    return str(s).replace('"', "'").replace("\\", "\\\\").replace("\n", "\\n").replace("\t", " ")

def process_docker_history(history_path: Path, image_safe_name: str) -> dict:
    if not history_path.exists():
        return {"full_content": "", "steps": []}
    steps = []
    commands = []
    try:
        with open(history_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        for index, line in enumerate(reversed(lines)):
            cmd = line.strip()
            if not cmd: continue
            clean_cmd = cmd.replace("/bin/sh -c #(nop) ", "").replace("/bin/sh -c ", "RUN ")
            steps.append({
                "step_id": f"step_{image_safe_name}_{index+1}",
                "order": index + 1,
                "instruction": clean_rdf_string(clean_cmd),
                "image_identifier": image_safe_name
            })
            commands.append(clean_cmd)
        full_content = "\n".join(commands)
        return {"full_content": clean_rdf_string(full_content), "steps": steps}
    except Exception as e:
        return {"full_content": "", "steps": []}

def generate_unified_json(temp_dir: Path, containers_data: list, images_to_analyze: list) -> dict:
    unified_data = {
        "host": [], "containers": [], "images": [], "layers": [],
        "image_layer_relations": [], "dockerfiles": [], "dockerfile_steps": [],
        "os": [], "packages": [], "vulnerabilities": [], "pkg_vuln_relations": [] 
    }

    hostname = socket.gethostname().strip()
    unified_data["host"].append({"id": hostname, "ip": "127.0.0.1", "architecture": "x86_64"})

    # Containers
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

    # Images
    for image_name in images_to_analyze:
        safe_name = sanitize(image_name)
        
        image_layers_ids = []
        created = ""
        arch = "unknown"
        size = 0
        
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
                    raw_layers = idata.get('RootFS', {}).get('Layers', [])
                    image_layers_ids = [sanitize(l) for l in raw_layers]
            except: pass

        if not created or created.lower() == "none": created = ""
        
        unified_data["images"].append({
            "identifier": safe_name, 
            "raw_identifier": image_name,
            "architecture": arch, 
            "created": created,
            "size": size
        })

        history_file = temp_dir / f"history_{safe_name}.txt"
        processed_history = process_docker_history(history_file, safe_name)
        dockerfile_id = f"dockerfile_{safe_name}"
        unified_data["dockerfiles"].append({
            "id": dockerfile_id, "image_identifier": safe_name,
            "label": f"Dockerfile for {image_name}",
            "content": processed_history["full_content"]
        })
        for step in processed_history["steps"]:
            step["dockerfile_id"] = dockerfile_id
            unified_data["dockerfile_steps"].append(step)

        for layer_id in image_layers_ids:
            unified_data["image_layer_relations"].append({
                "image_identifier": safe_name, "layer_id": layer_id
            })
            if not any(l['id'] == layer_id for l in unified_data["layers"]):
                 unified_data["layers"].append({"id": layer_id, "size": 0})

        syft_file = temp_dir / f"syft_{safe_name}.json"
        grype_file = temp_dir / f"grype_{safe_name}.json"

        artifacts = syft_parser.parse_image_artifacts(str(syft_file), str(grype_file), image_name)

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