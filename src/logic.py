import subprocess
import shutil
import logging
import tempfile
import rdflib
from pathlib import Path
from . import unifier

# Directory where mapping files are stored
MAPPINGS_DIR = Path(__file__).parent.parent / "mappings"

def sanitize_cli_name(n: str) -> str:
    """Sanitizes names for filenames."""
    return n.replace(":", "_").replace("/", "_")

def check_dependencies():
    """Checks if external tools (docker, syft, grype) are available in PATH."""
    for cmd in ["docker", "syft", "grype"]:
        if not shutil.which(cmd):
            raise EnvironmentError(f"{cmd} not found. Please install it.")

def run_command(command, output_file=None, allow_nonzero=False):
    """
    Executes a shell command safely.
    
    Args:
        command (list): The command to run.
        output_file (Path, optional): File to write stdout to.
        allow_nonzero (bool): If True, suppresses error on non-zero exit codes (useful for Grype).
    """
    # Force quiet mode for syft/grype
    if "syft" in command or "grype" in command:
        if "-q" not in command: command.append("-q")
    try:
        if output_file:
            with open(output_file, "w", encoding='utf-8') as f:
                subprocess.run(command, stdout=f, stderr=subprocess.PIPE, check=True, text=True)
        else:
            subprocess.run(command, capture_output=True, check=True, text=True)
    except subprocess.CalledProcessError:
        if not allow_nonzero: raise

def get_docker_state():
    """Returns lists of containers and images found on the host."""
    # Get Containers
    cmd = ["docker", "ps", "-a", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    containers = []
    for line in res.stdout.strip().splitlines():
        if line:
            parts = line.split("\t")
            containers.append({'id': parts[0], 'image': parts[1], 'name': parts[2], 'status': parts[3]})
            
    # Get Images
    cmd_i = ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]
    res_i = subprocess.run(cmd_i, capture_output=True, text=True, check=True)
    images = set()
    for line in res_i.stdout.strip().splitlines():
        if line and "<none>" not in line:
            images.add(line)
            
    return containers, sorted(list(images))

def get_analyzed_images(graph_path: Path):
    """Checks the existing graph to see which images have already been analyzed."""
    if not graph_path.exists():
        return set()
    g = rdflib.Graph()
    try:
        g.parse(str(graph_path), format="nt")
        q = """SELECT DISTINCT ?label WHERE { ?img a <https://w3id.org/c2t/o#Image> ; <http://www.w3.org/2000/01/rdf-schema#label> ?label . }"""
        analyzed = set()
        for row in g.query(q):
            analyzed.add(str(row.label))
        return analyzed
    except Exception:
        return set()

def process_incremental(output_graph_path: Path, force_rebuild=False):
    """
    Main orchestration logic.
    1. Checks host state.
    2. Compares with existing graph (Incremental update).
    3. Runs Syft, Grype, Docker inspect and Docker history for new items.
    4. Unifies data and generates RDF triples.
    """
    check_dependencies()
    
    containers, current_images = get_docker_state()
    logging.info(f"Host State: {len(containers)} containers, {len(current_images)} images.")

    if force_rebuild and output_graph_path.exists():
        output_graph_path.unlink()
        existing_images = set()
    else:
        existing_images = get_analyzed_images(output_graph_path)
    
    # Calculate delta
    images_to_process = [img for img in current_images if img not in existing_images]
    
    if not images_to_process and not force_rebuild and output_graph_path.exists():
        logging.info("Graph is up to date.")
        return

    logging.info(f"Analyzing {len(images_to_process)} new images...")

    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        
        # Analyze Containers
        for c in containers:
            run_command(["docker", "inspect", c['id']], temp_dir / f"inspect_{c['id']}.json")

        # Analyze Images
        for img in images_to_process:
            safe = sanitize_cli_name(img)
            logging.info(f"Processing: {img}")
            
            run_command(["syft", img, "-o", "json"], temp_dir / f"syft_{safe}.json")
            run_command(["grype", img, "-o", "json"], temp_dir / f"grype_{safe}.json", allow_nonzero=True)
            run_command(["docker", "inspect", img], temp_dir / f"image_inspect_{safe}.json")
            run_command(["docker", "history", img, "--no-trunc", "--format", "{{json .}}"], temp_dir / f"history_{safe}.json")

        # Unify data into a single JSON structure
        new_graph = unifier.generate_unified_json(temp_dir, containers, images_to_process)

    # Merge with existing graph
    main_graph = rdflib.Graph()
    if output_graph_path.exists():
        main_graph.parse(str(output_graph_path), format="nt")
    
    main_graph += new_graph
    
    output_graph_path.parent.mkdir(exist_ok=True)
    main_graph.serialize(destination=str(output_graph_path), format="nt", encoding="utf-8")
    logging.info(f"Graph updated at {output_graph_path}")