#!/usr/bin/env python3
import click
import logging
import re
import sys
import traceback
from pathlib import Path
from urllib.parse import unquote
from . import logic, queries

# Configure logging with timestamps
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%H:%M:%S')

# Path to the RDF Knowledge Graph
OUTPUT_FILE = Path(__file__).parent.parent / "output" / "docker_graph.nt"

# Definition of severity levels for filtering
SEVERITY_LEVELS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "NEGLIGIBLE": 1,
    "UNKNOWN": 0
}

# --- MAIN CLI GROUP ---
@click.group(epilog="Run 'c2t COMMAND --help' for more information on a specific command.")
def cli():
    """
    \b
    C2T: Tool for Docker Security Auditing and Forensic Traceability.
    -----------------------------------------------------------------
    Generates Knowledge Graphs from Docker containers to analyze 
    vulnerabilities and software composition (SBOM).
    """
    pass

# --- PROCESS COMMAND ---
@cli.command(short_help="Analyzes host and generates graph.")
@click.option('--force', is_flag=True, help="Forces full graph regeneration.")
def process(force):
    """Analyzes the current Docker Host state."""
    click.echo(click.style("Starting Docker Host analysis...", fg='green'))
    logic.process_incremental(OUTPUT_FILE, force_rebuild=force)

# --- HELPER FUNCTIONS ---

def get_query_engine():
    """Initializes the query engine or exits if graph is missing."""
    if not OUTPUT_FILE.exists():
        click.echo(click.style("Error: The graph does not exist. Run 'c2t process' first.", fg='red'))
        sys.exit(1)
    return queries.QueryEngine(OUTPUT_FILE)

def extract_name_from_uri(uri_str):
    """Extracts the package name from a PURL URI."""
    try:
        decoded = unquote(str(uri_str))
        if "pkg:" in decoded:
            purl_part = decoded.split("pkg:")[-1]
            if "/" in purl_part: 
                name_ver = purl_part.split("/")[-1]
            else: 
                name_ver = purl_part
            return name_ver.split("@")[0]
    except: 
        pass
    return "Unknown Package"

def split_package_version(pkg_name, version):
    """Splits name and version if they are combined."""
    pkg = str(pkg_name)
    ver = str(version) if version else "unknown"
    
    is_invalid_ver = ver.lower() in ["none", "unknown", "n/a", ""]
    if is_invalid_ver and " " in pkg:
        try:
            parts = pkg.split(" ", 1)
            if len(parts) > 1 and (parts[1][0].isdigit() or parts[1].lower().startswith('v')):
                return parts[0], parts[1]
        except: 
            pass
    return pkg, ver

def format_ports(ports_str):
    """Formats the raw ports string from Docker."""
    s = str(ports_str)
    if not s or s == "{}" or "None" in s:
        raw = re.findall(r"(\d+/(?:tcp|udp))", s)
        if raw: return ", ".join(sorted(set(raw)))
        return ""
    try:
        mappings = re.findall(r"'HostPort':\s*'(\d+)'", s)
        internal = re.findall(r"'(\d+/(?:tcp|udp))':", s)
        if mappings and internal:
            pairs = []
            for i, m in enumerate(mappings):
                if i < len(internal): 
                    pairs.append(f"{m}->{internal[i]}")
            return ", ".join(pairs)
        
        raw_keys = re.findall(r"['\"](\d+/(?:tcp|udp))['\"]", s)
        if raw_keys: return ", ".join(sorted(set(raw_keys)))
        
        raw = re.findall(r"(\d+/(?:tcp|udp))", s)
        return ", ".join(sorted(set(raw)))
    except: 
        return ""

# --- COMMANDS ---

@cli.command(name='list', short_help="Lists deployed containers.")
@click.option('--running', is_flag=True, help="Show only running containers.")
def list_containers(running):
    """Lists deployed containers."""
    qe = get_query_engine()
    results = qe.list_containers()
    
    total = len(results)
    stats = {"running": 0, "exited": 0, "paused": 0}
    filtered_results = []
    
    # Process results for stats and filtering
    for r in results:
        status_val = getattr(r, 'status', 'unknown')
        s = str(status_val).lower()
        
        # Count stats
        if "up" in s or "running" in s: stats["running"] += 1
        elif "exited" in s: stats["exited"] += 1
        else: stats["paused"] += 1
        
        # Apply filter 
        if running:
            if "up" in s or "running" in s:
                filtered_results.append(r)
        else:
            filtered_results.append(r)

    click.echo(click.style(f"\n[CONTAINER SUMMARY]", bold=True))
    click.echo(f"Total: {total} | ", nl=False)
    click.echo(click.style(f"Running: {stats['running']}", fg='green') + " | ", nl=False)
    click.echo(click.style(f"Exited: {stats['exited']}", fg='red') + " | ", nl=False)
    click.echo(click.style(f"Other: {stats['paused']}", fg='yellow'))
    
    if running:
        click.echo(click.style("Filter active: Showing only running containers.", fg='cyan'))

    click.echo("")
    header = f"{'HOST':<12} {'CONTAINER NAME':<25} {'ID':<14} {'IMAGE':<30} {'STATUS':<12} {'PORTS'}"
    click.echo(header)
    click.echo("-" * 120)
    
    for row in filtered_results:
        host = str(getattr(row, 'hostName', 'local'))
        n_val = getattr(row, 'name', 'n/a')
        id_val = getattr(row, 'id', 'n/a')
        img_val = getattr(row, 'imageName', 'unknown')
        stat_val = getattr(row, 'status', 'unknown')
        ports_val = getattr(row, 'ports', '')

        name = str(n_val)[:23] + ".." if len(str(n_val)) > 24 else str(n_val)
        c_id = str(id_val)[:12]
        image = str(img_val)[:28] + ".." if len(str(img_val)) > 29 else str(img_val)
        status = str(stat_val)
        ports = format_ports(ports_val)
        
        click.echo(f"{host:<12} {name:<25} {c_id:<14} {image:<30} {status:<12} {ports}")

@cli.command(short_help="Audits security (Containers OR Images).")
@click.argument('target')
@click.option('--filter', is_flag=True, help="Show only HIGH and CRITICAL vulnerabilities.")
def assess(target, filter):
    """Evaluates vulnerabilities."""
    qe = get_query_engine()
    
    # 1. Metadata
    meta_res = qe.get_target_metadata(target)
    arch, size, created, os_str = "Unknown", "Unknown", "Unknown", "Unknown"
    
    for row in meta_res:
        a = getattr(row, 'arch', None)
        s = getattr(row, 'size', None)
        c = getattr(row, 'created', None)
        on = getattr(row, 'osName', None)
        ov = getattr(row, 'osVer', None)

        if a: arch = str(a)
        if s: size = str(s)
        if c: created = str(c)
        if on:
            os_str = str(on)
            if ov: os_str += f" {ov}"
    
    # 2. Stats
    count_res = qe.get_total_package_count(target)
    total_pkgs = 0
    for row in count_res:
        pc = getattr(row, 'pkgCount', 0)
        try: total_pkgs = int(pc)
        except: pass

    click.echo(click.style(f"\n[ASSESS SUMMARY] Target: {target}", bold=True))
    click.echo(f"Architecture: {arch}")
    click.echo(f"Size: {size}")
    click.echo(f"Operative system: {os_str}")
    click.echo(f"Creation time: {created}")
    click.echo(f"Total Packages: {total_pkgs}")
    click.echo("")

    # 3. Vulnerabilities
    raw_results = qe.assess_target(target)
    results = [row for row in raw_results]
    
    if not results:
        click.echo(f"No vulnerabilities found for '{target}' (or target not in graph).")
        return

    # Filter logic
    final_results = []
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Negligible': 0, 'Unknown': 0}
    
    for row in results:
        sev_raw = str(getattr(row, 'severity', 'Unknown'))
        sev_str = sev_raw.capitalize()
        
        if sev_str not in counts: sev_str = 'Unknown'
        counts[sev_str] += 1
        
        # Apply filter
        if filter:
            score = SEVERITY_LEVELS.get(sev_raw.upper(), 0)
            # High and Critical
            if score >= 4:
                final_results.append(row)
        else:
            final_results.append(row)

    total_vulns = len(results)
    summary_parts = []
    for s in ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']:
        if counts[s] > 0:
            c = 'red' if s in ['Critical', 'High'] else 'magenta' if s == 'Medium' else 'yellow' if s == 'Low' else 'white'
            summary_parts.append(click.style(f"{s}: {counts[s]}", fg=c))
    
    click.echo(f"Vulnerabilities ({total_vulns}): " + " | ".join(summary_parts))
    
    if filter:
        click.echo(click.style("Filter active: Showing HIGH and CRITICAL only.", fg='cyan'))
    
    click.echo("")
    click.echo(f"{'SEVERITY':<12} {'PKG NAME':<35} {'VULN ID':<20}")
    click.echo("-" * 70)
    
    for row in final_results:
        sev = str(getattr(row, 'severity', 'Unknown'))
        vuln = str(getattr(row, 'vulnID', ''))
        raw_pkg = str(getattr(row, 'pkgName', 'Unknown'))
        pkg_uri = getattr(row, 'pkgURI', '')

        if raw_pkg == "Unknown" and pkg_uri:
            pkg = extract_name_from_uri(pkg_uri)
        else:
            pkg, _ = split_package_version(raw_pkg, "unknown")
        
        color = 'white'
        if sev == 'Critical': color = 'red'
        elif sev == 'High': color = 'magenta' 
        elif sev == 'Medium': color = 'yellow' 
        
        click.echo(click.style(f"{sev:<12}", fg=color) + f"{pkg:<35} {vuln:<20}")

@cli.command(short_help="Compares libraries between images.")
@click.argument('img1')
@click.argument('img2')
def diff(img1, img2):
    """Compares two images (Metadata + Unified Library Table)."""
    try:
        qe = get_query_engine()
        
        # --- 1. METADATA ---
        def get_meta(img_name):
            d = {"arch": "Unknown", "size": "Unknown", "os": "Unknown", "created": "Unknown", "vulns": "0"}
            res = qe.get_image_metadata(img_name)
            for row in res:
                if getattr(row, 'arch', None): d["arch"] = str(row.arch)
                if getattr(row, 'size', None): d["size"] = str(row.size)
                if getattr(row, 'created', None): d["created"] = str(row.created)
                on = getattr(row, 'osName', None)
                ov = getattr(row, 'osVer', None)
                if on:
                    val = str(on)
                    if ov: val += " " + str(ov)
                    d["os"] = val.strip()
            
            v_res = qe.get_image_vuln_count(img_name)
            for row in v_res:
                if getattr(row, 'vCount', None): d["vulns"] = str(row.vCount)
            return d

        m1 = get_meta(img1)
        m2 = get_meta(img2)

        click.echo(click.style(f"\n[MAIN COMPARISON]", bold=True))
        click.echo(f"{'tags':<15} {img1:<40} {img2:<40}")
        click.echo("-" * 95)
        click.echo(f"{'architecture':<15} {m1['arch']:<40} {m2['arch']:<40}")
        click.echo(f"{'size':<15} {m1['size']:<40} {m2['size']:<40}")
        click.echo(f"{'osDescription':<15} {m1['os']:<40} {m2['os']:<40}")
        click.echo(f"{'created':<15} {m1['created']:<40} {m2['created']:<40}")
        click.echo(f"{'vulnerabilities':<15} {m1['vulns']:<40} {m2['vulns']:<40}")
        click.echo("")

        # --- 2. PACKAGES ---
        def get_pkgs_dict(img_name):
            d = {}
            for row in qe.get_image_packages_simple(img_name):
                p_name = str(getattr(row, 'pkgName', ''))
                v = getattr(row, 'version', None)
                p_ver = str(v) if v else "unknown"
                n, v = split_package_version(p_name, p_ver)
                d[n] = v
            return d

        p1 = get_pkgs_dict(img1)
        p2 = get_pkgs_dict(img2)
        all_keys = sorted(list(set(p1.keys()) | set(p2.keys())))

        # --- 3. UNIFIED TABLE ---
        click.echo(click.style(f"[LIBRARIES COMPARISON]", bold=True))
        
        col1_w = 40
        col2_w = 35
        col3_w = 35
        
        h1 = (img1[:32] + '..') if len(img1) > 33 else img1
        h2 = (img2[:32] + '..') if len(img2) > 33 else img2
        
        click.echo(f"{'LIBRARY':<{col1_w}} {h1:<{col2_w}} {h2:<{col3_w}}")
        click.echo("-" * (col1_w + col2_w + col3_w))

        for lib in all_keys:
            ver1 = p1.get(lib)
            ver2 = p2.get(lib)

            # colors
            # V1
            if ver1 is None:
                txt1 = click.style("None", fg='red')
                len1 = 4
            else:
                c = 'green' if (ver1 == ver2) else 'yellow'
                txt1 = click.style(ver1, fg=c)
                len1 = len(ver1)

            # V2
            if ver2 is None:
                txt2 = click.style("None", fg='red')
            else:
                c = 'green' if (ver1 == ver2) else 'yellow'
                txt2 = click.style(ver2, fg=c)
            
            click.echo(f"{lib:<{col1_w}}", nl=False)
            
            pad1 = col2_w - len1
            if pad1 < 1: pad1 = 1
            click.echo(txt1 + (" " * pad1), nl=False)
            
            click.echo(txt2)

        click.echo("")
        sys.exit(0)

    except Exception:
        traceback.print_exc()
        sys.exit(1)

@cli.command(short_help="Finds containers affected by a library.")
@click.argument('lib')
def search_lib(lib):
    """Finds which deployed containers depend on a specific library."""
    qe = get_query_engine()
    results = qe.affected_containers_by_lib(lib)
    if not results:
        click.echo(f"No containers found using library: '{lib}'")
        return
    unique = set(str(getattr(row, 'containerName', '')) for row in results)
    click.echo(click.style(f"\n[SEARCH RESULTS] Library: {lib}", bold=True))
    click.echo(f"Total Matches: {len(results)} | Affected Containers: {len(unique)}")
    click.echo("")
    header = f"{'CONTAINER':<25} {'IMAGE':<30} {'PACKAGE MATCH':<25} {'VERSION'}"
    click.echo(header)
    click.echo("-" * 100)
    for row in results:
        cont = str(getattr(row, 'containerName', ''))
        img = str(getattr(row, 'imageName', ''))
        pkg_val = str(getattr(row, 'pkgName', 'Unknown'))
        v = getattr(row, 'version', None)
        ver_val = str(v) if v else "unknown"
        pkg, ver = split_package_version(pkg_val, ver_val)
        click.echo(f"{cont:<25} {img:<30} {pkg:<25} {ver}")

@cli.command(short_help="Finds images containing an app.")
@click.argument('app')
def search_app(app):
    """Finds which images contain a specific application installed."""
    qe = get_query_engine()
    results = qe.images_with_app(app)
    if not results:
        click.echo(f"No images found containing application: '{app}'")
        return
    click.echo(click.style(f"\n[SEARCH RESULTS] Application: {app}", bold=True))
    click.echo(f"Total Images Found: {len(results)}")
    click.echo("")
    header = f"{'IMAGE':<35} {'VERSION'}"
    click.echo(header)
    click.echo("-" * 50)
    for row in results:
        img = str(getattr(row, 'imageName', ''))
        v = getattr(row, 'version', None)
        ver_val = str(v) if v else "unknown"
        _, ver = split_package_version("temp", ver_val)
        click.echo(f"{img:<35} {ver if ver != 'unknown' else ver_val}")

@cli.command(short_help="Shows image SBOM.")
@click.argument('image')
def show_libs(image):
    """Lists all libraries (SBOM) in a specific image."""
    qe = get_query_engine()
    results = qe.image_libraries(image)
    click.echo(click.style(f"\n[SBOM SUMMARY] Image: {image}", bold=True))
    click.echo(f"Total Packages Installed: {len(results)}")
    click.echo("")
    if not results: return
    click.echo(f"{'PACKAGE NAME':<40} {'VERSION'}")
    click.echo("-" * 60)
    for row in results:
        pkg_val = getattr(row, 'pkgName', 'Unknown')
        ver_val = getattr(row, 'version', 'unknown')
        pkg, ver = split_package_version(pkg_val, ver_val)
        click.echo(f"{pkg:<40} {ver}")

@cli.command(short_help="Operating Systems report.")
def report_os():
    """Lists the Operating System families detected in the images."""
    qe = get_query_engine()
    results = qe.images_os()
    distros = set(str(getattr(row, 'osName', 'Unknown')) for row in results)
    click.echo(click.style(f"\n[OS REPORT SUMMARY]", bold=True))
    click.echo(f"Total Images: {len(results)} | OS Families: {', '.join(distros)}")
    click.echo("")
    click.echo(f"{'IMAGE':<30} {'OS FAMILY'}")
    click.echo("-" * 60)
    for row in results:
        img = str(getattr(row, 'imageName', ''))
        os_n = str(getattr(row, 'osName', ''))
        click.echo(f"{img:<30} {os_n}")

@cli.command(short_help="Shows image metadata.")
def metadata():
    """
    Shows detailed metadata for all images in the graph.
    Includes Creation Date, Architecture, and the reconstructed Dockerfile.
    """
    qe = get_query_engine()
    results = qe.image_metadata()
    click.echo(click.style(f"\n[METADATA REPORT]", bold=True))
    click.echo(f"Analyzed Images: {len(results)}")
    for row in results:
        click.echo("\n" + "="*60)
        img = str(getattr(row, 'imageName', ''))
        c_val = getattr(row, 'created', None)
        created = str(c_val) if c_val else "Unknown"
        arch = str(getattr(row, 'arch', 'unknown'))
        click.echo(f"IMAGE:   {img}")
        click.echo(f"CREATED: {created}")
        click.echo(f"ARCH:    {arch}")
        
        h = getattr(row, 'history', None)
        if h:
            click.echo("-" * 20)
            click.echo("BUILD HISTORY:")
            click.echo(str(h).replace('\\n', '\n'))

if __name__ == '__main__':
    cli()