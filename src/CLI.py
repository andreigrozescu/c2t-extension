#!/usr/bin/env python3
import click
import logging
import re
import sys
import traceback
from pathlib import Path
from urllib.parse import unquote
from . import logic, queries

# Configuration for logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%H:%M:%S')

# Path to the final Knowledge Graph file
OUTPUT_FILE = Path(__file__).parent.parent / "output" / "docker_graph.nt"

# Severity scoring for sorting vulnerabilities
SEVERITY_LEVELS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "NEGLIGIBLE": 1,
    "UNKNOWN": 0
}

@click.group(epilog="Run 'c2t COMMAND --help' for more information.")
def cli():
    """
    C2T: Containers to Triples - Forensic & Security Analysis Tool.
    """
    pass

@cli.command(short_help="Analyzes host and generates graph.")
@click.option('--force', is_flag=True, help="Forces full graph regeneration (discards previous data).")
def process(force):
    """
    Analyzes the host state and generates the Knowledge Graph.

    \b
    USAGE:
        c2t process [OPTIONS]

    \b
    OPTIONS NOTE:
        Options must be placed AFTER the command.

    \b
    EXAMPLES:
        c2t process
        c2t process --force  (Rebuilds the graph from scratch)
    """
    click.echo(click.style("Starting Docker Host analysis...", fg='green'))
    logic.process_incremental(OUTPUT_FILE, force_rebuild=force)

def get_query_engine():
    """Initializes the Query Engine if the graph exists."""
    if not OUTPUT_FILE.exists():
        click.echo(click.style("Error: The graph does not exist. Run 'c2t process' first.", fg='red'))
        sys.exit(1)
    return queries.QueryEngine(OUTPUT_FILE)

# --- HELPERS ---

def sizeof_fmt(num):
    """Calculates human-readable size (Base 10 to match Docker CLI)."""
    try:
        num = float(num)
    except (ValueError, TypeError):
        return "0 B"
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num) < 1000.0:
            return f"{num:3.1f} {unit}"
        num /= 1000.0
    return f"{num:.1f} TB"

def extract_name_from_uri(uri_str):
    """Extracts a readable package name from a PURL URI."""
    try:
        decoded = unquote(str(uri_str))
        if "pkg:" in decoded:
            purl_part = decoded.split("pkg:")[-1]
            if "/" in purl_part: name_ver = purl_part.split("/")[-1]
            else: name_ver = purl_part
            return name_ver.split("@")[0]
    except: pass
    return "Unknown Package"

def split_package_version(pkg_name, version):
    """Splits package name and version if version is merged in the name."""
    pkg = str(pkg_name)
    ver = str(version) if version else "unknown"
    if ver.lower() in ["none", "unknown", "n/a", ""] and " " in pkg:
        try:
            parts = pkg.split(" ", 1)
            if len(parts) > 1 and (parts[1][0].isdigit() or parts[1].lower().startswith('v')):
                return parts[0], parts[1]
        except: pass
    return pkg, ver

def format_ports(ports_str):
    """Formats the raw ports string from Docker inspect into a readable string."""
    s = str(ports_str)
    if not s or s == "{}" or "None" in s:
        # Fallback to regex extraction if dict parsing fails
        raw = re.findall(r"(\d+/(?:tcp|udp))", s)
        if raw: return ", ".join(sorted(set(raw)))
        return ""
    try:
        # Extract host mappings and internal ports
        mappings = re.findall(r"'HostPort':\s*'(\d+)'", s)
        internal = re.findall(r"'(\d+/(?:tcp|udp))':", s)
        if mappings and internal:
            pairs = []
            for i, m in enumerate(mappings):
                if i < len(internal): pairs.append(f"{m}->{internal[i]}")
            return ", ".join(pairs)
        raw_keys = re.findall(r"['\"](\d+/(?:tcp|udp))['\"]", s)
        if raw_keys: return ", ".join(sorted(set(raw_keys)))
        raw = re.findall(r"(\d+/(?:tcp|udp))", s)
        return ", ".join(sorted(set(raw)))
    except: return ""

# --- COMMANDS ---

@cli.command(name='list', short_help="Lists deployed containers.")
@click.option('--running', is_flag=True, help="Show only running containers.")
def list_containers(running):
    """
    Lists deployed containers found in the graph.

    \b
    USAGE:
        c2t list [OPTIONS]

    \b
    OPTIONS NOTE:
        Options must be placed AFTER the command.

    \b
    EXAMPLES:
        c2t list            (Show all containers)
        c2t list --running  (Show only active containers)
    """
    qe = get_query_engine()
    results = qe.list_containers()
    
    total = len(results)
    stats = {"running": 0, "exited": 0, "paused": 0}
    filtered_results = []

    # Calculate statistics and filter results
    for r in results:
        status_val = getattr(r, 'status', 'unknown')
        s = str(status_val).lower()
        if "up" in s or "running" in s: stats["running"] += 1
        elif "exited" in s: stats["exited"] += 1
        else: stats["paused"] += 1
        
        if running:
            if "up" in s or "running" in s: filtered_results.append(r)
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
        img_val = getattr(row, 'displayImage', None) or getattr(row, 'imageName', 'Unknown')
        stat_val = getattr(row, 'status', 'unknown')
        ports_val = getattr(row, 'ports', '')

        name = str(n_val)[:23] + ".." if len(str(n_val)) > 24 else str(n_val)
        c_id = str(id_val)[:12]
        image = str(img_val)[:28] + ".." if len(str(img_val)) > 29 else str(img_val)
        status = str(stat_val)
        ports = format_ports(ports_val)
        click.echo(f"{host:<12} {name:<25} {c_id:<14} {image:<30} {status:<12} {ports}")

@cli.command(short_help="Assess security of containers and images.")
@click.argument('target')
@click.option('--filter', is_flag=True, help="Show only HIGH and CRITICAL vulnerabilities.")
@click.option('--fixable', is_flag=True, help="Show only vulnerabilities with a fix available.")
def assess(target, filter, fixable):
    """
    Evaluates vulnerabilities for a specific TARGET (Image name or Container name).

    \b
    USAGE:
        c2t assess <TARGET> [OPTIONS]

    \b
    IMPORTANT:
        Options/Flags must be placed AFTER the target argument.

    \b
    COMBINING OPTIONS:
        You can combine multiple options in the same command.
        Example: Filter for High/Critical AND only Fixable ones.

    \b
    EXAMPLES:
        c2t assess nginx:latest
        c2t assess nginx:latest --filter
        c2t assess webvowl_server_1 --fixable
        c2t assess webvowl_server_1 --filter --fixable
    """
    qe = get_query_engine()
    
    # 1. Metadata
    meta_res = qe.get_target_metadata(target)
    
    data = {
        "type": "Unknown",
        "arch": "Unknown",
        "size": "Unknown",
        "os": "Unknown",
        "created": "Unknown",
        "status": None,
        "ports": None,
        "image": None
    }
    
    for row in meta_res:
        if getattr(row, 'type', None): data["type"] = str(row.type)
        if getattr(row, 'arch', None): data["arch"] = str(row.arch)
        if getattr(row, 'size', None): data["size"] = str(row.size)
        if getattr(row, 'created', None): data["created"] = str(row.created)
        
        on = getattr(row, 'osName', None)
        ov = getattr(row, 'osVer', None)
        if on:
            val = str(on)
            if ov: val += " " + str(ov)
            data["os"] = val.strip()

        if getattr(row, 'status', None): data["status"] = str(row.status)
        if getattr(row, 'ports', None): data["ports"] = format_ports(str(row.ports))
        if getattr(row, 'imageName', None): data["image"] = str(row.imageName)
    
    # 2. Package Count
    count_res = qe.get_total_package_count(target)
    total_pkgs = 0
    for row in count_res:
        pc = getattr(row, 'pkgCount', 0)
        try: total_pkgs = int(pc)
        except: pass

    # --- PRINT HEADER ---
    type_label = f" ({data['type']})" if data['type'] != "Unknown" else ""
    click.echo(click.style(f"\n[ASSESS SUMMARY] Target: {target}{type_label}", bold=True))
    click.echo(f"Architecture: {data['arch']}")
    click.echo(f"Size: {data['size']}")
    click.echo(f"Operative system: {data['os']}")
    click.echo(f"Creation time: {data['created']}")
    
    if data['type'] == "Container":
        s_color = 'green' if 'up' in str(data['status']).lower() else 'red'
        click.echo(f"Status: " + click.style(f"{data['status']}", fg=s_color))
        if data['ports']:
            click.echo(f"Ports: {data['ports']}")
        if data['image']:
            click.echo(f"Base Image: {data['image']}")
    
    click.echo(f"Total Packages: {total_pkgs}")
    click.echo("")

    # --- VULNERABILITIES ---
    raw_results = qe.assess_target(target)
    results = [row for row in raw_results]
    
    if not results:
        click.echo(f"No vulnerabilities found for '{target}' (or target not in graph).")
        return

    filtered_results = []
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Negligible': 0, 'Unknown': 0}
    
    # Filter and count statistics
    for row in results:
        sev_raw = str(getattr(row, 'severity', 'Unknown'))
        sev_str = sev_raw.capitalize()
        
        if sev_str not in counts: sev_str = 'Unknown'
        counts[sev_str] += 1
        
        include = True
        if filter:
            score = SEVERITY_LEVELS.get(sev_raw.upper(), 0)
            if score < 4: include = False
        if fixable:
            fix_val = str(getattr(row, 'fixedIn', ''))
            if not fix_val or fix_val == "None" or fix_val == "": include = False

        if include:
            filtered_results.append(row)

    total_vulns = len(results)
    summary_parts = []
    for s in ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']:
        if counts[s] > 0:
            c = 'red' if s in ['Critical', 'High'] else 'magenta' if s == 'Medium' else 'yellow' if s == 'Low' else 'white'
            summary_parts.append(click.style(f"{s}: {counts[s]}", fg=c))
    
    click.echo(f"Vulnerabilities ({total_vulns}): " + " | ".join(summary_parts))
    if filter: click.echo(click.style("Filter active: Showing HIGH and CRITICAL only.", fg='cyan'))
    if fixable: click.echo(click.style("Filter active: Showing only FIXABLE vulnerabilities.", fg='cyan'))
    click.echo("")

    # ORDER: SEVERITY | SCORE | VULN ID | TYPE | PKG NAME | VERSION | FIXED IN
    click.echo(f"{'SEV':<10} {'SCORE':<6} {'VULN ID':<20} {'TYPE':<12} {'PKG NAME':<25} {'VERSION':<15} {'FIXED IN'}")
    click.echo("-" * 110)
    for row in filtered_results:
        sev = str(getattr(row, 'severity', 'Unknown'))
        vuln = str(getattr(row, 'vulnID', ''))
        score = str(getattr(row, 'score', '-'))
        fixed = str(getattr(row, 'fixedIn', '-'))
        if fixed == "None" or not fixed: fixed = "-"
        v_type = str(getattr(row, 'vulnType', 'unk'))[:8]
        raw_pkg = str(getattr(row, 'pkgName', 'Unknown'))
        pkg_ver = str(getattr(row, 'pkgVersion', ''))
        pkg_uri = getattr(row, 'pkgURI', '')
        
        if raw_pkg == "Unknown" and pkg_uri: 
            pkg = extract_name_from_uri(pkg_uri)
        else: 
            pkg, v_split = split_package_version(raw_pkg, "unknown")
            if not pkg_ver: pkg_ver = v_split

        color = 'white'
        if sev == 'Critical': color = 'red'
        elif sev == 'High': color = 'magenta' 
        elif sev == 'Medium': color = 'yellow' 
        
        click.echo(click.style(f"{sev:<10}", fg=color) + f"{score:<6} {vuln:<20} {v_type:<12} {pkg:<25} {pkg_ver:<15} {fixed}")

@cli.command(name='check-pkg', short_help="Audits a specific package across all versions.")
@click.argument('pkg_name')
def check_pkg(pkg_name):
    """
    Shows a detailed vulnerability report for a specific PACKAGE, grouped by version.
    Useful to compare which versions in your infrastructure are vulnerable vs safe.

    \b
    USAGE:
        c2t check-pkg <PACKAGE_NAME>

    \b
    EXAMPLES:
        c2t check-pkg musl
        c2t check-pkg openssl
    """
    qe = get_query_engine()
    results = qe.audit_package_versions(pkg_name)
    
    if not results:
        click.echo(f"No packages found matching '{pkg_name}'.")
        return

    data = {}
    
    # Organize data by PackageName -> Version -> Vulnerabilities
    for row in results:
        name = str(getattr(row, 'pkgName', 'Unknown'))
        ver = str(getattr(row, 'version', 'Unknown'))
        
        if name not in data: data[name] = {}
        if ver not in data[name]: data[name][ver] = []
        
        v_id = getattr(row, 'vulnID', None)
        if v_id:
            data[name][ver].append({
                "id": str(v_id),
                "sev": str(getattr(row, 'severity', 'Unknown')),
                "fixed": str(getattr(row, 'fixedIn', '-'))
            })

    click.echo(click.style(f"\n[PACKAGE AUDIT REPORT] Query: {pkg_name}", bold=True))
    
    for name in sorted(data.keys()):
        click.echo(click.style(f"\nLIBRARY: {name}", fg='cyan', bold=True))
        click.echo("=" * 60)
        
        for ver in sorted(data[name].keys()):
            vulns = data[name][ver]
            
            # Status label
            if not vulns:
                status_label = click.style("[SAFE]", fg='green', bold=False)
            else:
                status_label = click.style(f"[VULNERABLE: {len(vulns)}]", fg='red', bold=False)
            
            click.echo(f"\n  VERSION: {click.style(ver, bold=False)} {status_label}")
            
            if not vulns:
                click.echo(click.style("     No vulnerabilities found.", fg='green'))
            else:
                # Sort vulns by severity
                vulns.sort(key=lambda x: SEVERITY_LEVELS.get(x['sev'].upper(), 0), reverse=True)
                
                click.echo(f"     {'SEVERITY':<10} {'VULN ID':<18} {'FIXED IN'}")
                click.echo(f"     {'-'*40}")
                
                for v in vulns:
                    color = 'white'
                    s = str(v['sev'])
                    if s.lower() == 'critical': color = 'red'
                    elif s.lower() == 'high': color = 'magenta'
                    elif s.lower() == 'medium': color = 'yellow'
                    
                    fixed_val = v['fixed'] if v['fixed'] and v['fixed'] != "None" else "-"

                    click.echo(f"     {click.style(f'{s:<10}', fg=color)} {v['id']:<18} {fixed_val}")
                    
    click.echo("")

@cli.command(short_help="Shows detailed info about a vulnerability.")
@click.argument('vuln_id')
def vuln(vuln_id):
    """
    Shows detailed information (CVSS, Vector, Description, Fix) for a specific VULNERABILITY ID.
    
    Supported formats include CVE, GHSA, RHSA, etc.

    \b
    USAGE:
        c2t vuln <VULNERABILITY_ID>

    \b
    EXAMPLES:
        c2t vuln CVE-2019-14697
        c2t vuln GHSA-jfh8-c2jp-5v3q
    """
    qe = get_query_engine()
    results = qe.get_vulnerability_details(vuln_id)
    
    found = False
    for row in results:
        found = True
        v_id = str(getattr(row, 'id', vuln_id))
        sev = str(getattr(row, 'severity', 'Unknown'))
        score = str(getattr(row, 'score', 'N/A'))
        vector = str(getattr(row, 'vector', 'N/A'))
        fixed = str(getattr(row, 'fixedIn', 'N/A'))
        v_type = str(getattr(row, 'type', 'Unknown'))
        desc = str(getattr(row, 'description', 'No description available.'))
        aff_pkg = str(getattr(row, 'affectedPkg', 'Unknown'))
        if aff_pkg.startswith('pkg:'):
            aff_pkg = extract_name_from_uri(aff_pkg)

        click.echo(click.style(f"\n[VULNERABILITY DETAILS] {v_id}", bold=True))
        click.echo("-" * 60)
        
        color = 'white'
        if sev.lower() == 'critical': color = 'red'
        elif sev.lower() == 'high': color = 'magenta'
        elif sev.lower() == 'medium': color = 'yellow'
        
        click.echo(f"SEVERITY:  " + click.style(sev, fg=color))
        click.echo(f"CVSS SCORE: {score}")
        click.echo(f"TYPE:       {v_type}")
        click.echo(f"AFFECTED PKG: {aff_pkg}") 
        click.echo(f"FIXED IN:   {fixed}")
        click.echo("")
        click.echo("DESCRIPTION:")
        
        import textwrap
        wrapped_desc = textwrap.fill(desc, width=80)
        click.echo(wrapped_desc)
        click.echo("")
    
    if not found:
        click.echo(f"Vulnerability '{vuln_id}' not found in the graph.")
        return

    impact_res = qe.get_vulnerability_impact(vuln_id)
    affected = list(impact_res)
    
    if affected:
        click.echo(click.style("[AFFECTED RESOURCES]", bold=True))
        click.echo(f"{'IMAGE':<35} {'CONTAINER (INSTANCE)'}")
        click.echo("-" * 60)
        for row in affected:
            img = str(getattr(row, 'imageName', 'Unknown'))
            cont = str(getattr(row, 'containerName', '-'))
            if cont == "None": cont = "-"
            click.echo(f"{img:<35} {cont}")
    else:
        click.echo("No local images or containers affected by this vulnerability.")
    click.echo("")

@cli.command(short_help="Compares packages between images.")
@click.argument('img1')
@click.argument('img2')
def diff(img1, img2):
    """
    Compares two IMAGES side-by-side to detect version changes in packages.
    
    \b
    USAGE:
        c2t diff <IMAGE_1> <IMAGE_2>

    \b
    EXAMPLES:
        c2t diff redis:6.2-alpine redis:7.2-alpine
    """
    try:
        qe = get_query_engine()
        
        # Helper to get metadata for comparison header
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

        # Helper to get package dictionary for comparison
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

        click.echo(click.style(f"[PACKAGE COMPARISON]", bold=True))
        col1_w = 40
        col2_w = 35
        col3_w = 35
        h1 = (img1[:32] + '..') if len(img1) > 33 else img1
        h2 = (img2[:32] + '..') if len(img2) > 33 else img2
        click.echo(f"{'PACKAGE':<{col1_w}} {h1:<{col2_w}} {h2:<{col3_w}}")
        click.echo("-" * (col1_w + col2_w + col3_w))

        for lib in all_keys:
            ver1 = p1.get(lib)
            ver2 = p2.get(lib)
            if ver1 is None:
                txt1 = click.style("None", fg='red')
                len1 = 4
            else:
                c = 'green' if (ver1 == ver2) else 'yellow'
                txt1 = click.style(ver1, fg=c)
                len1 = len(ver1)
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

@cli.command(name="containers-with", short_help="Finds containers affected by a package.")
@click.argument('pkg_name')
def containers_with(pkg_name):
    """
    Finds which deployed CONTAINERS depend on a specific PACKAGE.
    
    \b
    USAGE:
        c2t containers-with <PACKAGE_NAME>
    """
    qe = get_query_engine()
    results = qe.affected_containers_by_lib(pkg_name)
    if not results:
        click.echo(f"No containers found using package: '{pkg_name}'")
        return
    unique_ids = set(str(getattr(row, 'containerName', '')) for row in results)
    click.echo(click.style(f"\n[SEARCH RESULTS] Package: {pkg_name}", bold=True))
    click.echo(f"Affected Containers: {len(unique_ids)} | Total Occurrences: {len(results)}")
    click.echo("")
    header = f"{'CONTAINER':<25} {'IMAGE':<30} {'PACKAGE MATCH':<25} {'VERSION':<20} {'VULNS'}"
    click.echo(header)
    click.echo("-" * 110)
    for row in results:
        cont = str(getattr(row, 'containerName', ''))
        img = str(getattr(row, 'imageName', ''))
        pkg_val = str(getattr(row, 'pkgName', 'Unknown'))
        v = getattr(row, 'version', None)
        ver_val = str(v) if v else "unknown"
        pkg, ver = split_package_version(pkg_val, ver_val)
        v_count = int(getattr(row, 'vulns', 0))
        v_str = click.style(str(v_count), fg='red' if v_count > 0 else 'green')
        click.echo(f"{cont:<25} {img:<30} {pkg:<25} {ver:<20} {v_str}")

@cli.command(name="images-with", short_help="Finds images containing a package.")
@click.argument('pkg_name')
def images_with(pkg_name):
    """
    Finds which IMAGES in the catalog contain a specific PACKAGE/LIBRARY.
    
    \b
    USAGE:
        c2t images-with <PACKAGE_NAME>
    """
    qe = get_query_engine()
    results = qe.images_with_app(pkg_name)
    if not results:
        click.echo(f"No images found containing package: '{pkg_name}'")
        return
    click.echo(click.style(f"\n[SEARCH RESULTS] Package: {pkg_name}", bold=True))
    click.echo(f"Total Images Found: {len(results)}")
    click.echo("")
    header = f"{'IMAGE':<35} {'PACKAGE':<25} {'VERSION':<20} {'VULNS'}"
    click.echo(header)
    click.echo("-" * 90)
    for row in results:
        img = str(getattr(row, 'imageName', ''))
        pkg_val = str(getattr(row, 'pkgName', 'Unknown'))
        v = getattr(row, 'version', None)
        ver_val = str(v) if v else "unknown"
        pkg, ver = split_package_version(pkg_val, ver_val)
        v_count = int(getattr(row, 'vulns', 0))
        v_str = click.style(str(v_count), fg='red' if v_count > 0 else 'green')
        click.echo(f"{img:<35} {pkg:<25} {ver:<20} {v_str}")

@cli.command(name='show-pkgs', short_help="Shows image SBOM.")
@click.argument('image')
def show_pkgs(image):
    """Lists all installed packages (SBOM) in a specific image."""
    qe = get_query_engine()
    results = qe.get_image_packages(image)
    click.echo(click.style(f"\n[SBOM SUMMARY] Image: {image}", bold=True))
    click.echo(f"Total Packages Installed: {len(results)}")
    click.echo("")
    if not results: return
    click.echo(f"{'PACKAGE NAME':<40} {'VERSION':<25} {'TYPE'}")
    click.echo("-" * 80)
    for row in results:
        pkg_val = getattr(row, 'pkgName', 'Unknown')
        ver_val = getattr(row, 'version', 'unknown')
        type_val = getattr(row, 'type', 'unknown')
        pkg, ver = split_package_version(pkg_val, ver_val)
        click.echo(f"{pkg:<40} {ver:<25} {type_val}")

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
    """Shows detailed metadata for all images in the graph."""
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

@cli.command(name='layers', short_help="Forensic analysis of image layers.")
@click.argument('image')
def layers(image):
    """
    Shows forensic layer details: Size, Packages, Vulnerabilities, and Build Command.
    
    \b
    USAGE:
        c2t layers <IMAGE_NAME>
    """
    qe = get_query_engine()
    results = qe.get_layer_info(image)
    click.echo(click.style(f"\n[LAYER FORENSICS] Image: {image}", bold=True))
    
    if not results:
        click.echo("Image not found or no layer info available.")
        return
        
    W_ID = 18
    W_SIZE = 10
    W_PKG = 8
    W_VULN = 12 
    
    click.echo(f"{'LAYER ID':<{W_ID}} {'SIZE':<{W_SIZE}} {'PKGS':<{W_PKG}} {'VULNS':<{W_VULN}} {'INSTRUCTION'}")
    click.echo("-" * 110)
    
    total_size = 0
    
    for row in results:
        lid = str(getattr(row, 'layerID', ''))[:15] + ".."
        
        # Calculate human-readable size
        raw_size = getattr(row, 'size', 0)
        size_str = sizeof_fmt(raw_size)
        try: total_size += float(raw_size)
        except: pass
        
        # Packages column
        pkgs = int(getattr(row, 'pkgCount', 0))
        pkgs_str = str(pkgs) if pkgs > 0 else "-"
        pkgs_display = f"{pkgs_str:<{W_PKG}}"
        
        # Vulnerabilities column
        vulns = int(getattr(row, 'vulnCount', 0))
        vulns_visual_len = len(str(vulns)) if vulns > 0 else 1
        v_str = "-"

        if vulns > 0:
            v_str = click.style(str(vulns), fg='red', bold=True)
        padding_vuln = " " * (W_VULN - vulns_visual_len)
        v_display = v_str + padding_vuln
        
        # Instruction column
        instr = str(getattr(row, 'instruction', 'Unknown'))
        
        # Cleanup for "RUN RUN"
        if instr.startswith("RUN RUN "):
            instr = instr[4:]
            
        if len(instr) > 60: instr = instr[:57] + "..."
        
        if "Unknown" in instr: 
            instr = click.style(instr, dim=True) 
        else: 
            instr = click.style(instr, fg='cyan')

        click.echo(f"{lid:<{W_ID}} {size_str:<{W_SIZE}} {pkgs_display} {v_display} {instr}")
        
    click.echo("-" * 110)
    click.echo(f"Total Size on Disk: {sizeof_fmt(total_size)}")
    click.echo("")

@cli.command(name='top-risks', short_help="Ranking of most vulnerable images and containers.")
def top_risks():
    """Shows a ranking of images and containers with the most Critical/High vulnerabilities."""
    qe = get_query_engine()
    
    # --- IMAGES SECTION ---
    results_img = qe.get_top_risky_images()
    click.echo(click.style(f"\n[RISK RANKING] Top Vulnerable Images", bold=True))
    click.echo("-" * 65)
    
    if not results_img:
        click.echo("No high-risk images found.")
    else:
        click.echo(f"{'IMAGE NAME':<45} {'RISK COUNT (Crit+High)'}")
        click.echo("-" * 65)
        for row in results_img:
            img = str(getattr(row, 'imageName', 'Unknown'))
            if len(img) > 43: img = img[:40] + "..."
            count = str(getattr(row, 'riskCount', '0'))
            click.echo(f"{img:<45} {click.style(count, fg='red')}")
    click.echo("")

    # --- CONTAINERS SECTION ---
    results_cont = qe.get_top_risky_containers()
    click.echo(click.style(f"[RISK RANKING] Top Vulnerable Containers", bold=True))
    click.echo("-" * 65)
    
    if not results_cont:
        click.echo("No high-risk containers found.")
    else:
        click.echo(f"{'CONTAINER NAME':<45} {'RISK COUNT (Crit+High)'}")
        click.echo("-" * 65)
        for row in results_cont:
            cont = str(getattr(row, 'containerName', 'Unknown'))
            if len(cont) > 43: cont = cont[:40] + "..."
            count = str(getattr(row, 'riskCount', '0'))
            click.echo(f"{cont:<45} {click.style(count, fg='red')}")
    click.echo("")

if __name__ == '__main__':
    cli()