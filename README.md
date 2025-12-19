# C2T

**Context:** This project is developed as a **Bachelor's Thesis (TFG)**. It acts as an extension of the original [c2t tool](https://github.com/osoc-es/c2t), adding capabilities for monitoring containers deployed on a host, performing vulnerability analysis using SBOMs, and generating forensic traceability data through Knowledge Graphs.

## Architecture and Workflow

The application follows a modular pipeline designed to extract, unify, and semantically map data from the Docker environment.

1.  **Orchestration (`src/logic.py`):**
    The system scans the host for available images and containers. It invokes external CLI tools (`docker inspect`, `docker history`, `syft`, `grype`) to generate raw data files.

2.  **Parsing (`src/inspect_parser.py`, `src/syft_parser.py`):**
    The raw outputs are processed to normalize data structures, extract relevant metadata (creation dates, architecture, ports), and clean identifiers.

3.  **Unification (`src/unifier.py`):**
    All parsed data is aggregated into a single JSON structure (`unified_data.json`). This module then triggers **Morph-KGC** to map this JSON into RDF Triples using the rules defined in `mappings/mapping_host.yarrrrml.yaml`.

4.  **Graph Generation (`output/docker_graph.nt`):**
    The result is an N-Triples file representing the current state of the host, including relationships between images, layers, packages, and vulnerabilities.

5.  **Querying (`src/queries.py`, `src/CLI.py`):**
    The CLI uses `rdflib` to load the graph and execute SPARQL queries to answer specific user questions (e.g., security assessments, diffs).

## System Requirements

*   **Docker:** Required to interact with the daemon.
*   **Syft:** Required for generating the Software Bill of Materials (SBOM).
    ```bash
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
    ```
*   **Grype:** Required for vulnerability scanning.
    ```bash
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
    ```

## Installation

Installation can be done using **Poetry** or a standard Python **virtual environment**.

### Option A: Using Poetry

1.  Clone the repositoryand enter the directory:
    ```bash
    git clone https://github.com/andreigrozescu/c2t-extension.git
    cd c2t
    ```

2.  Install dependencies:
    ```bash
    poetry install
    ```

3.  Activate the environment:
    ```bash
    # Universal method
    source $(poetry env info --path)/bin/activate
    ```

### Option B: Standard Virtual Environment

1.  Clone the repository and enter the directory:
    ```bash
    git clone https://github.com/andreigrozescu/c2t-extension.git
    cd c2t
    ```

2.  Create and activate the environment:
    ```bash
    python3 -m venv c2t-env
    source c2t-env/bin/activate
    ```

3.  Install the package:
    ```bash
    pip install -e .
    ```

## Usage

### 1. Generate Graph
Analyzes the host state and generates the Knowledge Graph.

```bash
c2t process
```
By default, the tool performs an **incremental update**. It scans the Docker Host and compares it against the existing Knowledge Graph. It **only analyzes new images or containers** that are not yet present in the graph. This is the recommended mode for daily usage, as it avoids regenerating the whole graph.

```bash
c2t process --force
```
The `--force` flag completely discards the existing graph and re-analyzes all images and containers currently present on the host. 

### 2. List Containers
Lists all containers found in the graph, including their ID, Status, and mapped Ports.
```bash
c2t list
```

### 3. Security Assessment
Performs a security audit on a specific container or image. It displays metadata and a list of package vulnerabilities grouped by severity.
```bash
c2t assess <TARGET>
```
**Example:**
```bash
c2t assess nginx:latest
```

### 4. Image Comparison
Compares two images side-by-side. It displays a metadata comparison table (OS, Size, Date, Vulnerability Count) and a library comparison table highlighting version differences.
```bash
c2t diff <IMAGE_1> <IMAGE_2>
```
**Example:**
```bash
c2t diff redis:6.2-alpine redis:7.2-alpine
```

### 5. Search Library
Finds which containers or images contain a specific library installed. Useful for tracking vulnerable dependencies.
```bash
c2t search-lib <LIBRARY_NAME>
```
**Example:**
```bash
c2t search-lib openssl
```

### 6. Search Application
Reverse search to find which images contain a specific application software.
```bash
c2t search-app <APP_NAME>
```
**Example:**
```bash
c2t search-app python
```

### 7. Metadata
Retrieves metadata for all images and shows the reconstructed Dockerfile using docker history.
```bash
c2t metadata
```

### 8. Operative System Report
Generates a summary of the Operating System families detected in the local registry.
```bash
c2t report-os
```

### 9. Show SBOM
Lists all installed packages and versions for a specific image.
```bash
c2t show-libs <IMAGE_NAME>
```