import rdflib
import logging
from pathlib import Path

PREFIXES = """
    PREFIX c2t: <https://w3id.org/c2t/o#>
    PREFIX c2ti: <https://w3id.org/c2t/instance/>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX dpv: <http://dockerpedia.inf.utfsm.cl/vocab#>
    PREFIX schema: <http://schema.org/>
    PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""

class QueryEngine:
    """Encapsulates SPARQL queries logic against the RDF graph."""
    
    def __init__(self, graph_path: Path):
        self.graph_path = graph_path
        self.g = rdflib.Graph()
        if self.graph_path.exists():
            logging.info(f"Loading graph from {self.graph_path}...")
            self.g.parse(str(self.graph_path), format="nt")
            logging.info(f"Graph loaded with {len(self.g)} triples.")
        else:
            logging.warning("No graph found. Run 'c2t process' first.")

    def run_query(self, query_body):
        """Executes a query with standard prefixes prepended."""
        full_query = PREFIXES + query_body
        return self.g.query(full_query)

    def list_containers(self):
        """Retrieves ID, Name, Status, Ports, and associated Image for all containers."""
        q = """
        SELECT DISTINCT ?id ?name ?status ?ports ?displayImage ?hostName
        WHERE {
            ?c a c2t:Container ;
               dct:identifier ?id ;
               rdfs:label ?name ;
               c2t:status ?status ;
               c2t:isInstanceOf ?img .
            
            OPTIONAL { ?img rdfs:label ?label }
            BIND(COALESCE(?label, "Deleted/Unknown") AS ?displayImage)

            OPTIONAL { ?c c2t:isDeployedOn/dct:identifier ?hostName . }
            OPTIONAL { ?c c2t:ports ?ports }
        }
        ORDER BY ?name
        """
        return self.run_query(q)

    def get_target_metadata(self, target):
        """Retrieves metadata (Arch, Size, OS, Created, Status) for a target (Image/Container)."""
        q_cont = f"""
        SELECT ?type ?arch ?size ?osName ?osVer ?created ?status ?ports ?imageName
        WHERE {{
            ?c a c2t:Container ; rdfs:label ?cName .
            FILTER (REGEX(?cName, "{target}", "i"))
            BIND("Container" AS ?type)
            
            ?c c2t:isInstanceOf ?img .
            OPTIONAL {{ ?img rdfs:label ?imageName }}
            OPTIONAL {{ ?c c2t:status ?status }}
            OPTIONAL {{ ?c c2t:ports ?ports }}
            OPTIONAL {{ ?c schema:dateCreated ?created }}
            
            OPTIONAL {{ ?img c2t:architecture ?arch }}
            OPTIONAL {{ ?img dpv:size ?size }}
            OPTIONAL {{ 
                ?img c2t:hasOperatingSystem ?os .
                ?os schema:name ?osName .
                OPTIONAL {{ ?os schema:hasVersion ?osVer }}
            }}
        }} LIMIT 1
        """
        res = self.run_query(q_cont)
        if len(res) > 0: return res

        q_img = f"""
        SELECT ?type ?arch ?size ?osName ?osVer ?created
        WHERE {{
            ?img a c2t:Image ; rdfs:label ?imgName .
            FILTER (REGEX(?imgName, "{target}", "i"))
            BIND("Image" AS ?type)
            
            OPTIONAL {{ ?img schema:dateCreated ?created }}
            OPTIONAL {{ ?img c2t:architecture ?arch }}
            OPTIONAL {{ ?img dpv:size ?size }}
            OPTIONAL {{ 
                ?img c2t:hasOperatingSystem ?os .
                ?os schema:name ?osName .
                OPTIONAL {{ ?os schema:hasVersion ?osVer }}
            }}
        }} LIMIT 1
        """
        return self.run_query(q_img)

    def get_total_package_count(self, target):
        """Counts total distinct packages installed in a target."""
        q = f"""
        SELECT (COUNT(DISTINCT ?pkg) as ?pkgCount)
        WHERE {{
            {{
                ?c a c2t:Container ; rdfs:label ?name ; c2t:isInstanceOf ?img .
                FILTER (REGEX(?name, "{target}", "i"))
            }} UNION {{
                ?img a c2t:Image ; rdfs:label ?name .
                FILTER (REGEX(?name, "{target}", "i"))
            }}
            ?img c2t:hasLayer/c2t:hasPackageVersion ?pkg .
        }}
        """
        return self.run_query(q)

    def get_image_vuln_count(self, image_name):
        """Counts total distinct vulnerabilities for a specific image."""
        q = f"""
        SELECT (COUNT(DISTINCT ?v) as ?vCount)
        WHERE {{
            ?img a c2t:Image ; rdfs:label ?name .
            FILTER (REGEX(?name, "{image_name}", "i"))
            ?img c2t:hasLayer/c2t:hasPackageVersion ?pkg .
            ?pkg c2t:hasVulnerability ?v .
        }}
        """
        return self.run_query(q)

    def assess_target(self, target):
        """
        Retrieves full vulnerability report for a target.
        Includes: Package Name, Version, CVE ID, Severity, Score, Fix availability.
        """
        q = f"""
        SELECT DISTINCT ?pkgName ?pkgVersion ?vulnID ?severity ?score ?fixedIn ?pkgURI ?vulnType
        WHERE {{
            {{
                ?c a c2t:Container ; rdfs:label ?name ; c2t:isInstanceOf ?img .
                FILTER (REGEX(?name, "{target}", "i"))
            }} UNION {{
                ?img a c2t:Image ; rdfs:label ?name .
                FILTER (REGEX(?name, "{target}", "i"))
            }}

            ?img c2t:hasLayer/c2t:hasPackageVersion ?pkg .
            ?pkg c2t:hasVulnerability ?v .
            
            BIND(?pkg AS ?pkgURI)
            ?v dct:identifier ?vulnID .
            OPTIONAL {{ ?v c2t:severity ?severity }}
            OPTIONAL {{ ?v c2t:score ?score }}
            OPTIONAL {{ ?v c2t:fixedIn ?fixedIn }}
            OPTIONAL {{ ?v c2t:vulnerabilityType ?vulnType }}
            
            OPTIONAL {{ ?pkg schema:name ?n1 }}
            OPTIONAL {{ ?pkg rdfs:label ?n2 }}
            BIND(COALESCE(?n1, ?n2, "Unknown") AS ?pkgName)
            OPTIONAL {{ ?pkg schema:hasVersion ?pkgVersion }}
        }}
        ORDER BY ?severity
        """
        return self.run_query(q)

    def get_vulnerability_details(self, vuln_id):
        """
        Retrieves details for a specific Vulnerability ID (CVE/GHSA).
        Sorts by description length to prefer verbose entries (e.g., NVD over Alpine).
        """
        q = f"""
        SELECT ?id ?severity ?score ?vector ?fixedIn ?type ?description ?affectedPkg
        WHERE {{
            ?v a c2t:Vulnerability ;
               dct:identifier ?id .
            FILTER (REGEX(?id, "^{vuln_id}$", "i"))
            
            OPTIONAL {{ ?v c2t:severity ?severity }}
            OPTIONAL {{ ?v c2t:score ?score }}
            OPTIONAL {{ ?v c2t:vector ?vector }}
            OPTIONAL {{ ?v c2t:fixedIn ?fixedIn }}
            OPTIONAL {{ ?v c2t:vulnerabilityType ?type }}
            OPTIONAL {{ ?v c2t:hasAffectedPackage ?affectedPkg }}
            
            OPTIONAL {{ ?v dct:description ?descRaw }}
            BIND(COALESCE(?descRaw, "") AS ?description)
        }}
        ORDER BY DESC(STRLEN(?description))
        LIMIT 1
        """
        return self.run_query(q)

    def get_vulnerability_impact(self, vuln_id):
        """Finds all Images and Containers affected by a specific Vulnerability."""
        q = f"""
        SELECT DISTINCT ?imageName ?containerName
        WHERE {{
            ?v a c2t:Vulnerability ; dct:identifier ?id .
            FILTER (REGEX(?id, "^{vuln_id}$", "i"))
            
            ?pkg c2t:hasVulnerability ?v .
            ?layer c2t:hasPackageVersion ?pkg .
            ?img c2t:hasLayer ?layer ; rdfs:label ?imageName .
            
            OPTIONAL {{
                ?c c2t:isInstanceOf ?img ; rdfs:label ?containerName .
            }}
        }}
        ORDER BY ?imageName
        """
        return self.run_query(q)

    def get_image_metadata(self, image_name):
        """Retrieves OS, Architecture, and Creation Date for an image."""
        q = f"""
        SELECT DISTINCT ?arch ?size ?osName ?osVer ?created
        WHERE {{
            ?img a c2t:Image ; rdfs:label ?name .
            FILTER (REGEX(STR(?name), "{image_name}", "i"))
            
            OPTIONAL {{ ?img c2t:architecture ?arch }}
            OPTIONAL {{ ?img dpv:size ?size }}
            OPTIONAL {{ ?img schema:dateCreated ?created }}
            OPTIONAL {{ 
                ?img c2t:hasOperatingSystem ?os .
                ?os schema:name ?osName .
                OPTIONAL {{ ?os schema:hasVersion ?osVer }}
            }}
        }}
        LIMIT 1
        """
        return self.run_query(q)

    def get_image_packages_simple(self, image_name):
        """Simple list of packages and versions for 'diff' command."""
        q = f"""
        SELECT DISTINCT ?pkgName ?version
        WHERE {{
            ?img a c2t:Image ; rdfs:label ?name .
            FILTER (REGEX(STR(?name), "{image_name}", "i"))
            
            ?img c2t:hasLayer/c2t:hasPackageVersion ?pkg .
            
            OPTIONAL {{ ?pkg schema:name ?n1 }}
            OPTIONAL {{ ?pkg rdfs:label ?n2 }}
            BIND(COALESCE(?n1, ?n2, "Unknown") AS ?pkgName)
            
            OPTIONAL {{ ?pkg schema:hasVersion ?version }}
        }}
        """
        return self.run_query(q)

    def affected_containers_by_lib(self, lib_name):
        """Finds containers using a specific library/package."""
        q = f"""
        SELECT DISTINCT ?containerName ?imageName ?pkgName ?version (COUNT(?v) as ?vulns)
        WHERE {{
            ?c a c2t:Container ; rdfs:label ?containerName ; c2t:isInstanceOf ?img .
            ?img rdfs:label ?imageName .
            ?img c2t:hasLayer/c2t:hasPackageVersion ?pkg .
            
            OPTIONAL {{ ?pkg schema:name ?n1 }}
            OPTIONAL {{ ?pkg rdfs:label ?n2 }}
            OPTIONAL {{ ?pkg schema:hasVersion ?version }}
            
            BIND(COALESCE(?n1, ?n2, "Unknown") AS ?pkgName)
            
            FILTER (REGEX(?pkgName, "{lib_name}", "i"))
            
            OPTIONAL {{ ?pkg c2t:hasVulnerability ?v }}
        }}
        GROUP BY ?containerName ?imageName ?pkgName ?version
        """
        return self.run_query(q)

    def images_with_app(self, app_name):
        """Finds images containing a specific package."""
        q = f"""
        SELECT DISTINCT ?imageName ?pkgName ?version (COUNT(?v) as ?vulns)
        WHERE {{
            ?img a c2t:Image ; rdfs:label ?imageName .
            ?img c2t:hasLayer/c2t:hasPackageVersion ?pkg .
            
            OPTIONAL {{ ?pkg schema:name ?n1 }}
            OPTIONAL {{ ?pkg rdfs:label ?n2 }}
            OPTIONAL {{ ?pkg schema:hasVersion ?version }}
            
            BIND(COALESCE(?n1, ?n2, "Unknown") AS ?pkgName)
            
            FILTER (REGEX(?pkgName, "{app_name}", "i"))
            
            OPTIONAL {{ ?pkg c2t:hasVulnerability ?v }}
        }}
        GROUP BY ?imageName ?pkgName ?version
        """
        return self.run_query(q)

    def get_image_packages(self, image_name):
        """Retrieves full SBOM (name, version, type) for an image."""
        q = f"""
        SELECT DISTINCT ?pkgName ?version ?type
        WHERE {{
            ?img a c2t:Image ; rdfs:label ?name .
            FILTER (REGEX(STR(?name), "{image_name}", "i"))
            ?img c2t:hasLayer/c2t:hasPackageVersion ?pkg .
            OPTIONAL {{ ?pkg schema:name ?n1 }}
            OPTIONAL {{ ?pkg rdfs:label ?n2 }}
            BIND(COALESCE(?n1, ?n2, "Unknown") AS ?pkgName)
            OPTIONAL {{ ?pkg schema:hasVersion ?version }}
            OPTIONAL {{ ?pkg c2t:packageType ?type }}
        }}
        ORDER BY ?pkgName
        """
        return self.run_query(q)

    def images_os(self):
        """Retrieves OS distribution for all images."""
        q = """
        SELECT DISTINCT ?imageName ?osName
        WHERE {
            ?img a c2t:Image ; rdfs:label ?imageName ; c2t:hasOperatingSystem ?os .
            ?os schema:name ?osName .
        }
        """
        return self.run_query(q)

    def image_metadata(self):
        """Retrieves generic metadata and build history for all images."""
        q = """
        SELECT DISTINCT ?imageName ?created ?arch ?history
        WHERE {
            ?img a c2t:Image ; 
                 rdfs:label ?imageName .
            OPTIONAL { ?img schema:dateCreated ?created }
            OPTIONAL { ?img c2t:architecture ?arch }
            OPTIONAL { ?img c2t:hasBuildHistory ?history }
        }
        """
        return self.run_query(q)

    def get_top_risky_images(self, limit=10):
        """Ranks images by count of Critical and High vulnerabilities."""
        q = f"""
        SELECT ?imageName (COUNT(?v) as ?riskCount)
        WHERE {{
            ?img a c2t:Image ; rdfs:label ?imageName .
            ?img c2t:hasLayer/c2t:hasPackageVersion ?pkg .
            ?pkg c2t:hasVulnerability ?v .
            ?v c2t:severity ?sev .
            FILTER (LCASE(STR(?sev)) IN ('critical', 'high'))
        }}
        GROUP BY ?imageName
        ORDER BY DESC(?riskCount)
        LIMIT {limit}
        """
        return self.run_query(q)

    def get_top_risky_containers(self, limit=10):
        """Ranks containers by count of Critical and High vulnerabilities."""
        q = f"""
        SELECT ?containerName (COUNT(?v) as ?riskCount)
        WHERE {{
            ?c a c2t:Container ; rdfs:label ?containerName ; c2t:isInstanceOf ?img .
            ?img c2t:hasLayer/c2t:hasPackageVersion ?pkg .
            ?pkg c2t:hasVulnerability ?v .
            ?v c2t:severity ?sev .
            FILTER (LCASE(STR(?sev)) IN ('critical', 'high'))
        }}
        GROUP BY ?containerName
        ORDER BY DESC(?riskCount)
        LIMIT {limit}
        """
        return self.run_query(q)

    def get_layer_info(self, image_name):
        """
        Retrieves forensic data for image layers: ID, Size, Build Instruction, and Order Index.
        Used for 'c2t layers' command.
        """
        q = f"""
        SELECT ?layerID ?size ?instruction ?index (COUNT(DISTINCT ?pkg) as ?pkgCount) (COUNT(DISTINCT ?v) as ?vulnCount)
        WHERE {{
            ?img a c2t:Image ; rdfs:label ?name .
            FILTER (REGEX(?name, "{image_name}", "i"))
            
            ?img c2t:hasLayer ?layer .
            
            ?layer dct:identifier ?layerID .
            OPTIONAL {{ ?layer c2t:instruction ?instruction }}
            OPTIONAL {{ ?layer dpv:size ?size }}
            OPTIONAL {{ ?layer c2t:layerIndex ?index }}
            
            OPTIONAL {{ 
                ?layer c2t:hasPackageVersion ?pkg .
                OPTIONAL {{ ?pkg c2t:hasVulnerability ?v }}
            }}
        }}
        GROUP BY ?layerID ?size ?instruction ?index
        ORDER BY ?index
        """
        return self.run_query(q)
    
    def audit_package_versions(self, pkg_name):
        """
        Retrieves all versions of a specific package across the graph, 
        listing vulnerabilities for each version to detect safe vs unsafe versions.
        """
        q = f"""
        SELECT DISTINCT ?pkgName ?version ?vulnID ?severity ?fixedIn
        WHERE {{
            ?pkg a c2t:PackageVersion .
            
            OPTIONAL {{ ?pkg schema:name ?n1 }}
            OPTIONAL {{ ?pkg rdfs:label ?n2 }}
            BIND(COALESCE(?n1, ?n2, "Unknown") AS ?pkgName)
            
            FILTER (REGEX(?pkgName, "^{pkg_name}$", "i") || REGEX(?pkgName, "^{pkg_name}[^a-zA-Z0-9]", "i"))
            
            ?pkg schema:hasVersion ?version .

            OPTIONAL {{
                ?pkg c2t:hasVulnerability ?v .
                ?v dct:identifier ?vulnID .
                OPTIONAL {{ ?v c2t:severity ?severity }}
                OPTIONAL {{ ?v c2t:fixedIn ?fixedIn }}
            }}
        }}
        ORDER BY ?pkgName ?version ?severity
        """
        return self.run_query(q)