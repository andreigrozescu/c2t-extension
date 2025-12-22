import rdflib
import logging
from pathlib import Path

# Common Prefixes
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
        full_query = PREFIXES + query_body
        return self.g.query(full_query)

    def debug_dump_node(self, target):
        q = f"""SELECT ?s ?p ?o WHERE {{ ?s rdfs:label ?label . FILTER (REGEX(?label, "{target}", "i")) ?s ?p ?o . }}"""
        return self.run_query(q)

    def list_containers(self):
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
        # 1. Try as Container
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

        # 2. Try as Image
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
        q = f"""
        SELECT DISTINCT ?pkgName ?pkgVersion ?vulnID ?severity ?score ?fixedIn ?pkgURI
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
        Fetches all ontology properties for a specific Vulnerability ID,
        including the affected package (from Mapping: hasAffectedPackage).
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
            OPTIONAL {{ ?v dct:description ?description }}
            OPTIONAL {{ ?v c2t:hasAffectedPackage ?affectedPkg }}
        }}
        LIMIT 1
        """
        return self.run_query(q)

    def get_image_metadata(self, image_name):
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
        """
        Req 1: Count vulnerabilities for the specific package found.
        """
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
        """
        Req 6: Include package match name and vulnerability count.
        """
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

    def image_libraries(self, image_name):
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
        q = """
        SELECT DISTINCT ?imageName ?osName
        WHERE {
            ?img a c2t:Image ; rdfs:label ?imageName ; c2t:hasOperatingSystem ?os .
            ?os schema:name ?osName .
        }
        """
        return self.run_query(q)

    def image_metadata(self):
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