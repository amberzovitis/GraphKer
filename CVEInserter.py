import os
import time
import fnmatch
from fileType import FileType
from Util import Util
from neo4j import exceptions

class CVEInserter:

    def __init__(self, driver, import_path):
        self.driver = driver
        self.import_path = import_path

    # Configure CVE Files and CVE Cypher Script for insertion
    def cve_insertion(self):
        print("\nInserting CVE Files to Database...")
        files = self.files_to_insert_cve()
        for f in files:
            print('Inserting ' + f)
            self.query_cve_script(f)

    # Cypher Query to insert CVE Cypher Script
    def query_cve_script(self, file):
        start_time = time.time()
        cves_cypher_file = open(self.import_path + "CVEs.cypher", "r")
        query = cves_cypher_file.read()
        query = query.replace('cveFilesToImport', f"'{file}'")

        try:
            with self.driver.session() as session:
                session.run(query)
        except exceptions.CypherError as e:
            print(f"CypherError: {e}")
        except exceptions.DriverError as e:
            print(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            print(f"An error occurred: {e}")

        end_time = time.time()

        print(f"\nCVE Files: { file } insertion completed within { end_time - start_time }\n----------")

    # Define which Dataset and Cypher files will be imported on CVE Insertion
    def files_to_insert_cve(self):
        listOfFiles = os.listdir(self.import_path + "nist/cve/splitted/")
        pattern = "*.json"
        cve_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cve_output"):
                    cve_files.append("nist/cve/splitted/" + entry)
                else:
                    continue

        return cve_files