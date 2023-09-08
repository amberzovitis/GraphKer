import os
import time
import fnmatch
from neo4j import exceptions

class CPEInserter:

    def __init__(self, driver, import_path):
        self.driver = driver
        self.import_path = import_path

    # Configure CPE Files and CPE Cypher Script for insertion
    def cpe_insertion(self):
        print("\nInserting CPE Files to Database...")
        files = self.files_to_insert_cpe()
        for f in files:
            print('Inserting ' + f)
            self.query_cpe_script(f)

    # Cypher Query to insert CPE Cypher Script
    def query_cpe_script(self, file):
        start_time = time.time()
        # Insert file with CPE Query Script to Database
        cpes_cypher_file = open(self.import_path + "CPEs.cypher", "r")
        query = cpes_cypher_file.read()
        query = query.replace('cpeFilesToImport', f"'{file}'")
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

        print(f"\nCPE Files: {file} insertion completed. within {end_time - start_time}\n----------")

    # Define which Dataset and Cypher files will be imported on CPE Insertion
    def files_to_insert_cpe(self):
        listOfFiles = os.listdir(self.import_path + "nist/cpe/splitted/")
        pattern = "*.json"
        cpe_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cpe_output"):
                    cpe_files.append("nist/cpe/splitted/" + entry)
                else:
                    continue

        return cpe_files