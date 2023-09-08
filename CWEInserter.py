import os
import fnmatch
from neo4j import exceptions

class CWEInserter:

    def __init__(self, driver, import_path):
        self.driver = driver
        self.import_path = import_path

    # Cypher Query to insert CWE reference Cypher Script
    def query_cwe_reference_script(self, file):
        cwes_cypher_file = open(self.import_path + "CWEs_reference.cypher", "r")
        query = cwes_cypher_file.read()
        query = query.replace('cweReferenceFilesToImport', f"'{file}'")

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

        print("\nCWE Files: " + file + " insertion completed. \n----------")

    # Cypher Query to insert CWE weakness Cypher Script
    def query_cwe_weakness_script(self, file):
        cwes_cypher_file = open(self.import_path + "CWEs_weakness.cypher", "r")
        query = cwes_cypher_file.read()
        query = query.replace('cweWeaknessFilesToImport', f"'{file}'")

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

        print("\nCWE Files: " + file + " insertion completed. \n----------")

    # Cypher Query to insert CWE category Cypher Script
    def query_cwe_category_script(self, file):
        cwes_cypher_file = open(self.import_path + "CWEs_category.cypher", "r")
        query = cwes_cypher_file.read()
        query = query.replace('cweCategoryFilesToImport', f"'{file}'")

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

        print("\nCWE Files: " + file + " insertion completed. \n----------")

    # Cypher Query to insert CWE view Cypher Script
    def query_cwe_view_script(self, file):
        cwes_cypher_file = open(self.import_path + "CWEs_view.cypher", "r")
        query = cwes_cypher_file.read()
        query = query.replace('cweViewFilesToImport', f"'{file}'")

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

        print("\nCWE Files: " + file + " insertion completed. \n----------")

    # Configure CWE Files and CWE Cypher Script for insertion
    def cwe_insertion(self):
        print("\nInserting CWE Files to Database...")
        files = self.files_to_insert_cwe_reference()
        for f in files:
            print('Inserting ' + f)
            self.query_cwe_reference_script(f)

        files = self.files_to_insert_cwe_weakness()
        for f in files:
            print('Inserting ' + f)
            self.query_cwe_weakness_script(f)

        files = self.files_to_insert_cwe_category()
        for f in files:
            print('Inserting ' + f)
            self.query_cwe_category_script(f)

        files = self.files_to_insert_cwe_view()
        for f in files:
            print('Inserting ' + f)
            self.query_cwe_view_script(f)

    # Define which Dataset and Cypher files will be imported on CWE reference Insertion
    def files_to_insert_cwe_reference(self):
        listOfFiles = os.listdir(self.import_path + "mitre_cwe/splitted/")
        pattern = "*.json"

        reference_files = []

        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cwe_reference"):
                    reference_files.append("mitre_cwe/splitted/" + entry)
                else:
                    continue

        return reference_files

    # Define which Dataset and Cypher files will be imported on CWE weakness Insertion
    def files_to_insert_cwe_weakness(self):
        listOfFiles = os.listdir(self.import_path + "mitre_cwe/splitted/")
        pattern = "*.json"
        weakness_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cwe_weakness"):
                    weakness_files.append("mitre_cwe/splitted/" + entry)
                else:
                    continue

        return weakness_files


    # Define which Dataset and Cypher files will be imported on CWE category Insertion
    def files_to_insert_cwe_category(self):
        listOfFiles = os.listdir(self.import_path + "mitre_cwe/splitted/")
        pattern = "*.json"
        category_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cwe_category"):
                    category_files.append("mitre_cwe/splitted/" + entry)
                else:
                    continue

        return category_files


    # Define which Dataset and Cypher files will be imported on CWE view Insertion
    def files_to_insert_cwe_view(self):
        listOfFiles = os.listdir(self.import_path + "mitre_cwe/splitted/")
        pattern = "*.json"
        view_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cwe_view"):
                    view_files.append("mitre_cwe/splitted/" + entry)
                else:
                    continue

        return view_files