import os
import fnmatch
from neo4j import exceptions

class CAPECInserter:

    def __init__(self, driver, import_path):
        self.driver = driver
        self.import_path = import_path

    # Cypher Query to insert CAPEC refrence Cypher Script
    def query_capec_reference_script(self, file):
        capecs_cypher_file = open(self.import_path + "CAPECs_reference.cypher", "r")
        query = capecs_cypher_file.read()
        query = query.replace('capecReferenceFilesToImport', f"'{file}'")
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

        print("\nCAPEC Files: " + file + " insertion completed. \n----------")

    # Cypher Query to insert CAPEC attack Cypher Script
    def query_capec_attack_script(self, file):
        capecs_cypher_file = open(self.import_path + "CAPECs_attack.cypher", "r")
        query = capecs_cypher_file.read()

        query = query.replace('capecAttackFilesToImport', f"'{file}'")
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


        print("\nCAPEC Files: " + file + " insertion completed. \n----------")

    # Cypher Query to insert CAPEC category Cypher Script
    def query_capec_category_script(self, file):
        capecs_cypher_file = open(self.import_path + "CAPECs_category.cypher", "r")
        query = capecs_cypher_file.read()
        query = query.replace('capecCategoryFilesToImport', f"'{file}'")

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


        print("\nCAPEC Files: " + file + " insertion completed. \n----------")

    # Cypher Query to insert CAPEC view Cypher Script
    def query_capec_view_script(self, file):
        capecs_cypher_file = open(self.import_path + "CAPECs_view.cypher", "r")
        query = capecs_cypher_file.read()
        query = query.replace('capecViewFilesToImport', f"'{file}'")

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


        print("\nCAPEC Files: " + file + " insertion completed. \n----------")

    # Configure CAPEC Files and CAPEC Cypher Script for insertion
    def capec_insertion(self):
        print("\nInserting CAPEC Files to Database...")
        files = self.files_to_insert_capec_reference()
        for f in files:
            print('Inserting ' + f)
            self.query_capec_reference_script(f)

        files = self.files_to_insert_capec_attack()
        for f in files:
            print('Inserting ' + f)
            self.query_capec_attack_script(f)

        files = self.files_to_insert_capec_category()
        for f in files:
            print('Inserting ' + f)
            self.query_capec_category_script(f)

        files = self.files_to_insert_capec_view()
        for f in files:
            print('Inserting ' + f)
            self.query_capec_view_script(f)

    # Define which Dataset and Cypher files will be imported on CAPEC refrence Insertion
    def files_to_insert_capec_reference(self):
        listOfFiles = os.listdir(self.import_path + "mitre_capec/splitted/")
        pattern = "*.json"
        reference_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_reference"):
                    reference_files.append("mitre_capec/splitted/" + entry)
                else:
                    continue

        return reference_files

    # Define which Dataset and Cypher files will be imported on CAPEC attack Insertion
    def files_to_insert_capec_attack(self):
        listOfFiles = os.listdir(self.import_path + "mitre_capec/splitted/")
        pattern = "*.json"
        attack_pattern_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_attack_pattern"):
                    attack_pattern_files.append("mitre_capec/splitted/" + entry)
                else:
                    continue

        return attack_pattern_files

    # Define which Dataset and Cypher files will be imported on CAPEC category Insertion
    def files_to_insert_capec_category(self):
        listOfFiles = os.listdir(self.import_path + "mitre_capec/splitted/")
        pattern = "*.json"
        category_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_category"):
                    category_files.append("mitre_capec/splitted/" + entry)
                else:
                    continue

        return category_files

    # Define which Dataset and Cypher files will be imported on CAPEC view Insertion
    def files_to_insert_capec_view(self):
        listOfFiles = os.listdir(self.import_path + "mitre_capec/splitted/")
        pattern = "*.json"
        view_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_view"):
                    view_files.append("mitre_capec/splitted/" + entry)
                else:
                    continue

        return view_files