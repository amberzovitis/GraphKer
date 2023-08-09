import argparse
import os
import webbrowser
from neo4j import GraphDatabase
import scraper
import fnmatch
import platform
import shutil
from pathlib import Path
from fileType import FileType


class App:

    # Initializing Neo4j Driver
    def __init__(self, url, username, password):
        self.driver = GraphDatabase.driver(url, auth=(username, password))

    # Don't forget to close the driver connection when you are finished with it
    def close(self):
        self.driver.close()

    # Clear Database
    def clear(self):
        # Clear Database from existing nodes and relationships
        query = """match (n) detach delete (n)"""
        session = self.driver.session()
        session.run(query)
        print("\nPrevious Data have been deleted.")

        self.clearSchema()
        print("\nDatabase is clear and ready for imports.")

    # Clear Schema
    def clearSchema(self):
        # Clear Database from existing constraints and indexes
        query = """CALL apoc.cypher.runSchemaFile("ClearConstraintsIndexes.cypher")"""
        session = self.driver.session()
        session.run(query)
        print("\nPrevious Schema has been deleted.")

    # Constraints and Indexes
    def schema_script(self):
        # Create Constraints and Indexes
        query = """CALL apoc.cypher.runSchemaFile("ConstraintsIndexes.cypher")"""
        session = self.driver.session()
        session.run(query)
        print("\nSchema with Constraints and Indexes insertion completed.")

    # Cypher Query to insert CPE Cypher Script
    def query_cpe_script(self, files):
        # Insert file with CPE Query Script to Database
        query = """CALL apoc.cypher.runFile("CPEs.cypher")"""
        session = self.driver.session()
        session.run(query)
        for file in files:
            print("\nCPE Files: " + file + " insertion completed. \n----------")

    # Configure CPE Files and CPE Cypher Script for insertion
    def cpe_insertion(self):
        print("\nInserting CPE Files to Database...")
        files = files_to_insert_cpe()
        for f in files:
            print('Inserting ' + f)
        #self.query_cpe_script(files)

    # Cypher Query to insert CVE Cypher Script
    def query_cve_script(self, files):
        query = """CALL apoc.cypher.runFile("CVEs.cypher")"""
        session = self.driver.session()
        session.run(query)
        for file in files:
            print("\nCVE Files: " + file + " insertion completed. \n----------")

    # Configure CVE Files and CVE Cypher Script for insertion
    def cve_insertion(self):
        print("\nInserting CVE Files to Database...")
        files = files_to_insert_cve()
        for f in files:
            print('Inserting ' + f)
        #self.query_cve_script(files)

    # Cypher Query to insert CWE Cypher Script
    def query_cwe_script(self, files):
        query = """CALL apoc.cypher.runFile("CWEs.cypher")"""
        session = self.driver.session()
        session.run(query)
        for file in files:
            print("\nCWE Files: " + file + " insertion completed. \n----------")

    # Configure CWE Files and CWE Cypher Script for insertion
    def cwe_insertion(self):
        print("\nInserting CWE Files to Database...")
        files = files_to_insert_cwe()
        for f in files:
            print('Inserting ' + f)
        #self.query_cwe_script(files)

    # Cypher Query to insert CAPEC Cypher Script
    def query_capec_script(self, files):
        query = """CALL apoc.cypher.runFile("CAPECs.cypher")"""
        session = self.driver.session()
        session.run(query)
        for file in files:
            print("\nCAPEC Files: " + file + " insertion completed. \n----------")

    # Configure CAPEC Files and CAPEC Cypher Script for insertion
    def capec_insertion(self):
        print("\nInserting CAPEC Files to Database...")
        files = files_to_insert_capec()
        for f in files:
            print('Inserting ' + f)
        #self.query_capec_script(files)


# Define which Dataset and Cypher files will be imported on CPE Insertion
def files_to_insert_cpe():
    listOfFiles = os.listdir(import_path + "nist/cpe/splitted/")
    pattern = "*.json"
    cpe_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cpe_output"):
                cpe_files.append("nist/cpe/splitted/" + entry)
            else:
                continue
    cpes = {
        'cpeFilesToImport' : cpe_files
    }

    replace_files_cypher_script(cpes, FileType.CPE)
    return cpe_files


# Define which Dataset and Cypher files will be imported on CVE Insertion
def files_to_insert_cve():
    listOfFiles = os.listdir(import_path + "nist/cve/splitted/")
    pattern = "*.json"
    cve_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cve_output"):
                cve_files.append("nist/cve/splitted/" + entry)
            else:
                continue
    cves = {
        'cveFilesToImport' : cve_files
    }

    replace_files_cypher_script(cves, FileType.CVE)

    return cve_files


# Define which Dataset and Cypher files will be imported on CWE Insertion
def files_to_insert_cwe():
    listOfFiles = os.listdir(import_path + "mitre_cwe/splitted/")
    pattern = "*.json"
    weakness_files = []
    category_files = []
    reference_files = []
    view_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cwe_weakness"):
                weakness_files.append("mitre_cwe/splitted/" + entry)
            elif entry.startswith("cwe_category"):
                category_files.append("mitre_cwe/splitted/" + entry)
            elif entry.startswith("cwe_reference"):
                reference_files.append("mitre_cwe/splitted/" + entry)
            elif entry.startswith("cwe_view"):
                view_files.append("mitre_cwe/splitted/" + entry)
            else:
                continue

    cwes = {
        'cweWeaknessFilesToImport' : weakness_files,
        'cweCategoryFilesToImport' : category_files,
        'cweReferenceFilesToImport' : reference_files,
        'cweViewFilesToImport' : view_files
    }

    replace_files_cypher_script(cwes, FileType.CWE)

    return weakness_files + category_files + reference_files + view_files


# Define which Dataset and Cypher files will be imported on CAPEC Insertion
def files_to_insert_capec():
    listOfFiles = os.listdir(import_path + "mitre_capec/splitted/")
    pattern = "*.json"
    attack_pattern_files = []
    category_files = []
    reference_files = []
    view_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("capec_attack_pattern"):
                attack_pattern_files.append("mitre_capec/splitted/" + entry)
            elif entry.startswith("capec_category"):
                category_files.append("mitre_capec/splitted/" + entry)
            elif entry.startswith("capec_reference"):
                reference_files.append("mitre_capec/splitted/" + entry)
            elif entry.startswith("capec_view"):
                view_files.append("mitre_capec/splitted/" + entry)
            else:
                continue

    capecs = {
        'capecAttackFilesToImport' : attack_pattern_files,
        'capecCategoryFilesToImport' : category_files,
        'capecReferenceFilesToImport' : reference_files,
        'capecViewFilesToImport' : view_files
    }
    replace_files_cypher_script(capecs, FileType.CAPEC)

    return attack_pattern_files + category_files + reference_files + view_files

def replace_files_cypher_script(files_by_type, type):
    current_path = os.getcwd()
    current_os = platform.system()
    if (current_os == "Linux" or current_os == "Darwin"):
        current_path += "/CypherScripts/"
    elif current_os == "Windows":
        current_path += "\CypherScripts\\"

    if type == FileType.CPE:
        toUpdate = current_path + "CPEs.cypher"
        fin = open(toUpdate, "rt")
        updatedFile = import_path + "CPEs.cypher"
        fout = open(updatedFile, "wt")

        for line in fin:
            line_to_insert = replace_placeholder_with_value(line, files_by_type)
            fout.write(line_to_insert)

        fin.close()
        fout.close()

    if type == FileType.CVE:
        toUpdate = current_path + "CVEs.cypher"
        fin = open(toUpdate, "rt")
        updatedFile = import_path + "CVEs.cypher"
        fout = open(updatedFile, "wt")

        for line in fin:
            line_to_insert = replace_placeholder_with_value(line, files_by_type)
            fout.write(line_to_insert)

        fin.close()
        fout.close()

    if type == FileType.CAPEC:
        toUpdate = current_path + "CAPECs.cypher"
        fin = open(toUpdate, "rt")
        updatedFile = import_path + "CAPECs.cypher"
        fout = open(updatedFile, "wt")

        for line in fin:
            line_to_insert = replace_placeholder_with_value(line, files_by_type)
            fout.write(line_to_insert)
        
        fin.close()
        fout.close()
    
    if type == FileType.CWE:
        toUpdate = current_path + "CWEs.cypher"
        fin = open(toUpdate, "rt")
        updatedFile = import_path + "CWEs.cypher"
        fout = open(updatedFile, "wt")

        for line in fin:
            line_to_insert = replace_placeholder_with_value(line, files_by_type)
            fout.write(line_to_insert)

        fin.close()
        fout.close()

def replace_placeholder_with_value(line, files_by_type):
    for key in files_by_type.keys():
        if key in line:
            return line.replace(key, string_to_insert_from_files(files_by_type[key]))
    return line

def string_to_insert_from_files(files):
    stringToInsert = "\""
    for file in files:
        stringToInsert += file + "\", \""
    stringToInsert = stringToInsert[:-3]
    return stringToInsert

# Copy Cypher Script Schema Files to Import Path
def copy_files_cypher_script():
    current_path = os.getcwd()
    current_os = platform.system()
    if (current_os == "Linux" or current_os == "Darwin"):
        current_path += "/CypherScripts/"
    elif current_os == "Windows":
        current_path += "\CypherScripts\\"

    shutil.copy2(current_path + "ConstraintsIndexes.cypher", import_path)
    shutil.copy2(current_path + "ClearConstraintsIndexes.cypher", import_path)


# Clear Import Directory
def clear_directory():
    try:
        # List all files and directories inside the specified directory
        directory_contents = os.listdir(import_path)

        # Delete each file and subdirectory within the directory
        for item in directory_contents:
            item_path = os.path.join(import_path, item)
            if os.path.isfile(item_path):
                os.remove(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)

        print(f"Contents of '{import_path}' have been deleted.")
    except FileNotFoundError:
        print(f"Directory not found: {import_path}")
    except Exception as e:
        print(f"Error occurred: {e}")


# Set Import Directory
def set_import_path(directory):
    global import_path
    current_os = platform.system()
    if (current_os == "Linux" or current_os == "Darwin"):
        import_path = directory
    elif current_os == "Windows":
        import_path = directory.replace("\\", "\\\\") + "\\\\"


# Define the functions that will be running
def run(url_db, username, password, directory, neo4jbrowser, graphlytic):
    set_import_path(directory)

    #clear_directory()    
    #scraper.download_datasets(import_path)

    copy_files_cypher_script()

    app = App(url_db, username, password)
    app.clear()
    app.close()

    app = App(url_db, username, password)
    app.schema_script()
    app.cve_insertion()
    app.cwe_insertion()
    app.capec_insertion()
    app.cpe_insertion()
    app.close()

    if neo4jbrowser:
        webbrowser.open("http://localhost:7474")
    if graphlytic:
        webbrowser.open("http://localhost:8110/")
    return


def main():
    # Initialize the parser
    parser = argparse.ArgumentParser(
        description=" +-+-+-+-+-+-+-+-+ \n |G|r|a|p|h|K|e|r| \n +-+-+-+-+-+-+-+-+"
                    "\n \nWith GraphKer you can have the most recent update of cyber-security vulnerabilities, weaknesses, attack patterns and platforms "
                    "from MITRE and NIST, in an very useful and user friendly way provided by neo4j graph databases! \n \n"
                    "--Search, Export Data and Analytics, Enrich your Skills-- \n \n"
                    "**Created by Adamantios - Marios Berzovitis, Cybersecurity Expert MSc, BSc** \n"
                    "Diploma Research - MSc @ Distributed Systems, Security and Emerging Information Technologies | University Of Piraeus \n"
                    "Co-Working with Cyber Security Research Lab | University Of Piraeus \n"
                    "LinkedIn:https://tinyurl.com/p57w4ntu \n"
                    "Github:https://github.com/amberzovitis \n \n"
                    "Enjoy! Provide Feedback!", formatter_class=argparse.RawTextHelpFormatter
    )

    # Add Parameters
    parser.add_argument('-u', '--urldb', required=True,
                        help="Insert bolt url of your neo4j graph database.")
    parser.add_argument('-n', '--username', required=True,
                        help="Insert username of your graph database.")
    parser.add_argument('-p', '--password', required=True,
                        help="Insert password of your graph database.")
    parser.add_argument('-d', '--directory', required=True,
                        help="Insert import path of your graph database.")
    parser.add_argument('-b', '--neo4jbrowser', choices=['y', 'Y'],
                        help="Press y or Y to open neo4jbrowser after the insertion of elements in your graph database.")
    parser.add_argument('-g', '--graphlytic', choices=['y', 'Y'],
                        help="Press y or Y to open Graphlytic app after the insertion of elements in your graph database.")

    args = parser.parse_args()
    if args.neo4jbrowser == "y" or args.neo4jbrowser == "Y":
        neo4jbrowser_open = True
    else:
        neo4jbrowser_open = False
    if args.graphlytic == "y" or args.neo4jbrowser == "Y":
        graphlytic_open = True
    else:
        graphlytic_open = False
    run(args.urldb, args.username, args.password,
        args.directory, neo4jbrowser_open, graphlytic_open)
    return


if __name__ == '__main__':
    main()
