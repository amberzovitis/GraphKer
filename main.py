import argparse
import webbrowser
from neo4j import GraphDatabase
import scraper
import time
from Util import Util
from CPEInserter import CPEInserter
from CWEInserter import CWEInserter
from CVEInserter import CVEInserter
from CAPECInserter import CAPECInserter
from DatabaseUtil import DatabaseUtil

# Define the functions that will be running
def run(url_db, username, password, directory, neo4jbrowser, graphlytic):
    try:
        start_time = time.time()

        import_path = Util.set_import_path(directory)

        Util.clear_directory(import_path)
        scraper.download_datasets(import_path)

        Util.copy_files_cypher_script(import_path)

        driver = GraphDatabase.driver(url_db, auth=(username, password))

        cpeInserter = CPEInserter(driver, import_path)
        cveInserter = CVEInserter(driver, import_path)
        cweInserter = CWEInserter(driver, import_path)
        capecInserter = CAPECInserter(driver, import_path)
        databaseUtil = DatabaseUtil(driver)

        databaseUtil.clear()
        databaseUtil.schema_script()
        cpeInserter.cpe_insertion()
        capecInserter.capec_insertion()
        cveInserter.cve_insertion()
        cweInserter.cwe_insertion()

        driver.close()

        end_time = time.time()

        execution_time = end_time - start_time
        print(f"Import finished in: {execution_time:.6f} seconds")

    except Exception as e:
        print(f"Error occurred: {e}")
        driver.close()

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