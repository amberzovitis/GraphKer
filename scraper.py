import os
import requests
import zipfile
from bs4 import BeautifulSoup
import platform
from circuitbreaker import circuit
import json
import xmltodict
import fnmatch
import subprocess
import math

MAX_RETRIES = 5

def download_files_cve(import_path):
    url = 'https://nvd.nist.gov/vuln/data-feeds'
    root = 'https://nvd.nist.gov/'
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    zip_files = [
        dl for dl in all_links if dl and '.json.zip' in dl and 'nvdcve' in dl
    ]
    download_folder = import_path + "nist/cve/"
    extract_dir = import_path + "nist/cve/"

    # Download and Unzip the files
    print('\nUpdating the Database with the latest CVE Files...')
    for zip_file in zip_files:
        print("Zip file: ", zip_file)
        full_url = root + zip_file
        zip_file_name = os.path.basename(zip_file)
        download_file_to_path(full_url, download_folder, zip_file_name)
        unzip_files_to_directory(download_folder, extract_dir, zip_file_name)

    transform_xml_files_to_json(extract_dir)
    transform_json_big_files_to_multiline_json(extract_dir, '.CVE_Items', 'cve')

def download_files_cpe(import_path):
    url = 'https://nvd.nist.gov/vuln/data-feeds'
    root = 'https://nvd.nist.gov/'
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    zip_files = [
        dl for dl in all_links if dl and '.json.zip' in dl and 'nvdcpematch' in dl
    ]
    download_folder = import_path + "nist/cpe/"
    extract_dir = import_path + "nist/cpe/"

    # Download and Unzip the files
    print('\nUpdating the Database with the latest CVE Files...')
    for zip_file in zip_files:
        full_url = root + zip_file
        zip_file_name = os.path.basename(zip_file)
        # 5 attempts to download and unzip the file correctly
        download_file_to_path(full_url, download_folder, zip_file_name)
        unzip_files_to_directory(download_folder, extract_dir, zip_file_name)

    transform_xml_files_to_json(extract_dir)
    transform_json_big_files_to_multiline_json(extract_dir, '.matches', 'cpe')

def download_files_cwe(import_path):
    url = 'https://cwe.mitre.org/data/archive.html'
    root = 'https://cwe.mitre.org/'
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    zip_files = [
        dl for dl in all_links if dl and '.xml.zip' in dl
    ]
    zip_file = zip_files[0]
    download_folder = import_path + "mitre_cwe/"
    extract_dir = import_path + "mitre_cwe/"

    # Download and Unzip the files
    print('\nUpdating the Database with the latest CWE Files...')
    full_url = root + zip_file
    zip_file_name = os.path.basename(zip_file)

    # 5 attempts to download and unzip the file correctly
    download_file_to_path(full_url, download_folder, zip_file_name)
    unzip_files_to_directory(download_folder, extract_dir, zip_file_name)
    transform_xml_files_to_json(extract_dir)
    replace_unwanted_string_cwe(extract_dir)
    transform_json_big_files_to_multiline_json(extract_dir, '.Weakness_Catalog.External_References.External_Reference', 'cwe_reference')
    transform_json_big_files_to_multiline_json(extract_dir, '.Weakness_Catalog.Weaknesses.Weakness', 'cwe_weakness')
    transform_json_big_files_to_multiline_json(extract_dir, '.Weakness_Catalog.Categories.Category', 'cwe_category')
    transform_json_big_files_to_multiline_json(extract_dir, '.Weakness_Catalog.Views.View', 'cwe_view')

def download_files_capec(import_path):
    url = 'https://capec.mitre.org/data/archive.html'
    root = 'https://capec.mitre.org/'
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    xml_files = [
        dl for dl in all_links if dl and '.xml' in dl
    ]
    xml_file = xml_files[0]

    download_folder = import_path + "mitre_capec/"
    extract_dir = import_path + "mitre_capec/"

    # Download xml file
    print('\nUpdating the Database with the latest CAPEC Files...')
    full_url = root + xml_file
    zip_file_name = os.path.basename(xml_file)

    download_file_to_path(full_url, download_folder, zip_file_name)
    transform_xml_files_to_json(download_folder)
    replace_unwanted_string_capec(download_folder)
    transform_json_big_files_to_multiline_json(extract_dir, '.Attack_Pattern_Catalog.External_References.External_Reference', 'capec_reference')
    transform_json_big_files_to_multiline_json(extract_dir, '.Attack_Pattern_Catalog.Attack_Patterns.Attack_Pattern', 'capec_attack_pattern')
    transform_json_big_files_to_multiline_json(extract_dir, '.Attack_Pattern_Catalog.Categories.Category', 'capec_category')
    transform_json_big_files_to_multiline_json(extract_dir, '.Attack_Pattern_Catalog.Views.View', 'capec_view')


def download_datasets(import_path):
    download_files_cve(import_path)
    download_files_cpe(import_path)
    download_files_cwe(import_path)
    download_files_capec(import_path)

# Define the function that makes the HTTP request with retry
def make_http_request_with_retry(url, retries=0):
    try:
        # Call the function that makes the HTTP request, protected by the circuit breaker
        return download_file_to_path(url)
    except circuit.BreakerOpenError:
        if retries < MAX_RETRIES:
            print(f"Circuit is open. Retrying... Attempt {retries + 1}")
            return make_http_request_with_retry(url, retries=retries + 1)
        else:
            raise RuntimeError("Circuit is open. Max retries reached.")
    except Exception as e:
        if retries < MAX_RETRIES:
            print(f"Error occurred: {e}. Retrying... Attempt {retries + 1}")
            return make_http_request_with_retry(url, retries=retries + 1)
        else:
            raise RuntimeError("Max retries reached. Last error: {}".format(e))

# Define the function that makes the HTTP request
@circuit(failure_threshold=10)
def download_file_to_path(url, download_path, file_name):
    print("Download path: ", download_path)
    if not os.path.exists(download_path):
        os.makedirs(download_path, exist_ok=True)
    r = requests.get(url)
    dl_path = os.path.join(download_path, file_name)
    with open(dl_path, 'wb') as file:
        file.write(r.content)

def unzip_files_to_directory(zip_path, extract_path, zip_filename):
    try:
        if not os.path.exists(extract_path):
            os.makedirs(extract_path, exist_ok=True)
        z = zipfile.ZipFile(os.path.join(zip_path, zip_filename))
        z.extractall(extract_path)
        print(zip_filename + ' unzipped successfully')
        print('---------')
        z.close()
        current_os = platform.system()
        if (current_os == "Linux" or current_os == "Darwin"):
            file_to_delete = f'{extract_path}' + f'/{zip_filename}'
        elif current_os == "Windows":
            file_to_delete = f'{extract_path}' + f'\\{zip_filename}'
        os.remove(file_to_delete)
    except zipfile.BadZipfile as e:
        print("Error while unzipping data" + e)

def transform_xml_files_to_json(path):
    directory_contents = os.listdir(path)

    for item in directory_contents:
        item_path = os.path.join(path, item)
        if item_path.endswith(".xml") and os.path.isfile(item_path):
            xml_file_to_json(item_path)
            os.remove(item_path)


# Convert XML Files to JSON Files
def xml_file_to_json(xmlFile):
    # parse the import folder for xml files
    # open the input xml file and read
    # data in form of python dictionary
    # using xmltodict module
    if xmlFile.endswith(".xml"):
        with open(xmlFile, 'r', encoding='utf-8') as xml_file:
            data_dict = xmltodict.parse(xml_file.read())
            xml_file.close()
            # generate the object using json.dumps()
            # corresponding to json data
            json_data = json.dumps(data_dict)
            # Write the json data to output
            # json file
            xml_file.close()
        jsonfile = f'{xmlFile}'
        print(jsonfile)
        jsonfile = jsonfile.replace(".xml", ".json")
        print(jsonfile)
        with open(jsonfile, "w") as json_file:
            json_file.write(json_data)
            json_file.close()

# Flatten CWE Dataset File
def replace_unwanted_string_cwe(path):
    listOfFiles = os.listdir(path)
    pattern = "*.json"
    files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cwec"):
                files.append(entry)
                break
    file = path + files[0]
    fin = open(file, "rt")
    flattened_cwe = path + "cwe.json"
    fout = open(flattened_cwe, "wt")
    for line in fin:
        fout.write(line.replace('"@', '"'))
    fin.close()
    os.remove(file)
    fout.close()

# Flatten CAPEC Dataset File
def replace_unwanted_string_capec(path):
    listOfFiles = os.listdir(path)
    pattern = "*.json"
    files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("capec"):
                files.append(entry)
                break
    file = path + files[0]
    fin = open(file, "rt")
    flattened_cwe = path + "capec.json"
    fout = open(flattened_cwe, "wt")
    for line in fin:
        fout.write(line.replace('"@', '"').replace('#text', 'text'))
    fin.close()
    fout.close()
    os.remove(file)

def transform_json_big_files_to_multiline_json(path, jq_filter, file_type):
    directory_contents = os.listdir(path)
    batch_size=1000

    if not os.path.exists(os.path.join(path, "splitted")):
        os.makedirs(os.path.join(path, "splitted"), exist_ok=True)
    for item in directory_contents:
        item_path = os.path.join(path, item)
        if item_path.endswith(".json") and os.path.isfile(item_path):
            #with open(item_path, 'r', encoding='utf-8') as file:
                #content = file.read()
                #print(content)
                # Run jq on the JSON data
            result = run_jq(item_path, f'{jq_filter} | length')
            if result:
                total_elements = int(result)
                num_files=(( (total_elements + batch_size - 1) / batch_size ))
            else:
                num_files = 0
                #file.close()
            print("Result is: ", num_files)
            for i in range(math.ceil(num_files)):
                start = i * batch_size
                end = min(start + batch_size, total_elements)

                # Extract a batch of elements using jq
                batch_filter = f'{jq_filter}[{start}:{end}]'
                batch_data = run_jq(item_path, batch_filter)
                if batch_data:
                    print("Writing data code: ")
                    # Save the batch data to a new file
                    output_file = os.path.join(path, f"splitted/{file_type}_output_file_{i}.json")
                    with open(output_file, 'w') as outfile:
                        outfile.write(batch_data)

def run_jq(json_data, jq_filter):
    try:
        jq_command = f'jq -r {jq_filter} {json_data}'
        print("Executing command:", jq_command)

        # Run jq command and capture the output
        process = subprocess.run(['jq', '-r', jq_filter, json_data], capture_output=True, text=True, check=True)
        if process.returncode == 0:
            return process.stdout.strip()
        else:
            print("==============>")
            raise RuntimeError(f"Error running jq command: {process.stderr.strip()}")
    except FileNotFoundError:
        raise RuntimeError("jq command not found. Make sure jq is installed on your system.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error running jq command. Make sure jq is installed and check your JSON and filter. Error: {e}")