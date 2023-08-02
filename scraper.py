import os
import requests
import zipfile
from bs4 import BeautifulSoup
import platform
from circuitbreaker import circuit

MAX_RETRIES = 5

def download_files_cve_cpe(import_path):
    url = 'https://nvd.nist.gov/vuln/data-feeds'
    root = 'https://nvd.nist.gov/'
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    zip_files = [
        dl for dl in all_links if dl and '.json.zip' in dl
    ]
    download_folder = import_path

    # Download and Unzip the files
    print('\nUpdating the Database with the latest CVE Files...')
    for zip_file in zip_files:
        full_url = root + zip_file
        zip_filename = os.path.basename(zip_file)
        dl_path = os.path.join(download_folder, zip_filename)
        # 5 attempts to download and unzip the file correctly
        extract_dir = import_path
        download_file_to_path(full_url, download_folder, zip_filename)
        # unzip
        try:
            z = zipfile.ZipFile(dl_path)
            z.extractall(os.path.join(download_folder, extract_dir))
            print(zip_filename + ' unzipped successfully')
            print('---------')
            z.close()
            current_os = platform.system()
            if (current_os == "Linux" or current_os == "Darwin"):
                file_to_delete = f'{extract_dir}' + f'/{zip_filename}'
            elif current_os == "Windows":
                file_to_delete = f'{extract_dir}' + f'\\{zip_filename}'
            os.remove(file_to_delete)
        except zipfile.BadZipfile as e:
            print("Error while unzipping data" + e)


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
    download_folder = import_path

    # Download and Unzip the files
    print('\nUpdating the Database with the latest CWE Files...')
    full_url = root + zip_file
    zip_filename = os.path.basename(zip_file)
    print(zip_filename)
    dl_path = os.path.join(download_folder, zip_filename)
    # 5 attempts to download and unzip the file correctly
    download_file_to_path(full_url, download_folder, zip_filename)
    # unzip
    extract_dir = import_path
    try:
        z = zipfile.ZipFile(dl_path)
        z.extractall(os.path.join(download_folder, extract_dir))
        print(zip_filename + ' unzipped successfully')
        z.close()
        current_os = platform.system()
        if (current_os == "Linux" or current_os == "Darwin"):
            file_to_delete = f'{extract_dir}' + f'/{zip_filename}'
        elif current_os == "Windows":
            file_to_delete = f'{extract_dir}' + f'\\{zip_filename}'
        os.remove(file_to_delete)
    except zipfile.BadZipfile:
        print('\nUpdating the Database with the latest CWE Files...')


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
    download_folder = import_path

    # Download xml file
    print('\nUpdating the Database with the latest CAPEC Files...')
    full_url = root + xml_file
    xml_filename = os.path.basename(xml_file)
    print(xml_filename)
    download_file_to_path(full_url, download_folder, xml_filename)


def download_datasets(import_path):
    download_files_cve_cpe(import_path)
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
    r = requests.get(url)
    dl_path = os.path.join(download_path, file_name)
    with open(dl_path, 'wb') as file:
        file.write(r.content)