import os
import requests
import zipfile
from bs4 import BeautifulSoup
import platform


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
    tries = 0
    for zip_file in zip_files:
        full_url = root + zip_file
        zip_filename = os.path.basename(zip_file)
        print(zip_filename)
        dl_path = os.path.join(download_folder, zip_filename)
        # 5 attempts to download and unzip the file correctly
        extract_dir = import_path
        while tries < 5:
            r = requests.get(full_url)
            dl_path = os.path.join(download_folder, zip_filename)
            with open(dl_path, 'wb') as z_file:
                z_file.write(r.content)
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
                break
            except zipfile.BadZipfile:
                # Bad download, try again
                pass
            tries += 1


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
    tries = 0
    full_url = root + zip_file
    zip_filename = os.path.basename(zip_file)
    print(zip_filename)
    dl_path = os.path.join(download_folder, zip_filename)
    # 5 attempts to download and unzip the file correctly
    while tries < 5:
        r = requests.get(full_url)
        dl_path = os.path.join(download_folder, zip_filename)
        with open(dl_path, 'wb') as z_file:
            z_file.write(r.content)
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
            break
        except zipfile.BadZipfile:
            # Bad download, try again
            pass
        tries += 1


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
    tries = 0
    full_url = root + xml_file
    xml_filename = os.path.basename(xml_file)
    print(xml_filename)
    dl_path = os.path.join(download_folder, xml_filename)
    # 5 attempts to download the file correctly
    while tries < 5:
        r = requests.get(full_url)
        dl_path = os.path.join(download_folder, xml_filename)
        with open(dl_path, 'wb') as x_file:
            x_file.write(r.content)
        tries += 1


def download_datasets(import_path):
    download_files_cve_cpe(import_path)
    download_files_cwe(import_path)
    download_files_capec(import_path)
