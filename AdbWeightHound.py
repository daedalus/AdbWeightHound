#!/usr/bin/python3
# Author Dario Clavijo 2025
# License GPLv3.

import subprocess
import os
import tempfile
import hashlib
from colorama import Fore, Style, init
import argparse  # Import the argparse module

# Initialize colorama
init(autoreset=True)

# Updated ML model weight file extensions
ML_MODEL_EXTENSIONS = [
    ".tflite", ".onnx", ".pt", ".pth", ".pb", ".h5", ".caffemodel",
    ".weights", ".mlmodel", ".gguf", ".safetensors"
]
APK_EXTENSIONS = [".apk",".xapk",".zip",".jar"]
TMPBASEDIR = "./tmp"
MODELSDIR = "./models_found" 

FOUND = set()  # Set to store found files and avoid duplicates

# Common Android directories to search
SEARCH_PATHS = [
    "/data/data", "/data/local/tmp", "/sdcard/Android/data",
    "/sdcard/Download", "/sdcard/Documents", "/sdcard/", "/"
]

# Known ML model file signatures (magic bytes)
ML_MODEL_SIGNATURES = {
    b" \x00\x00\x00TFL3": "TFlite",
    b"\x1c\x00\x00\x00TFL3": "TFlite",
    b"\x18\x00\x00\x00TFL3": "TFlite",
    b'-\x00\x00\x80\xbfb\xbf\x01': "TFlite",
    b"\x4F\x4E\x4E\x58": "ONNX",  # "ONNX"
    b"\x80\x02\x63\x6E\x6E": "PyTorch",  # Pickle format
    b"\x08\x01\x12": "TensorFlow .pb",  # Protocol buffer
    b'\n"\r\x00\x00 A\r': "TensorFlow .pb",
    b"\x89HDF\r\n\x1A\n": "HDF5 (Keras)",  # Keras HDF5
    b"bplist": "Apple CoreML",  # Binary property list
    b'GGUF\x03\x00\x00\x00': "GGUF",  # GGUF model format
    b"{\n  \"metadata\": {": "SafeTensors"  # JSON-like header
}

def local_shell(command):
    return subprocess.check_output(command.split(" "), stderr=subprocess.DEVNULL, universal_newlines=True)

def adb_shell(command):
    """
    Run an ADB shell command on the connected Android device and return the output.

    Args:
        command (list): A list of strings representing the ADB shell command.

    Returns:
        str: The output of the command, stripped of leading/trailing whitespace.
             Returns an empty string if the command fails.
    """
    try:
        result = subprocess.check_output(["adb", "shell"] + command, stderr=subprocess.DEVNULL, universal_newlines=True)
        return result.strip()
    except subprocess.CalledProcessError:
        return ""

def adb_pull(remote_path, local_path):
    """
    Pull a file from the Android device to the local machine using ADB.

    Args:
        remote_path (str): The path to the file on the Android device.
        local_path (str): The path to save the file on the local machine.

    Returns:
        bool: True if the pull operation succeeds, False otherwise.
    """
    try:
        subprocess.check_output(["adb", "pull", remote_path, local_path], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def calculate_md5(file_path):
    """
    Calculate the MD5 hash of a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The MD5 hash of the file, or None if the file does not exist.
    """
    if not os.path.exists(file_path):
        return None
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_remote_md5(remote_path):
    """
    Calculate the MD5 hash of a file on the Android device.

    Args:
        remote_path (str): The path to the file on the Android device.

    Returns:
        str: The MD5 hash of the file, or None if the file does not exist.
    """
    md5_output = adb_shell(["md5sum", f'"{remote_path}"'])
    if not md5_output:
        return None
    return md5_output.split()[0]

def human_readable_size(size_bytes):
    """
    Convert a file size in bytes to a human-readable format.

    Args:
        size_bytes (int): The size of the file in bytes.

    Returns:
        str: A human-readable string representing the file size (e.g., "1.23 MB").
    """
    if size_bytes == 0:
        return "0B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.2f} {size_names[i]}"

def get_file_size(file_path):
    """
    Retrieve the size of a file on the Android device.

    Args:
        file_path (str): The path to the file on the Android device.

    Returns:
        str: The human-readable size of the file (e.g., "1.23 MB").
             Returns "Unknown" if the size cannot be determined.
    """
    size_output = adb_shell(["stat", "-c%s", f'"{file_path}"'])
    return int(size_output)

def get_file_signature(file_path, local=False):
    """
    Extract the first 8 bytes of a file and compare against known ML model signatures.

    Args:
        file_path (str): The path to the file on the Android device.

    Returns:
        str: The type of the file if it matches a known signature (e.g., "TFlite").
             Returns "Unknown" if no match is found.
    """
    if not local:
        signature_bytes = bytes.fromhex(adb_shell(["xxd","-l 8","-p",file_path]))
    else:
        result = local_shell(f"xxd -l8 -p {file_path}")
        signature_bytes = bytes.fromhex(result)
 
    # Identify file type
    for magic_bytes, model_type in ML_MODEL_SIGNATURES.items():
        if signature_bytes.startswith(magic_bytes):
            return model_type
    return "Unknown"

def scan_files(files, local = False):
    """
    Scan a list of files for ML model or APK extensions.

    Args:
        files (list): A list of file paths to scan.
    """
    for file in files:
        if any(file.lower().endswith(ext) for ext in ML_MODEL_EXTENSIONS):
            if file not in FOUND:
                if not local:
                    size = get_file_size(file)
                    model_type = get_file_signature(file)
                else:
                    size = os.path.getsize(file)
                    model_type = get_file_signature(file, local=local)
                print(f"{Fore.GREEN}[+] Found possible ML Model: {file} ({human_readable_size(size)}) [Type: {model_type}]{Style.RESET_ALL}")
                FOUND.add(file)
        elif any(file.lower().endswith(ext) for ext in APK_EXTENSIONS):
            extract_and_scan_apk(file, local = local)

def extract_and_scan_apk(apk_path, local = False):
    """
    Pull an APK from the device to a temporary directory (if necessary), extract it, and search for ML models.

    Args:
        apk_path (str): The path to the APK file on the Android device.
    """
    print(f"{Fore.BLUE}[*] Processing APK: {apk_path}{Style.RESET_ALL}")

    # Define the local path for the APK in ./tmp/
    apk_name = os.path.basename(apk_path)
    local_apk_path = os.path.join(TMPBASEDIR, apk_name)

    local_md5 = None
    remote_md5 = None
    # Get the MD5 hash of the remote APK

    if not local:
        remote_md5 = get_remote_md5(apk_path)
        if not remote_md5:
            print(f"{Fore.RED}[-] Failed to calculate MD5 for remote APK: {apk_path}{Style.RESET_ALL}")
            return

        # Get the MD5 hash of the local APK (if it exists)
        local_md5 = calculate_md5(local_apk_path)


        if local_md5 and local_md5 == remote_md5:
            print(f"{Fore.YELLOW}[*] APK already exists in {TMPBASEDIR} with matching MD5. Skipping pull.{Style.RESET_ALL}")
        else:
            print(f"{Fore.BLUE}[*] Pulling APK to .{TMPBASEDIR}...{Style.RESET_ALL}")
            if not adb_pull(apk_path, local_apk_path):
                print(f"{Fore.RED}[-] Failed to pull APK: {apk_path}{Style.RESET_ALL}")
                return

    print(f"{Fore.BLUE}[*] Extracting APK: remote: {apk_path} local: {local_apk_path} {Style.RESET_ALL}")  
  
    # Extract the APK
    extracted_dir = os.path.join(TMPBASEDIR, "extracted", apk_name) + "/"
    os.makedirs(extracted_dir, exist_ok=True)
    try:
        result = subprocess.check_output(["unzip", "-u", local_apk_path, "-d", extracted_dir], stderr=subprocess.DEVNULL, universal_newlines=True)
 
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[-] Failed to extract APK: {local_apk_path}{Style.RESET_ALL}")
        return

    # Scan the extracted files
    for root, _, files in os.walk(extracted_dir):
        for file in files:
            file_path = os.path.join(root, file)
            scan_files([file_path], local=True)

def find_ml_models():
    """
    Search for ML model weight files on an Android device by scanning predefined directories.
    """
    print(f"{Fore.BLUE}[*] Searching for ML model files on the device...\n{Style.RESET_ALL}")

    for path in SEARCH_PATHS:
        print(f"{Fore.CYAN}[*] Checking {path}...{Style.RESET_ALL}")
        command = ["find", f'"{path}"', "-type", "f"]
        files = adb_shell(command).split("\n")

        for file in files:
            if any(file.lower().endswith(ext) for ext in ML_MODEL_EXTENSIONS + APK_EXTENSIONS):
                scan_files([file])

def scan_local_directory(directory):
    """
    Scan a local directory for APKs and ML models.

    Args:
        directory (str): The path to the local directory to scan.
    """
    print(f"{Fore.BLUE}[*] Scanning local directory: {directory}{Style.RESET_ALL}")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if any(file.lower().endswith(ext) for ext in APK_EXTENSIONS):
                extract_and_scan_apk(file_path, local=True)
            elif any(file.lower().endswith(ext) for ext in ML_MODEL_EXTENSIONS):
                scan_files([file_path], local=True)

def get_device_info():
    """
    Retrieve and print the Android device's serial number, model, and manufacturer.

    Returns:
        None
    """
    serial = adb_shell(["getprop", "ro.serialno"])
    model = adb_shell(["getprop", "ro.product.model"])
    manufacturer = adb_shell(["getprop", "ro.product.manufacturer"])

    print(f"\n{Fore.BLUE}[*] Device Information:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}Serial Number: {serial if serial else 'Unknown'}{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}Model: {model if model else 'Unknown'}{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}Manufacturer: {manufacturer if manufacturer else 'Unknown'}{Style.RESET_ALL}\n")

def main():
    """
    Main entry point of the script. Retrieves device information and searches for ML models.
    """
    parser = argparse.ArgumentParser(description="Search for ML models on an Android device.")
    parser.add_argument("--file", type=str, help="Specify a single file to scan.")
    parser.add_argument("--local-dir", type=str, help="Specify a local directory to scan for APKs and ML models.")
    args = parser.parse_args()
  
    os.makedirs(TMPBASEDIR, exist_ok=True)    

    if args.file:
        # If a file is specified, scan only that file
        scan_files([args.file])
    elif args.local_dir:
        # If a local directory is specified, scan it for APKs and ML models
        scan_local_directory(args.local_dir)
    else:
        # Otherwise, search for ML models in predefined directories
        get_device_info()
        find_ml_models()

    if len(FOUND) > 0:
        os.makedirs(MODELSDIR, exist_ok=True)
        print(f"\n{Fore.BLUE}[*] Summary:{Style.RESET_ALL}")
        
        # Dictionary to group files by their MD5 hash
        md5_to_files_map = dict()
        
        for ml_file in FOUND:
            # Calculate the MD5 hash of the file
            file_md5 = calculate_md5(ml_file)
            
            # Create a directory for this MD5 hash if it doesn't exist
            md5_model_dir = os.path.join(MODELSDIR, file_md5)
            os.makedirs(md5_model_dir, exist_ok=True)
            
            # Add the file to the dictionary under its MD5 hash
            if file_md5 not in md5_to_files_map:
                md5_to_files_map[file_md5] = set()
            md5_to_files_map[file_md5].add(ml_file)
        
        # Print and copy files grouped by their MD5 hash
        for file_md5, files in md5_to_files_map.items():
            md5_model_dir = os.path.join(MODELSDIR, file_md5)
            print(f"{Fore.BLUE} With MD5 {file_md5}:{Style.RESET_ALL}")
            for ml_file in files:
                # Copy the file to the MD5-specific directory
                dst_file_basename = os.path.basename(ml_file)
                dst_file_path = os.path.join(md5_model_dir, dst_file_basename)
                os.system(f"cp '{ml_file}' '{dst_file_path}'")
                print(f"   {Fore.CYAN} Found possible ML Model: [{ml_file}]. {Style.RESET_ALL}")

if __name__ == "__main__":
    main()
    

