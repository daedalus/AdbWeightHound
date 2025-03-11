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
APK_EXTENSIONS = [".apk"]

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
            extract_and_scan_apk(file)

def extract_and_scan_apk(apk_path):
    """
    Pull an APK from the device to a temporary directory (if necessary), extract it, and search for ML models.

    Args:
        apk_path (str): The path to the APK file on the Android device.
    """
    print(f"{Fore.BLUE}[*] Processing APK: {apk_path}{Style.RESET_ALL}")

    # Define the local path for the APK in /tmp/
    apk_name = os.path.basename(apk_path)
    local_apk_path = os.path.join("/tmp", apk_name)

    # Get the MD5 hash of the remote APK
    remote_md5 = get_remote_md5(apk_path)
    if not remote_md5:
        print(f"{Fore.RED}[-] Failed to calculate MD5 for remote APK: {apk_path}{Style.RESET_ALL}")
        return

    # Get the MD5 hash of the local APK (if it exists)
    local_md5 = calculate_md5(local_apk_path)

    # Compare MD5 hashes
    if local_md5 and local_md5 == remote_md5:
        print(f"{Fore.YELLOW}[*] APK already exists in /tmp/ with matching MD5. Skipping pull.{Style.RESET_ALL}")
    else:
        print(f"{Fore.BLUE}[*] Pulling APK to /tmp/...{Style.RESET_ALL}")
        if not adb_pull(apk_path, local_apk_path):
            print(f"{Fore.RED}[-] Failed to pull APK: {apk_path}{Style.RESET_ALL}")
            return

    # Extract the APK
    extracted_dir = os.path.join("/tmp", "extracted", apk_name)
    os.makedirs(extracted_dir, exist_ok=True)
    try:
        subprocess.check_output(["unzip", f'"{local_apk_path}"', "-d", f'"{extracted_dir}"'], stderr=subprocess.DEVNULL, shell=True)
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
    args = parser.parse_args()

    get_device_info()

    if args.file:
        # If a file is specified, scan only that file
        scan_files([args.file])
    else:
        # Otherwise, search for ML models in predefined directories
        find_ml_models()

if __name__ == "__main__":
    main()
