# TBC

The brain collector is a Python script designed to search for machine learning model weight files on an Android device via ADB. It scans common directories for known ML model file extensions and signatures and can also extract APK files to analyze their contents.

## Features
- Scans Android devices for ML model files.
- Supports various model file formats, including .tflite, .onnx, .pt, .pb, .h5, and more.
- Detects files based on extensions and magic byte signatures.
- Extracts APK files and searches for embedded ML models.
- Provides device information such as serial number, model, and manufacturer.
- Displays file size in a human-readable format.
- Supports local file scanning as well.
- Cleanup functionality: Optionally cleans up the tmp/ directory after execution.

## Prerequisites
- Python 3.x
- ADB (Android Debug Bridge) installed and added to system PATH.
- Required Python modules: colorama, argparse.
- A connected Android device with ADB debugging enabled.

## Installation
1. Clone the repository or download the script.
2. Install dependencies using:
   ```bash
   pip install colorama
   ```
3. Ensure ADB is installed and accessible:
   ```bash
   adb devices
   ```

## Usage
Run the script to scan for ML models on a connected device:
```bash
$ python AdbWeightHound.py
usage: AdbWeightHound.py [-h] [--file FILE] [--local-dir LOCAL_DIR] [--export-csv EXPORT_CSV] [--cleanup]

Search for ML models on an Android device.

options:
  -h, --help            show this help message and exit
  --file FILE           Specify a single file to scan.
  --local-dir LOCAL_DIR
                        Specify a local directory to scan for APKs and ML models.
  --export-csv EXPORT_CSV
                        Specify a filename to export the summary to CSV.
  --cleanup             Clean up the tmp/ directory after execution.

```

To scan a specific file:
```bash
$ python AdbWeightHound.py --file /path/to/file
```

## How It Works
1. The script retrieves device information using ADB.
2. It searches predefined directories for known ML model file extensions.
3. If an APK file is found, it is extracted and scanned for embedded models.
4. Found models are displayed with their file size and detected format.
5. If the --cleanup flag is provided, the tmp/ directory is cleaned up after execution.

## Example Output
```
[*] Device Information:
    Serial Number: XYZ12345
    Model: Pixel 6
    Manufacturer: Google

[*] Searching for ML model files on the device...
[+] Found possible ML Model: /sdcard/Download/model.tflite (12.3 MB) [Type: TFlite]
```

## License
This project is licensed under the MIT License.

## Disclaimer
This tool is for educational and research purposes only. Use it responsibly and ensure you have permission before scanning any device.
