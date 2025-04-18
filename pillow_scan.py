# pillow_scan.py
from PIL import Image
from PIL.Image import DecompressionBombWarning
import warnings
import os
import argparse

# ignore warning for clean output
warnings.filterwarnings("ignore", category=DecompressionBombWarning)

MAX_DIMENSION = 10000
MAX_FILE_SIZE = 10 * 1024 * 1024

# scanner using pillow
def scan_with_pillow(path):
    print("\n--------------------------------------")
    print(f"\nFile: {os.path.basename(path)}")
    print("Scan: Pillow")
    print("\n--------------------------------------")

    if not os.path.exists(path):
        print("\nFile not found")
        print("\n--------------------------------------")
        return
        
    warnings_list = []

    # compares sizing to look for possible malicious intent
    try:
        img = Image.open(path)
        if img.size[0] * img.size[1] > Image.MAX_IMAGE_PIXELS:
            warnings_list.append("Warning: Image size exceeds safe limits (possible decompression bomb)")
        img.verify()

        print("\nImage verified successfully")
        print("\n--------------------------------------")

        img = Image.open(path)
        print(f"\nFormat     : {img.format}")
        print(f"Dimensions : {img.size[0]} x {img.size[1]}")
        print(f"Mode       : {img.mode}")

        width, height = img.size
        file_size = os.path.getsize(path)
        print(f"File size  : {file_size} bytes")
        print("\n--------------------------------------")

        if width > MAX_DIMENSION or height > MAX_DIMENSION:
            warnings_list.append("Warning: Extremely large dimensions may be suspicious")
        if file_size > MAX_FILE_SIZE:
            warnings_list.append("Warning: Very large WebP file")
        if img.format != "WEBP":
            warnings_list.append("Note: File is not in WEBP format. This check is for WebP exploits")

    # image can not be processed
    except Exception as e:
        print(f"\nCould not process image: {e}")
        print("\n--------------------------------------")
        return

    # prints warnings if there are any
    if warnings_list:
        print()
        for w in warnings_list:
            print(w)
        print("\n--------------------------------------")
    else:
        print("\nNo issues detected. Image appears clean")
        print("\n--------------------------------------")

    # scan is completed
    print("\nScan completed")
    print("\n--------------------------------------")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a WebP image for suspicious traits.")
    parser.add_argument("--file", required=True, help="Path to the image to scan")
    args = parser.parse_args()

    scan_with_pillow(args.file)