# image_scanner.py

import os
import struct
import requests
from io import BytesIO
from collections import deque
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from PIL import Image, ExifTags
from PIL.Image import DecompressionBombWarning
import warnings
from colorama import Fore, Style, init

# initialize colorama
init(autoreset=True)

# ignore decompression bomb warnings for clean output
warnings.filterwarnings("ignore", category=DecompressionBombWarning)

# supported image types
SUPPORTED_EXTENSIONS = (".webp", ".jpg", ".jpeg", ".png", ".gif", ".tiff", ".pdf")

# max safe values
MAX_DIMENSION = 10000
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# track visited pages to prevent re-scanning
visited_pages = set()

# scan image using Pillow
def scan_with_pillow(img_data, from_file=False, path_or_url=""):
    print("\nScanner: Pillow")

    warnings_list = []

    try:
        img = Image.open(img_data)
        img.verify()
        img_data.seek(0)
        img = Image.open(img_data)

        width, height = img.size
        img_format = (img.format or "Unknown").upper()
        mode = img.mode
        size_bytes = os.path.getsize(path_or_url) if from_file else len(img_data.getbuffer())

        print("- Image verified successfully\n")

        # image info
        print("General Information")
        print(f"- Format     : {img_format}")
        print(f"- Dimensions : {width} x {height}")
        print(f"- Mode       : {mode}")
        print(f"- File Size  : {size_bytes} bytes")

        # compares sizing to look for possible malicious intent
        if width * height > Image.MAX_IMAGE_PIXELS:
            warnings_list.append("Warning: Image size exceeds safe limits (possible decompression bomb)")
        if width > MAX_DIMENSION or height > MAX_DIMENSION:
            warnings_list.append("Warning: Extremely large dimensions may be suspicious")
        if size_bytes > MAX_FILE_SIZE:
            warnings_list.append("Warning: Very large image file")

        print("\nSecurity Warnings")
        if warnings_list:
            for w in warnings_list:
                print(Fore.RED+ "- " + w)
        else:
            print(Fore.YELLOW +"- No suspicious traits detected.")

        # checks for EXIF metadata
        if img_format in ("JPEG", "JPG", "PNG") and hasattr(img, "_getexif"):
            print("\nScanner: EXIF Metadata")
            try:
                exif_data = img._getexif()
                if exif_data:
                    exif = {ExifTags.TAGS.get(k, k): v for k, v in exif_data.items() if k in ExifTags.TAGS}
                    for tag in ("DateTime", "Make", "Model", "GPSInfo"):
                        if tag in exif:
                            print(f"- {tag}: {exif[tag]}")
                else:
                    print(Fore.YELLOW + f"- No EXIF metadata found.")
            except Exception as e:
                print(Fore.RED + f"Error reading EXIF metadata: {e}")

        # check general metadata (info fields)
        if img.info:
            print("\nScanner: Metadata Checking")
            suspicious = False
            for key, value in img.info.items():
                if isinstance(value, str):
                    if "<script>" in value.lower() or "password" in value.lower() or "secret" in value.lower():
                        print(Fore.RED + f"- Suspicious content detected in {key}: {value}")
                        suspicious = True
            if not suspicious:
                print(Fore.YELLOW + "- No suspicious metadata fields detected.")

        return img_format

    except Exception as e:
        print(Fore.RED + f"\nError, Pillow scan failed: {e}")
        return None

# scan WebP VP8X chunk manually
def scan_vp8x_chunk(img_data):
    print("\nScanner: VP8X Chunk Security Check")

    try:
        data = img_data.read()
        img_data.seek(0)

        if data[:4] != b'RIFF' or data[8:12] != b'WEBP':
            print(Fore.RED + "- Not a valid WebP file (missing RIFF/WEBP headers)")
            return

        offset = 12
        suspicious = False

        while offset + 8 <= len(data):
            chunk_type = data[offset:offset + 4]
            chunk_size = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            chunk_data = data[offset + 8:offset + 8 + chunk_size]

            if chunk_type == b'VP8X':
                print("- VP8X chunk found")
                flags = chunk_data[0]
                print(f"- Flags: {flags:08b}")

                if flags & 0b11000000:
                    print(Fore.RED + "Suspicious: Reserved bits set in VP8X flags")
                    suspicious = True
                if chunk_size != 10:
                    print(Fore.YELLOW + "Suspicious: Non-standard VP8X chunk size")
                    suspicious = True

                if not suspicious:
                    print(Fore.YELLOW + "- No suspicious traits detected in VP8X chunk.")
                return

            offset += 8 + chunk_size
            if chunk_size % 2 == 1:
                offset += 1

        print(Fore.YELLOW + "- No VP8X chunk found (not an extended WebP)")

    except Exception as e:
        print(Fore.RED + f"- Error during VP8X scan: {e}")

# extract EXIF hidden message from WebP manually
def extract_exif_from_webp(file_path):
    print("\nScanner: Hidden Data Detection")

    found_exif = False

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        offset = 12
        while offset + 8 <= len(data):
            chunk_type = data[offset:offset + 4]
            chunk_size = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            chunk_data = data[offset + 8:offset + 8 + chunk_size]

            if chunk_type == b'EXIF':
                found_exif = True
                print("- EXIF chunk found")
                try:
                    decoded = chunk_data.decode("utf-8", errors="ignore")
                    print("- Decoded hidden message:")
                    print(f"  {decoded}")
                except Exception as e:
                    print(Fore.RED + f"Failed to decode EXIF data: {e}")
                break  # <- important, no need to keep searching

            offset += 8 + chunk_size
            if chunk_size % 2 == 1:
                offset += 1

        if not found_exif:
            print(Fore.YELLOW + f"- No hidden data detected.")

    except Exception as e:
        print(Fore.RED + f"Error reading EXIF data: {e}")

# scan a local file
def scan_file(filepath):
    print("\n--------------------------------------")
    print(f"Scanning File: {os.path.basename(filepath)}")
    print("--------------------------------------")

    if not os.path.exists(filepath):
        print(Fore.RED + "\nError, File not found.\n")
        return

    with open(filepath, "rb") as f:
        img_data = BytesIO(f.read())

    fmt = scan_with_pillow(img_data, from_file=True, path_or_url=filepath)

    if fmt == "WEBP" or filepath.lower().endswith(".webp"):
        if fmt is None:
            print(Fore.RED + "\nWarning: Pillow scan failed, attempting VP8X chunk scan...")
        img_data.seek(0)
        scan_vp8x_chunk(img_data)
        extract_exif_from_webp(filepath)

    print("\n--------------------------------------")
    print("Scan Completed")
    print("--------------------------------------\n")

# scan a website and its internal images
def scan_site(start_url, max_depth=0):
    queue = deque()
    queue.append((start_url, 0))
    base_netloc = urlparse(start_url).netloc

    while queue:
        current_url, depth = queue.popleft()
        if current_url in visited_pages or depth > max_depth:
            continue

        visited_pages.add(current_url)

        print("\nWebsite Scan:", current_url)
        print("\n--------------------------------------")

        try:
            response = requests.get(current_url, timeout=10)
            response.raise_for_status()
        except Exception as e:
            print(Fore.RED + f"\nCould not load page: {e}\n")
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        for img_tag in soup.find_all("img"):
            src = img_tag.get("src")
            if not src:
                continue
            img_url = urljoin(current_url, src)

            if img_url.lower().endswith(SUPPORTED_EXTENSIONS):
                try:
                    img_resp = requests.get(img_url, timeout=10)
                    img_resp.raise_for_status()
                    img_data = BytesIO(img_resp.content)
                    fmt = scan_with_pillow(img_data, from_file=False, path_or_url=img_url)

                    if fmt == "WEBP" or img_url.lower().endswith(".webp"):
                        if fmt is None:
                            print(Fore.RED + "\nWarning: Pillow failed, attempting VP8X chunk scan...")
                        img_data.seek(0)
                        scan_vp8x_chunk(img_data)

                except Exception as e:
                    print(Fore.RED + f"\nFailed to scan image {img_url}: {e}")

        for link_tag in soup.find_all("a", href=True):
            href = link_tag.get("href")
            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc == base_netloc:
                queue.append((full_url, depth + 1))

# interactive menu
def main():
    print("\nImage Vulnerability Scanner")

    while True:
        print("\n--------------------------------------")
        print("1. Scan a local file")
        print("2. Scan a website")
        print("3. Exit")

        choice = input("\nSelect an option (1, 2, or 3): ").strip()

        if choice == "1":
            filepath = input("\nEnter path to image file: ").strip()
            scan_file(filepath)
        elif choice == "2":
            url = input("\nEnter website URL: ").strip()
            depth_input = input("Enter max crawl depth (default 0): ").strip()
            try:
                depth = int(depth_input) if depth_input else 0
            except ValueError:
                depth = 0
            scan_site(url, max_depth=depth)
        elif choice == "3":
            print("\nExiting.\n")
            break
        else:
            print(Fore.RED + "\nInvalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
