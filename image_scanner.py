#image_scanner.py

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
SUPPORTED_EXTENSIONS = (".webp", ".jpg", ".jpeg", ".png", ".gif")

# max safe values
MAX_DIMENSION = 10000
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# track visited pages to prevent re-scanning
visited_pages = set()

# scan image using Pillow

def scan_with_pillow(img_data, from_file=False, path_or_url=""):
    print("\n--------------------------------------")
    print(f"\nScan target: {path_or_url}")
    print("Scan: Pillow")
    print("\n--------------------------------------")

    warnings_list = []

    try:
        img = Image.open(img_data)
        if img.size[0] * img.size[1] > Image.MAX_IMAGE_PIXELS:
            warnings_list.append("Warning: Image size exceeds safe limits (possible decompression bomb)")

        img.verify()
        img_data.seek(0)
        img = Image.open(img_data)

        width, height = img.size
        img_format = (img.format or "Unknown").upper()
        mode = img.mode
        size_bytes = os.path.getsize(path_or_url) if from_file else len(img_data.getbuffer())

        print("\nImage verified successfully")
        print("\n--------------------------------------")
        print(f"Format     : {img_format}")
        print(f"Dimensions : {width} x {height}")
        print(f"Mode       : {mode}")
        print(f"File Size  : {size_bytes} bytes")
        print("\n--------------------------------------")

        if width > MAX_DIMENSION or height > MAX_DIMENSION:
            warnings_list.append("Warning: Extremely large dimensions may be suspicious")
        if size_bytes > MAX_FILE_SIZE:
            warnings_list.append("Warning: Very large image file")

        if warnings_list:
            print()
            for w in warnings_list:
                print(Fore.YELLOW + w)
            print("\n--------------------------------------")
        else:
            print("\nNo issues detected. Image appears clean")
            print("\n--------------------------------------")

        # EXIF metadata check
        if img_format in ("JPEG", "JPG", "PNG"):
            print("\nChecking EXIF metadata...")
            try:
                exif_data = img._getexif() if hasattr(img, "_getexif") else img.info.get("exif")
                if exif_data:
                    if isinstance(exif_data, bytes):
                        exif_data = Image.open(BytesIO(exif_data))._getexif()
                    exif = {ExifTags.TAGS.get(k, k): v for k, v in exif_data.items() if k in ExifTags.TAGS}
                    for tag in ("DateTime", "Make", "Model", "GPSInfo"):
                        if tag in exif:
                            print(f"{tag}: {exif[tag]}")
                else:
                    print("No EXIF metadata found.")
            except Exception as e:
                print(Fore.RED + f"Error reading EXIF metadata: {e}")

        print("\nScan completed")
   
        return img_format

    except Exception as e:
        print(Fore.RED + f"\nError during Pillow scan: {e}")
        print("\n--------------------------------------")
        return None

# scan WebP VP8X chunk manually

def scan_vp8x_chunk(img_data):
    print("\nScan: VP8X Chunk (CVE-2023-4863)")
    print("\n--------------------------------------")

    try:
        data = img_data.read()
        img_data.seek(0)

        if data[:4] != b'RIFF' or data[8:12] != b'WEBP':
            print(Fore.RED + "\nNot a valid WebP file (missing RIFF/WEBP headers)")
            print("\n--------------------------------------")
            return

        offset = 12
        vp8x_found = False
        suspicious = False

        while offset + 8 <= len(data):
            chunk_type = data[offset:offset + 4]
            chunk_size = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            chunk_data = data[offset + 8:offset + 8 + chunk_size]

            if chunk_type == b'VP8X':
                vp8x_found = True

                print("\nChunk Details:")
                print(f"Type   : {chunk_type.decode('ascii')}")
                print(f"Size   : {chunk_size} bytes")

                if len(chunk_data) < 1:
                    print("\nVP8X chunk too short to contain flags")
                    print("\n--------------------------------------")
                    return

                flags = chunk_data[0]
                print(f"Flags  : {flags:08b}")
                print("\n--------------------------------------")

                if flags & 0b11000000:
                    print(Fore.YELLOW + "\nSuspicious: Reserved bits are set in VP8X flags")
                    suspicious = True
                if chunk_size != 10:
                    print(Fore.YELLOW + "\nSuspicious: VP8X chunk size is non-standard (10 bytes expected)")
                    suspicious = True

                if not suspicious:
                    print("\nNo suspicious traits found in VP8X chunk")

                print("\nScan completed")
                return

            offset += 8 + chunk_size
            if chunk_size % 2 == 1:
                offset += 1

        if not vp8x_found:
            print(Fore.YELLOW + "\nNo VP8X chunk found — not an extended WebP")

    except Exception as e:
        print(Fore.RED + f"\nError during VP8X scan: {e}")

    print("\nScan completed")

# scan a local file

def scan_file(filepath):
    print("\n--------------------------------------")
    print(f"\nFile: {os.path.basename(filepath)}")

    if not os.path.exists(filepath):
        print(Fore.RED + "\nFile not found.")
        print("\n--------------------------------------")
        return

    with open(filepath, "rb") as f:
        img_data = BytesIO(f.read())

    fmt = scan_with_pillow(img_data, from_file=True, path_or_url=filepath)

    if fmt == "WEBP" or filepath.lower().endswith(".webp"):
        if fmt is None:
            print(Fore.YELLOW + "\nWarning: Pillow scan failed, attempting VP8X chunk scan ...")
        img_data.seek(0)
        scan_vp8x_chunk(img_data)

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
            print(Fore.RED + f"\nCould not load page: {e}")
            print("\n--------------------------------------")
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
                            print(Fore.YELLOW + "\nWarning: Pillow failed, attempting VP8X chunk scan...")
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
    print("1. Scan a local file")
    print("2. Scan a website")
    choice = input("\nSelect an option (1 or 2): ").strip()

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
    else:
        print(Fore.RED + "\nInvalid option. Exiting.")

if __name__ == "__main__":
    main()
