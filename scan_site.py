# scan_site.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
from PIL import Image
from PIL.Image import DecompressionBombWarning
from io import BytesIO
import argparse
import warnings

# ignore warning for clean output
warnings.filterwarnings("ignore", category=DecompressionBombWarning)

# supported formats
SUPPORTED_EXTENSIONS = (".webp", ".jpg", ".jpeg", ".png", ".gif")
MAX_DIMENSION = 10000
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
visited_pages = set()

# scans an image from a URL using Pillow
def scan_image_from_url(url):
    print("\n--------------------------------------")
    print(f"\nImage URL : {url}")

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        img_data = BytesIO(response.content)
        img = Image.open(img_data)
        img_format = (img.format or "Unknown").upper()
        print(f"Scan      : Pillow ({img_format})")
        print("\n--------------------------------------")

        img.verify()

        img = Image.open(BytesIO(response.content))
        width, height = img.size
        mode = img.mode
        file_size = len(response.content)

        print("Image verified successfully")
        print("\n--------------------------------------")

        print(f"\nFormat     : {img_format}")
        print(f"Dimensions : {width} x {height}")
        print(f"Mode       : {mode}")
        print(f"File size  : {file_size} bytes")
        print("\n--------------------------------------")

        warnings_list = []

        # adds to warning list if the file is unusually large
        if width * height > Image.MAX_IMAGE_PIXELS:
            warnings_list.append("Warning: Image size exceeds safe limits (possible decompression bomb)")
        if width > MAX_DIMENSION or height > MAX_DIMENSION:
            warnings_list.append("Warning: Extremely large dimensions may be suspicious")
        if file_size > MAX_FILE_SIZE:
            warnings_list.append("Warning: Very large image file")
        if img_format == "WEBP":
            warnings_list.append("Note: File is in WebP format. CVE-2023-4863 may apply.")

        # prints warnings if there are any
        if warnings_list:
            print()
            for w in warnings_list:
                print(w)
            print("\n--------------------------------------")
        else:
            print("\nNo issues detected. Image appears clean")
            print("\n--------------------------------------")

        print("\nScan completed")
        print("\n--------------------------------------")

    # handles image download or decoding errors
    except Exception as e:
        print("\n--------------------------------------")
        print(f"\nCould not scan image: {url}")
        print(f"Error: {e}")
        print("\n--------------------------------------")

# scans a webpage and adds internal links to the queue
def scan_page(url, base_netloc, queue, max_depth, current_depth):
    if url in visited_pages or current_depth > max_depth:
        return
    visited_pages.add(url)

    print("\n--------------------------------------")
    print(f"\nWebsite Scan: {url}")
    print("\n--------------------------------------")

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"\nCould not load site: {e}")
        print("\n--------------------------------------")
        return

    soup = BeautifulSoup(response.text, "html.parser")
    img_tags = soup.find_all("img")
    scanned = 0

    # scans all supported images
    for img in img_tags:
        src = img.get("src")
        if not src:
            continue

        img_url = urljoin(url, src)

        if img_url.lower().endswith(SUPPORTED_EXTENSIONS):
            scan_image_from_url(img_url)
            scanned += 1

    if scanned == 0:
        print("No supported images found on this page.")
        print("\n--------------------------------------")

    # adds internal links to the queue
    for link in soup.find_all("a", href=True):
        href = link["href"]
        full_url = urljoin(url, href)
        parsed = urlparse(full_url)
        if parsed.netloc == base_netloc and full_url not in visited_pages:
            queue.append((full_url, current_depth + 1))

# main crawl controller
def crawl_site(start_url, max_depth=1):
    queue = deque()
    queue.append((start_url, 0))
    base_netloc = urlparse(start_url).netloc

    while queue:
        current_url, depth = queue.popleft()
        scan_page(current_url, base_netloc, queue, max_depth, depth)

# entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan images from a site (single or recursive).")
    parser.add_argument("--site", required=True, help="Website URL to scan")
    parser.add_argument("--depth", type=int, default=0, help="Max crawl depth (default: 0 = single page only)")
    args = parser.parse_args()

    crawl_site(args.site, max_depth=args.depth)
