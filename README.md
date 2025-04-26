# CECS 378 Bug Hunting Through Malicious Images

## What is Pillow?
A Python imaging library used to upload and verify images. In this case, it is used to scan safe and malicious images to detect sizing issues which can possibly lead to a decompression bomb.

## What is VP8X?
VP8X is a part of a WebP image that tells the program it has extra features such as animation, metadata, or transparency. If it is messed up, it can be used to exploit the system.

## What is ANIM?
ANIM stands for animation, this image type can contain multiple frames similar to a GIF. Attackers can alter these frames or corrupt them to exploit vulnerabilities.

## What is EXIF?
EXIF stands for exchangable image file format, this image type stores metadata which can include date, time, camera make and model as well as GPS location. Attackers can alter these image types and hide malicious data in them as well. 

## To run:

1. cd to folder

2. For a safe scan using Pillow run "python pillow_scan.py --file pillow_safe.webp" without quotes

3. For a malicious scan using Pillow run "python pillow_scan.py --file pillow_malicious.webp" without quotes

4. For a safe scan using VP8X run "python vp8x_scan.py --file vp8x_malicious.webp" without quotes


To use both of them combined together run "python image_scanner.py" without quotes

1. Select an option, either 1 (local file) or 2 (website)
   
2. If option 1 is selected, type in the path to the desired file or make sure it in your current folder and just type the file name
   
3. If option 2 is selected, type in the full url of the website (For example, "https://www.google.com") without quotes.
