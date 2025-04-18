# CECS 378 Bug Hunting Through Malicious Images

## What is Pillow?
A Python imaging library. In this case, it is used to scan safe and malicious images to detect sizing issues which can possibly lead to a decompression bomb.

## What is VP8X?
VP8X is a part of a WebP image that tells the program it has extra features such as animation or transparency. If it is messed up, it can be used to exploit the system.

## To run:

1. cd to folder

2. For a safe scan using Pillow run "python pillow_scan.py --file pillow_safe.webp" without quotes

3. For a malicious scan using Pillow run "python pillow_scan.py --file pillow_malicious.webp" without quotes

4. For a safe scan using VP8X run "python vp8x_scan.py --file vp8x_malicious.webp" without quotes
