# vp8x_scan.py
import os
import struct

def scan_vp8x_chunk(path):
    print("\n--------------------------------------")
    print(f"\nFile: {os.path.basename(path)}")
    print("Scan: VP8X Chunk (CVE-2023-4863)")
    print("\n--------------------------------------")

    if not os.path.exists(path):
        print("\nFile not found")
        print("\n--------------------------------------")
        return

    try:
        with open(path, "rb") as f:
            data = f.read()

        print(f"\nFile found and loaded ({len(data)} bytes)")
        print("\n--------------------------------------")
        
        if data[:4] != b'RIFF' or data[8:12] != b'WEBP':
            print("\nNot a valid WebP file (missing RIFF/WEBP headers)")
            print("\n--------------------------------------")
            return

        offset = 12
        vp8x_found = False
        suspicious = False

        while offset + 8 <= len(data):
            chunk_type = data[offset:offset + 4]
            chunk_size = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            chunk_data = data[offset + 8:offset + 8 + chunk_size]

            try:
                chunk_name = chunk_type.decode("ascii")
            except:
                chunk_name = str(chunk_type)

            if chunk_type == b'VP8X':
                vp8x_found = True
                print("\nChunk Details:")
                print(f"   ├─ Type: {chunk_name}")
                print(f"   ├─ Size: {chunk_size} bytes")

                if len(chunk_data) < 1:
                    print("\nVP8X chunk too short to contain flags")
                    print("\n--------------------------------------")
                    return

                flags = chunk_data[0]
                print(f"   ├─ Flags: {flags:08b}")
                print("\n--------------------------------------")

                # Suspicious checks
                if flags & 0b11000000:
                    print("\nSuspicious: Reserved bits are set in VP8X flags")
                    print("\n--------------------------------------")
                    suspicious = True
                if chunk_size != 10:
                    print("\nSuspicious: VP8X chunk size is non-standard (10 bytes expected)")
                    print("\n--------------------------------------")
                    suspicious = True

                if not suspicious:
                    print("\nNo suspicious traits found in VP8X chunk")
                    print("\n--------------------------------------")

                print("\nScan complete")
                print("\n--------------------------------------")
                return

            offset += 8 + chunk_size
            if chunk_size % 2 == 1:
                offset += 1  # padding

        if not vp8x_found:
            print("\nNo VP8X chunk found — not an extended WebP")
            print("\n--------------------------------------")

    except Exception as e:
        print(f"\nError reading file: {e}")
        print("\n--------------------------------------")

    print("\nScan completed")
    print("\n--------------------------------------")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Check a WebP file for VP8X chunk issues (CVE-2023-4863).")
    parser.add_argument("--file", required=True, help="Path to the WebP file")
    args = parser.parse_args()

    scan_vp8x_chunk(args.file)
