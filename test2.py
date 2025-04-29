import struct

# allows you to enter a secret message
secret_message = "hello, im an orange cat."

# makes EXIF data
exif_header = b'\x00\x00' + secret_message.encode('utf-8')

# opens the original WebP
with open("output.webp", "rb") as f:
    original_data = f.read()

# creates EXIF chunk
exif_chunk_name = b'EXIF'
exif_chunk_size = struct.pack('<I', len(exif_header))
exif_chunk = exif_chunk_name + exif_chunk_size + exif_header

# splits original WebP into RIFF header and data
riff_header = original_data[:12]
remaining_data = original_data[12:]

# makes new file with hidden EXIF
with open("output_secret.webp", "wb") as f:
    f.write(riff_header + exif_chunk + remaining_data)

exit()
