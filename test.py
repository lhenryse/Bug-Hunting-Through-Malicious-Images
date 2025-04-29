from PIL import Image

# replaces your image name to create webp
img = Image.open("gato.jpg")  
img.save("output.webp", format="WEBP")
exit()
