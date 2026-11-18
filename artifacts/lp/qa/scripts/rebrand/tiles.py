import sys
from PIL import Image
src, out, w, h = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
im = Image.open(src).convert("RGB")
scale = w / im.width
im = im.resize((w, int(im.height * scale)))
n = 0
for top in range(0, im.height, h):
    im.crop((0, top, w, min(top + h, im.height))).save(f"{out}-{n}.jpg", quality=80); n += 1
print(n, im.size)
