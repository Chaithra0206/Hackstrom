import numpy as np
from PIL import Image

# Load both images
img1 = np.array(Image.open("demo.jpg").convert("RGB")).astype(np.float32)
img2 = np.array(Image.open("demo_cloaked.jpg").convert("RGB")).astype(np.float32)

# Subtract them to reveal the hidden noise
noise = np.abs(img1 - img2)
noise = np.clip(noise * 10, 0, 255).astype(np.uint8) # Multiply by 10 so you can see it

# Save it
Image.fromarray(noise).save("noise_difference.jpg")
print("Saved noise_difference.jpg! Open it to see the AI-killer pattern.")
