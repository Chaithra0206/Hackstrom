import io
from PIL import Image
import numpy as np
from skimage.metrics import structural_similarity as ssim
from skimage.metrics import peak_signal_noise_ratio as psnr

def compute_ssim_psnr(original_bytes: bytes, modified_bytes: bytes) -> dict:
    img1 = Image.open(io.BytesIO(original_bytes)).convert('RGB')
    img2 = Image.open(io.BytesIO(modified_bytes)).convert('RGB')
    if img1.size != img2.size:
        img2 = img2.resize(img1.size)
    arr1 = np.array(img1)
    arr2 = np.array(img2)
    return {
        "ssim": float(ssim(arr1, arr2, channel_axis=-1, data_range=255)),
        "psnr": float(psnr(arr1, arr2, data_range=255))
    }
