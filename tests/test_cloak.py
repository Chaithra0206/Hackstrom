import pytest
import base64
import io
from PIL import Image
from app.cloak import cloak_image
from app.metrics import compute_ssim_psnr

def test_cloak_image():
    img = Image.new('RGB', (224, 224), color='red')
    buffered = io.BytesIO()
    img.save(buffered, format="JPEG")
    img_bytes = buffered.getvalue()

    cloaked_bytes, metrics = cloak_image(img_bytes, epsilon=8/255, steps=2)

    assert cloaked_bytes is not None
    assert "ssim" in metrics
    assert "psnr" in metrics
    assert "cosine_similarity_before" in metrics
    assert "cosine_similarity_after" in metrics
    assert metrics["cosine_similarity_after"] <= metrics["cosine_similarity_before"]
    assert metrics["ssim"] > 0.95
