import io
from PIL import Image
import numpy as np

def cloak_image(image_bytes: bytes, epsilon: float = 8/255, steps: int = 8, model_name: str = "auto") -> tuple[bytes, dict]:
    import torch
    import torch.nn.functional as F
    import open_clip
    from app.metrics import compute_ssim_psnr

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model, _, _ = open_clip.create_model_and_transforms('ViT-B-32', pretrained='openai', device=device)
    model.eval()
    
    img_pil = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    
    # Proper tensor conversion [0, 1]
    img_np = np.array(img_pil).astype(np.float32) / 255.0
    img_tensor = torch.from_numpy(img_np).permute(2, 0, 1).unsqueeze(0).to(device)
    
    mean = torch.tensor([0.48145466, 0.4578275, 0.40821073], device=device).view(1, 3, 1, 1)
    std = torch.tensor([0.26862954, 0.26130258, 0.27577711], device=device).view(1, 3, 1, 1)
    
    def normalize(t):
        return (t - mean) / std
        
    with torch.no_grad():
        orig_emb = F.normalize(model.encode_image(normalize(img_tensor)), dim=-1)
        
    adv_tensor = img_tensor.clone().detach()
    alpha = epsilon / 4.0
    
    for i in range(steps):
        adv_tensor.requires_grad_(True)
        adv_emb = F.normalize(model.encode_image(normalize(adv_tensor)), dim=-1)
        loss = torch.cosine_similarity(orig_emb, adv_emb).mean()
        model.zero_grad()
        loss.backward()
        
        with torch.no_grad():
            # Update and clamp strictly in the [0, 1] pixel space
            adv_tensor = adv_tensor + alpha * adv_tensor.grad.sign()
            delta = torch.clamp(adv_tensor - img_tensor, min=-epsilon, max=epsilon)
            adv_tensor = torch.clamp(img_tensor + delta, min=0.0, max=1.0).detach()
            
    with torch.no_grad():
        adv_emb = F.normalize(model.encode_image(normalize(adv_tensor)), dim=-1)
        cos_after = torch.cosine_similarity(orig_emb, adv_emb).item()
        
    adv_img = adv_tensor.squeeze(0).cpu().numpy()
    adv_img = np.transpose(adv_img, (1, 2, 0))
    adv_img = np.clip(adv_img * 255.0, 0, 255).astype(np.uint8)
    
    out_img = Image.fromarray(adv_img)
    out_bytes = io.BytesIO()
    out_img.save(out_bytes, format='PNG')
    out_bytes_val = out_bytes.getvalue()
    
    quality = compute_ssim_psnr(image_bytes, out_bytes_val)
    
    metrics = {
        "ssim": quality["ssim"],
        "psnr": quality["psnr"],
        "cosine_similarity_before": 1.0,
        "cosine_similarity_after": cos_after,
        "epsilon": epsilon,
        "steps": steps,
        "model": "ViT-B-32"
    }
    return out_bytes_val, metrics
