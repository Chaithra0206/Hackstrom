import argparse
import sys
import json
from pathlib import Path
from app.cloak import cloak_image

def main():
    parser = argparse.ArgumentParser(description="CLI harness to test adversarial cloaking on an image.")
    parser.add_argument("--image", required=True, help="Path to the input image file to cloak.")
    parser.add_argument("--epsilon", type=float, default=8/255, help="Perturbation budget epsilon (default: 8/255).")
    parser.add_argument("--steps", type=int, default=8, help="Number of attack steps for PGD (default: 8).")
    parser.add_argument("--out", default="out/cloaked.png", help="Path to save the cloaked output image.")
    args = parser.parse_args()

    img_path = Path(args.image)
    if not img_path.exists():
        print(f"Error: Image {img_path} not found.")
        sys.exit(1)

    print(f"Loading {img_path}...")
    with open(img_path, "rb") as f:
        img_bytes = f.read()

    print(f"Running PGD cloak (epsilon={args.epsilon}, steps={args.steps})...")
    try:
        cloaked_bytes, metrics = cloak_image(img_bytes, epsilon=args.epsilon, steps=args.steps)
    except Exception as e:
        print(f"Error during cloaking: {e}")
        sys.exit(1)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(cloaked_bytes)

    print("\n--- METRICS ---")
    print(json.dumps(metrics, indent=4))
    print(f"\nCloaked image saved to: {out_path.absolute()}")

if __name__ == "__main__":
    main()
