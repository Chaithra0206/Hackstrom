import type {
  ProtectSocialResponse,
  SafeAgentChatResponse,
  VerifyWatermarkResponse,
} from "@/types/api";

const SIMULATED_DELAY_MS = 800;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeImageSource(imageBase64: string): string {
  const trimmed = imageBase64.trim();
  if (
    trimmed.startsWith("data:image/") ||
    trimmed.startsWith("http://") ||
    trimmed.startsWith("https://") ||
    trimmed.startsWith("/")
  ) {
    return trimmed;
  }
  if (trimmed.startsWith("PHN2Zy") || trimmed.startsWith("PD94bW")) {
    return `data:image/svg+xml;base64,${trimmed}`;
  }
  if (trimmed.startsWith("/9j/")) {
    return `data:image/jpeg;base64,${trimmed}`;
  }
  return `data:image/png;base64,${trimmed}`;
}

function createFallbackRedactedSvgDataUrl(): string {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 856 540" width="856" height="540">
  <rect width="856" height="540" fill="#0f172a" />
  <rect x="48" y="48" width="760" height="444" rx="16" fill="#1e293b" stroke="#334155" stroke-width="2" />
  <rect x="148" y="180" width="560" height="72" rx="6" fill="#000000" />
  <text x="428" y="224" text-anchor="middle" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="22" font-weight="700" fill="#f87171">[PII_REDACTED]</text>
  <rect x="148" y="310" width="560" height="84" rx="6" fill="#000000" />
  <text x="428" y="360" text-anchor="middle" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="22" font-weight="700" fill="#f87171">[PII_REDACTED]</text>
</svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

async function redactImageWithCanvas(imageBase64: string): Promise<string> {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return createFallbackRedactedSvgDataUrl();
  }

  const src = normalizeImageSource(imageBase64);

  return new Promise((resolve) => {
    const img = new Image();
    img.crossOrigin = "anonymous";

    img.onload = () => {
      try {
        const width = img.naturalWidth || img.width || 856;
        const height = img.naturalHeight || img.height || 540;
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;

        const ctx = canvas.getContext("2d");
        if (!ctx) {
          resolve(createFallbackRedactedSvgDataUrl());
          return;
        }

        ctx.drawImage(img, 0, 0, width, height);

        const barWidth = Math.round(width * 0.62);
        const barX = Math.round((width - barWidth) / 2);

        const centerBarHeight = Math.max(36, Math.round(height * 0.13));
        const centerBarY = Math.round(height * 0.43);

        const bottomBarHeight = Math.max(40, Math.round(height * 0.15));
        const bottomBarY = Math.round(height * 0.72);

        const drawRedactionBar = (x: number, y: number, w: number, h: number) => {
          ctx.fillStyle = "#000000";
          ctx.fillRect(x, y, w, h);

          ctx.strokeStyle = "#ef4444";
          ctx.lineWidth = Math.max(2, Math.round(width * 0.003));
          ctx.strokeRect(x, y, w, h);

          const fontSize = Math.max(14, Math.round(h * 0.42));
          ctx.font = `700 ${fontSize}px ui-monospace, SFMono-Regular, Menlo, monospace`;
          ctx.fillStyle = "#f87171";
          ctx.textAlign = "center";
          ctx.textBaseline = "middle";
          ctx.fillText("[PII_REDACTED]", x + w / 2, y + h / 2);
        };

        drawRedactionBar(barX, centerBarY, barWidth, centerBarHeight);
        drawRedactionBar(barX, bottomBarY, barWidth, bottomBarHeight);

        resolve(canvas.toDataURL("image/png"));
      } catch {
        resolve(createFallbackRedactedSvgDataUrl());
      }
    };

    img.onerror = () => {
      resolve(createFallbackRedactedSvgDataUrl());
    };

    img.src = src;
  });
}

async function computeSha256Hex(input: string): Promise<string> {
  if (
    typeof window !== "undefined" &&
    window.crypto?.subtle &&
    typeof TextEncoder !== "undefined"
  ) {
    try {
      const encoded = new TextEncoder().encode(input);
      const hashBuffer = await window.crypto.subtle.digest("SHA-256", encoded);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    } catch {
      // Fall through to deterministic fallback hash
    }
  }

  return "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
}

export async function mockProtectSocial(
  imageBase64: string
): Promise<ProtectSocialResponse> {
  await delay(SIMULATED_DELAY_MS);

  return {
    protected_image_base64: imageBase64,
    watermark_id: "WM-2026-DEV-991",
    ssim_score: 0.984,
    ai_embedding_shift: 0.76,
    processing_time_ms: 420,
  };
}

export async function mockVerifyWatermark(
  _imageBase64: string,
  transforms: string[]
): Promise<VerifyWatermarkResponse> {
  await delay(SIMULATED_DELAY_MS);

  return {
    is_verified: true,
    owner_id: "usr_devishree_07",
    confidence_score: 0.942,
    surviving_transforms: transforms,
  };
}

export async function mockSafeAgentChat(
  prompt: string,
  imageBase64: string,
  simulateAttack: boolean
): Promise<SafeAgentChatResponse> {
  await delay(SIMULATED_DELAY_MS);

  const [sanitizedImage, imageSha256] = await Promise.all([
    redactImageWithCanvas(imageBase64),
    computeSha256Hex(imageBase64 || prompt),
  ]);

  const purgedAt = new Date().toISOString();

  const agentReply = simulateAttack
    ? `Security firewall intercepted an untrusted tool call attempting to exfiltrate image context to https://evil-webhook.io/steal. The prompt ("${prompt}") was answered using only the PII-redacted image: document structure is valid and holder identity fields were masked prior to inference.`
    : `Processed your request ("${prompt}") using the sanitized image. Sensitive regions (FACE_1, ID_NUMBER) and EXIF metadata (GPS, Device, Timestamp) were stripped before model inference, and the temporary image buffer was zero-filled and purged.`;

  const response: SafeAgentChatResponse = {
    agent_reply: agentReply,
    sanitized_image_base64: sanitizedImage,
    stripped_metadata: {
      GPS: "12.9141° N, 74.8560° E",
      Device: "Pixel 9 Pro",
      Timestamp: "2026-11-17T22:30:00Z",
    },
    redacted_entities: ["FACE_1", "ID_NUMBER", "GPS_EXIF"],
    deletion_receipt: {
      receipt_id: `RCP-${Date.now().toString(36).toUpperCase()}`,
      image_sha256: imageSha256,
      purged_at: purgedAt,
      memory_status: "ZERO_FILLED_AND_PURGED",
      signature:
        "ed25519:a4c9f10b7d32e8a1650f9c4b2e118d70fa3c9e52d810b4c77e2a19d3f506c812",
    },
  };

  if (simulateAttack) {
    response.security_alert = {
      blocked: true,
      attack_type: "Prompt Injection Exfiltration",
      blocked_destination: "https://evil-webhook.io/steal",
    };
  }

  return response;
}

