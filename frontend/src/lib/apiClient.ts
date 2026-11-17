import {
  mockProtectSocial,
  mockSafeAgentChat,
  mockSanitizeImage,
  mockVerifyWatermark,
} from "@/lib/mockApi";
import type {
  ProtectSocialResponse,
  SafeAgentChatResponse,
  SanitizeResponse,
  VerifyWatermarkResponse,
} from "@/types/api";

const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK === "true";
const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/+$/, "") ||
  "http://localhost:8000";
const PRIVACY_API_BASE_URL =
  process.env.NEXT_PUBLIC_PRIVACY_API_URL?.replace(/\/+$/, "") ||
  "http://localhost:8001";

export function toDataUrl(b64: string): string {
  const trimmed = b64.trim();
  if (!trimmed) {
    return "";
  }
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
  if (trimmed.startsWith("R0lGOD")) {
    return `data:image/gif;base64,${trimmed}`;
  }
  if (trimmed.startsWith("UklGR")) {
    return `data:image/webp;base64,${trimmed}`;
  }
  return `data:image/png;base64,${trimmed}`;
}

async function postJson<TResponse>(
  path: string,
  body: Record<string, unknown>
): Promise<TResponse> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "");
    throw new Error(
      `API request failed (${response.status} ${response.statusText})${
        errorText ? `: ${errorText}` : ""
      }`
    );
  }

  return (await response.json()) as TResponse;
}

export async function protectSocial(
  imageBase64: string
): Promise<ProtectSocialResponse> {
  if (USE_MOCK) {
    return mockProtectSocial(imageBase64);
  }

  return postJson<ProtectSocialResponse>("/api/social/protect", {
    image_base64: imageBase64,
  });
}

export async function verifyWatermark(
  imageBase64: string,
  transforms: string[] = []
): Promise<VerifyWatermarkResponse> {
  if (USE_MOCK) {
    return mockVerifyWatermark(imageBase64, transforms);
  }

  return postJson<VerifyWatermarkResponse>("/api/social/verify", {
    image_base64: imageBase64,
    transforms,
  });
}

export async function safeAgentChat(
  prompt: string,
  imageBase64: string,
  simulateAttack = false
): Promise<SafeAgentChatResponse> {
  if (USE_MOCK) {
    return mockSafeAgentChat(prompt, imageBase64, simulateAttack);
  }

  // Pre-sanitize with Module 1 (Local Privacy Filter) before dispatching to Agent Gateway
  let sanitizedB64 = imageBase64;
  let strippedMeta: Record<string, string> = {};
  let detectedEntities: string[] = [];

  try {
    const sanitizeResult = await sanitizeImage(imageBase64);
    sanitizedB64 = sanitizeResult.sanitized_image_base64;
    strippedMeta = sanitizeResult.audit.stripped_metadata;
    detectedEntities = sanitizeResult.audit.detected_entities;
  } catch (err) {
    console.warn("Local Privacy Filter bypass/fallback:", err);
  }

  return postJson<SafeAgentChatResponse>("/api/agent/chat", {
    prompt,
    image_base64: sanitizedB64,
    simulate_attack: simulateAttack,
    stripped_metadata: strippedMeta,
    redacted_entities: detectedEntities,
  });
}

export async function sanitizeImage(
  imageBase64: string,
  options?: {
    blur_faces?: boolean;
    redact_pii?: boolean;
    strip_metadata?: boolean;
  }
): Promise<SanitizeResponse> {
  if (USE_MOCK) {
    return mockSanitizeImage(imageBase64);
  }

  const response = await fetch(`${PRIVACY_API_BASE_URL}/api/sanitize`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      image_base64: imageBase64,
      blur_faces: options?.blur_faces ?? true,
      redact_pii: options?.redact_pii ?? true,
      strip_metadata: options?.strip_metadata ?? true,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "");
    throw new Error(
      `Sanitize API request failed (${response.status} ${response.statusText})${
        errorText ? `: ${errorText}` : ""
      }`
    );
  }

  return (await response.json()) as SanitizeResponse;
}


