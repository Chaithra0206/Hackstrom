export interface ProtectSocialResponse {
  protected_image_base64: string;
  watermark_id: string;
  ssim_score: number;
  ai_embedding_shift: number;
  processing_time_ms: number;
}

export interface VerifyWatermarkResponse {
  is_verified: boolean;
  owner_id: string;
  confidence_score: number;
  surviving_transforms: string[];
}

export interface SafeAgentChatResponse {
  agent_reply: string;
  sanitized_image_base64: string;
  stripped_metadata: Record<string, string>;
  redacted_entities: string[];
  security_alert?: {
    blocked: boolean;
    attack_type: string;
    blocked_destination: string;
  };
  deletion_receipt: {
    receipt_id: string;
    image_sha256: string;
    purged_at: string;
    memory_status: "ZERO_FILLED_AND_PURGED";
    signature: string;
  };
}

