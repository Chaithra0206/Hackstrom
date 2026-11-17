import type { SafeAgentChatResponse } from "@/types/api";

export const HISTORY_STORAGE_KEY = "trustlens_history";
export const HISTORY_UPDATED_EVENT = "trustlens-history-updated";
const MAX_HISTORY_ITEMS = 50;

export interface SocialHistoryItem {
  id: string;
  type: "social";
  timestamp: string;
  fileName: string;
  protections: string[];
  ownerId: string;
  watermarkId: string;
  thumbnail: string;
}

export interface AgentHistoryItem {
  id: string;
  type: "agent";
  timestamp: string;
  prompt: string;
  hiddenItems: string[];
  leakStatus: "No Leaks" | "Blocked Sneaky Leak";
  blockedDestination?: string;
  receiptId: string;
  deletionReceipt: SafeAgentChatResponse["deletion_receipt"];
  thumbnail: string;
}

export type HistoryItem = SocialHistoryItem | AgentHistoryItem;

export type NewHistoryItemInput =
  | Omit<SocialHistoryItem, "id" | "timestamp">
  | Omit<AgentHistoryItem, "id" | "timestamp">;

export function getHistory(): HistoryItem[] {
  if (typeof window === "undefined") {
    return [];
  }
  try {
    const raw = window.localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as HistoryItem[]) : [];
  } catch {
    return [];
  }
}

export function addHistoryItem(item: NewHistoryItemInput): HistoryItem {
  const newItem: HistoryItem = {
    ...item,
    id: `hist-${Date.now().toString(36)}-${Math.random()
      .toString(36)
      .slice(2, 6)}`,
    timestamp: new Date().toISOString(),
  } as HistoryItem;

  if (typeof window !== "undefined") {
    try {
      const existing = getHistory();
      const updated = [newItem, ...existing].slice(0, MAX_HISTORY_ITEMS);
      window.localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(updated));
      window.dispatchEvent(new Event(HISTORY_UPDATED_EVENT));
    } catch {
      // Ignore storage quota errors gracefully
    }
  }

  return newItem;
}

export function clearHistory(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(HISTORY_STORAGE_KEY);
    window.dispatchEvent(new Event(HISTORY_UPDATED_EVENT));
  } catch {
    // Ignore storage errors gracefully
  }
}

export async function createThumbnailDataUrl(
  src: string,
  maxWidth = 180
): Promise<string> {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return src;
  }

  return new Promise((resolve) => {
    const img = new Image();
    img.crossOrigin = "anonymous";
    img.onload = () => {
      try {
        const origW = img.naturalWidth || img.width || maxWidth;
        const origH = img.naturalHeight || img.height || maxWidth;
        const scale = Math.min(1, maxWidth / origW);
        const w = Math.max(1, Math.round(origW * scale));
        const h = Math.max(1, Math.round(origH * scale));

        const canvas = document.createElement("canvas");
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext("2d");
        if (!ctx) {
          resolve(src);
          return;
        }
        ctx.drawImage(img, 0, 0, w, h);
        resolve(canvas.toDataURL("image/jpeg", 0.72));
      } catch {
        resolve(src);
      }
    };
    img.onerror = () => resolve(src);
    img.src = src;
  });
}

export function formatRelativeTime(isoTimestamp: string): string {
  const date = new Date(isoTimestamp);
  const diffSeconds = Math.max(
    0,
    Math.floor((Date.now() - date.getTime()) / 1000)
  );

  if (diffSeconds < 45) return "Just now";
  const diffMins = Math.floor(diffSeconds / 60);
  if (diffMins < 60) {
    return diffMins === 1 ? "1 min ago" : `${diffMins} mins ago`;
  }
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) {
    return diffHours === 1 ? "1 hour ago" : `${diffHours} hours ago`;
  }
  const diffDays = Math.floor(diffHours / 24);
  return diffDays === 1 ? "1 day ago" : `${diffDays} days ago`;
}

