"use client";

import React, { useCallback, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  Bot,
  CreditCard,
  EyeOff,
  FileImage,
  Loader2,
  Send,
  ShieldAlert,
  ShieldCheck,
  Upload,
  User,
} from "lucide-react";

import { DeletionReceipt } from "@/components/DeletionReceipt";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { safeAgentChat, toDataUrl } from "@/lib/apiClient";
import { addHistoryItem, createThumbnailDataUrl } from "@/lib/historyStore";
import type { SafeAgentChatResponse } from "@/types/api";

const PRESET_PROMPT = "Verify ID validity & extract expiry";

function blobToDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      if (typeof reader.result === "string") {
        resolve(reader.result);
      } else {
        reject(new Error("Failed to read file as data URL."));
      }
    };
    reader.onerror = () => reject(new Error("FileReader error."));
    reader.readAsDataURL(blob);
  });
}

export function SafeAgentTab() {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [attachedImage, setAttachedImage] = useState<string | null>(null);
  const [attachedFileName, setAttachedFileName] = useState<string>("");
  const [isDragging, setIsDragging] = useState(false);
  const [isLoadingSample, setIsLoadingSample] = useState(false);

  const [prompt, setPrompt] = useState<string>(PRESET_PROMPT);
  const [submittedPrompt, setSubmittedPrompt] = useState<string | null>(null);
  const [simulateAttack, setSimulateAttack] = useState<boolean>(false);

  const [isSending, setIsSending] = useState<boolean>(false);
  const [agentResponse, setAgentResponse] =
    useState<SafeAgentChatResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleImageSelected = useCallback(async (file: File) => {
    if (!file.type.startsWith("image/")) {
      setErrorMessage("Please attach a valid photo (PNG, JPG, WebP, or SVG).");
      return;
    }
    setErrorMessage(null);
    try {
      const dataUrl = await blobToDataUrl(file);
      setAttachedImage(dataUrl);
      setAttachedFileName(file.name);
      setAgentResponse(null);
      setSubmittedPrompt(null);
    } catch {
      setErrorMessage("Could not read the selected photo.");
    }
  }, []);

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      void handleImageSelected(file);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      void handleImageSelected(file);
    }
  };

  const handleLoadSampleId = async () => {
    setErrorMessage(null);
    setIsLoadingSample(true);
    try {
      const res = await fetch("/sample-id-card.svg");
      if (!res.ok) {
        throw new Error("Sample ID card could not be loaded.");
      }
      const blob = await res.blob();
      const dataUrl = await blobToDataUrl(blob);
      setAttachedImage(dataUrl);
      setAttachedFileName("sample-id-card.svg");
      setAgentResponse(null);
      setSubmittedPrompt(null);
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : "Failed to load sample ID."
      );
    } finally {
      setIsLoadingSample(false);
    }
  };

  const handleSend = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!attachedImage || !prompt.trim()) return;

    setErrorMessage(null);
    setIsSending(true);
    const currentPrompt = prompt.trim();
    setSubmittedPrompt(currentPrompt);

    try {
      const res = await safeAgentChat(
        currentPrompt,
        attachedImage,
        simulateAttack
      );
      setAgentResponse(res);

      const censoredDataUrl = toDataUrl(res.sanitized_image_base64);
      const thumbnail = await createThumbnailDataUrl(censoredDataUrl);
      addHistoryItem({
        type: "agent",
        prompt: currentPrompt,
        hiddenItems: ["Faces", "ID Numbers", "Location Tags"],
        leakStatus: res.security_alert?.blocked
          ? "Blocked Sneaky Leak"
          : "No Leaks",
        blockedDestination: res.security_alert?.blocked_destination,
        receiptId: res.deletion_receipt.receipt_id,
        deletionReceipt: res.deletion_receipt,
        thumbnail,
      });
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : "Could not reach the AI assistant."
      );
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="space-y-6">
      {errorMessage && (
        <Alert
          variant="destructive"
          className="rounded-[24px] border border-red-300/40 bg-red-950/80 text-red-100 shadow-lg"
        >
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{errorMessage}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Left Bento Card: Ask AI Safely */}
        <section className="flex flex-col rounded-[28px] border-t border-l border-white/25 bg-[#7E77B8] p-6 shadow-[0_18px_40px_rgba(32,27,66,0.35)]">
          <div className="mb-5 flex items-center justify-between gap-2">
            <div>
              <h2 className="flex items-center gap-2 text-lg font-bold text-[#F5F4FF]">
                <Bot className="h-5 w-5 text-[#DCD8FA]" />
                Ask AI Safely
              </h2>
              <p className="mt-1 text-sm text-[#EAE7FD]">
                Private details and location tags are hidden on your device
                before the AI sees anything.
              </p>
            </div>
          </div>

          <div className="flex flex-1 flex-col gap-5">
            {/* Pastel Lavender Dropzone */}
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  fileInputRef.current?.click();
                }
              }}
              className={`flex h-52 cursor-pointer flex-col items-center justify-center rounded-[24px] border-2 border-dashed p-5 text-center transition-all ${
                isDragging
                  ? "border-[#473E88] bg-[#DCD8FA] text-[#272248]"
                  : "border-[#473E88]/35 bg-[#C8C3F0] text-[#272248] shadow-[0_10px_24px_rgba(32,27,66,0.22)] hover:bg-[#D5D1F6]"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                className="hidden"
                onChange={handleFileInputChange}
              />
              {attachedImage ? (
                <div className="flex flex-col items-center gap-2">
                  <img
                    src={attachedImage}
                    alt="Attached document preview"
                    className="max-h-24 rounded-xl object-contain shadow-md ring-2 ring-[#473E88]/30"
                  />
                  <div className="flex items-center gap-1.5 font-mono text-xs font-medium text-[#272248]">
                    <FileImage className="h-3.5 w-3.5 text-[#473E88]" />
                    <span className="max-w-[240px] truncate">
                      {attachedFileName || "Attached Photo"}
                    </span>
                  </div>
                  <Button
                    type="button"
                    size="sm"
                    className="h-8 rounded-full bg-[#DCD8FA] px-3.5 text-xs font-bold text-[#272248] shadow-md transition-all hover:-translate-y-0.5 hover:bg-white"
                    onClick={(e) => {
                      e.stopPropagation();
                      void handleLoadSampleId();
                    }}
                    disabled={isLoadingSample}
                  >
                    {isLoadingSample ? (
                      <Loader2 className="mr-1.5 h-3 w-3 animate-spin" />
                    ) : (
                      <CreditCard className="mr-1.5 h-3 w-3 text-[#473E88]" />
                    )}
                    Reload Sample ID
                  </Button>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-2">
                  <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#DCD8FA] text-[#272248] shadow-sm">
                    <Upload className="h-5 w-5" />
                  </div>
                  <p className="text-sm font-bold text-[#272248]">
                    Drop an ID card or personal photo here
                  </p>
                  <p className="text-xs text-[#272248]/75">
                    PNG, JPG, WebP, or SVG
                  </p>
                  <Button
                    type="button"
                    size="sm"
                    className="mt-1 h-9 rounded-full bg-[#DCD8FA] px-4 text-xs font-bold text-[#272248] shadow-md transition-all hover:-translate-y-0.5 hover:bg-white"
                    onClick={(e) => {
                      e.stopPropagation();
                      void handleLoadSampleId();
                    }}
                    disabled={isLoadingSample}
                  >
                    {isLoadingSample ? (
                      <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <CreditCard className="mr-1.5 h-3.5 w-3.5 text-[#473E88]" />
                    )}
                    Try with a Sample ID
                    <span className="ml-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-[#473E88] text-[11px] text-white">
                      <ArrowRight className="h-3 w-3" />
                    </span>
                  </Button>
                </div>
              )}
            </div>

            {/* Prompt & Controls */}
            <form onSubmit={handleSend} className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-[#EAE7FD]">
                  Your Question
                </span>
                <button
                  type="button"
                  className="rounded-full bg-[#6E67A8] px-3 py-1 text-xs font-medium text-[#F5F4FF] transition hover:bg-[#5B5494]"
                  onClick={() => setPrompt(PRESET_PROMPT)}
                >
                  Preset: &ldquo;{PRESET_PROMPT}&rdquo;
                </button>
              </div>

              <div className="flex gap-2">
                <Input
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder="Ask the AI about your photo..."
                  aria-label="Ask the AI"
                  className="h-11 rounded-full border-white/20 bg-[#332D59] px-4 text-[#F5F4FF] placeholder:text-[#C8C3F0]/70 focus-visible:ring-[#DCD8FA]"
                />
                <Button
                  type="submit"
                  className="h-11 rounded-full bg-[#473E88] px-5 font-bold text-[#F5F4FF] shadow-md transition-all hover:-translate-y-0.5 hover:bg-[#3A3274] disabled:opacity-50"
                  disabled={!attachedImage || !prompt.trim() || isSending}
                >
                  {isSending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <>
                      <Send className="mr-1.5 h-4 w-4" />
                      Send
                    </>
                  )}
                </Button>
              </div>

              <div className="flex items-center justify-between gap-3 rounded-[20px] border border-amber-300/35 bg-[#332D59] px-4 py-3">
                <div className="flex items-start gap-2.5">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
                  <div>
                    <p className="text-xs font-bold text-amber-200">
                      Test Hacker Trick
                    </p>
                    <p className="text-[11px] text-[#D5D1F5]">
                      Pretend a hidden prompt tries to steal and email your
                      photo.
                    </p>
                  </div>
                </div>
                <Switch
                  checked={simulateAttack}
                  onCheckedChange={setSimulateAttack}
                  aria-label="Test Hacker Trick"
                />
              </div>
            </form>

            {/* Inset Dark Conversation Output */}
            <div className="flex-1 rounded-[24px] border border-white/10 bg-[#332D59] p-4 shadow-inner">
              <p className="mb-3 text-xs font-bold uppercase tracking-wider text-[#C8C3F0]">
                Chat
              </p>
              <ScrollArea className="h-[220px] pr-2">
                {submittedPrompt ? (
                  <div className="space-y-4">
                    <div className="flex items-start gap-2.5">
                      <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[#DCD8FA] text-[#272248]">
                        <User className="h-3.5 w-3.5" />
                      </div>
                      <div className="space-y-0.5 text-sm">
                        <p className="text-xs font-semibold text-[#C8C3F0]">
                          You
                        </p>
                        <p className="text-[#F5F4FF]">{submittedPrompt}</p>
                      </div>
                    </div>

                    {isSending ? (
                      <div className="flex items-center gap-2 pl-9 text-xs text-[#C8C3F0]">
                        <Loader2 className="h-3.5 w-3.5 animate-spin text-[#DCD8FA]" />
                        Hiding private details and asking AI...
                      </div>
                    ) : agentResponse ? (
                      <div className="flex items-start gap-2.5">
                        <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-400/20 text-emerald-300">
                          <Bot className="h-3.5 w-3.5" />
                        </div>
                        <div className="space-y-0.5 text-sm">
                          <p className="text-xs font-semibold text-emerald-300">
                            AI Assistant
                          </p>
                          <p className="leading-relaxed text-[#F5F4FF]">
                            {agentResponse.agent_reply}
                          </p>
                        </div>
                      </div>
                    ) : null}
                  </div>
                ) : (
                  <div className="flex h-[180px] items-center justify-center text-center text-xs text-[#C8C3F0]">
                    Attach a photo or click &ldquo;Try with a Sample ID&rdquo;,
                    then send a question to see how your privacy is protected.
                  </div>
                )}
              </ScrollArea>
            </div>
          </div>
        </section>

        {/* Right Bento Column: Privacy Inspector */}
        <div className="space-y-6">
          {/* Card A: What the AI Actually Sees */}
          <section className="space-y-4 rounded-[28px] border-t border-l border-white/25 bg-[#7E77B8] p-6 shadow-[0_18px_40px_rgba(32,27,66,0.35)]">
            <div>
              <h2 className="flex items-center gap-2 text-lg font-bold text-[#F5F4FF]">
                <EyeOff className="h-5 w-5 text-[#DCD8FA]" />
                What the AI Actually Sees
              </h2>
              <p className="mt-1 text-sm text-[#EAE7FD]">
                We covered your face, ID number, and GPS location on your device
                before sending.
              </p>
            </div>

            {agentResponse ? (
              <div className="space-y-4">
                <div className="flex items-center justify-center rounded-[22px] bg-[#332D59] p-3 shadow-inner">
                  <img
                    src={toDataUrl(agentResponse.sanitized_image_base64)}
                    alt="Photo with private details hidden"
                    className="max-h-48 rounded-xl object-contain"
                  />
                </div>

                <div className="rounded-[20px] bg-[#C8C3F0] p-4 text-[#272248] space-y-3">
                  <div className="space-y-1.5">
                    <p className="text-xs font-bold text-[#272248]">
                      Hidden Details
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {agentResponse.redacted_entities.map((entity) => (
                        <span
                          key={entity}
                          className="rounded-full bg-[#DCD8FA] px-3 py-1 font-mono text-xs font-semibold text-[#272248] shadow-sm"
                        >
                          {entity}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <p className="text-xs font-bold text-[#272248]">
                      Removed Photo Tags
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {Object.entries(agentResponse.stripped_metadata).map(
                        ([key, value]) => (
                          <span
                            key={key}
                            className="rounded-full bg-[#332D59] px-3 py-1 font-mono text-xs text-[#F5F4FF]"
                          >
                            {key}: {value}
                          </span>
                        )
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-[22px] border border-dashed border-white/30 bg-[#332D59]/55 p-6 text-center text-xs text-[#EAE7FD]">
                Send a question to preview the censored photo and the hidden
                details that never left your device.
              </div>
            )}
          </section>

          {/* Centered Step Pill */}
          <div className="flex justify-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-[#332D59] px-4 py-1 text-xs font-semibold text-[#DCD8FA] shadow-md">
              <ArrowDown className="h-3.5 w-3.5 text-emerald-300" />
              <span>Leak Check &amp; Deletion Proof</span>
            </div>
          </div>

          {/* Card B: Leak Blocker */}
          {agentResponse?.security_alert?.blocked ? (
            <Alert
              variant="destructive"
              className="rounded-[24px] border border-red-300/50 bg-red-950/90 p-5 text-red-50 shadow-lg"
            >
              <ShieldAlert className="h-5 w-5 text-red-300" />
              <AlertTitle className="text-sm font-bold text-red-100">
                Blocked a Sneaky Leak!
              </AlertTitle>
              <AlertDescription className="mt-1.5 space-y-2 text-xs text-red-100/90">
                <p>
                  Something tried to send your photo to an outside website, and
                  we stopped it.
                </p>
                <span className="inline-block rounded-full bg-red-900 px-3 py-1 font-mono text-xs text-red-100">
                  {agentResponse.security_alert.blocked_destination}
                </span>
              </AlertDescription>
            </Alert>
          ) : (
            <section className="flex items-center justify-between gap-3 rounded-[24px] border border-white/15 bg-[#332D59] px-5 py-4 shadow-md">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-emerald-400/20 text-emerald-300">
                  <ShieldCheck className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-sm font-bold text-emerald-200">
                    No Leaks Detected
                  </p>
                  <p className="text-xs text-[#D5D1F5]">
                    Your photo stayed strictly inside this chat.
                  </p>
                </div>
              </div>
              <Badge className="rounded-full bg-[#DCD8FA] px-3 py-1 text-xs font-bold text-[#272248]">
                All Clear
              </Badge>
            </section>
          )}

          {/* Card C: Proof Your Photo Was Deleted */}
          {agentResponse && (
            <DeletionReceipt receipt={agentResponse.deletion_receipt} />
          )}
        </div>
      </div>
    </div>
  );
}
