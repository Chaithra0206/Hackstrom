"use client";

import React, { useCallback, useRef, useState } from "react";
import {
  ReactCompareSlider,
  ReactCompareSliderImage,
} from "react-compare-slider";
import {
  ArrowDown,
  ArrowRight,
  CheckCircle2,
  Crop,
  Download,
  FileImage,
  Loader2,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  Upload,
  Wand2,
} from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { protectSocial, toDataUrl, verifyWatermark } from "@/lib/apiClient";
import { addHistoryItem, createThumbnailDataUrl } from "@/lib/historyStore";
import type {
  ProtectSocialResponse,
  VerifyWatermarkResponse,
} from "@/types/api";

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

function loadImageElement(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = "anonymous";
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("Failed to load image into canvas."));
    img.src = src;
  });
}

export function SocialShieldTab() {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const sandboxCanvasRef = useRef<HTMLCanvasElement | null>(null);

  const [sourceImage, setSourceImage] = useState<string | null>(null);
  const [sourceFileName, setSourceFileName] = useState<string>("");
  const [isDragging, setIsDragging] = useState(false);

  const [enableWatermark, setEnableWatermark] = useState(true);
  const [enableCloaking, setEnableCloaking] = useState(true);

  const [isLoadingSample, setIsLoadingSample] = useState(false);
  const [isProtecting, setIsProtecting] = useState(false);
  const [protectResult, setProtectResult] =
    useState<ProtectSocialResponse | null>(null);

  const [mutatedImage, setMutatedImage] = useState<string | null>(null);
  const [appliedTransforms, setAppliedTransforms] = useState<string[]>([]);
  const [isMutating, setIsMutating] = useState(false);

  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyResult, setVerifyResult] =
    useState<VerifyWatermarkResponse | null>(null);

  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleImageSelected = useCallback(async (file: File) => {
    if (!file.type.startsWith("image/")) {
      setErrorMessage("Please choose a valid photo (PNG, JPG, WebP, or SVG).");
      return;
    }
    setErrorMessage(null);
    try {
      const dataUrl = await blobToDataUrl(file);
      setSourceImage(dataUrl);
      setSourceFileName(file.name);
      setProtectResult(null);
      setMutatedImage(null);
      setAppliedTransforms([]);
      setVerifyResult(null);
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

  const handleLoadSamplePortrait = async () => {
    setErrorMessage(null);
    setIsLoadingSample(true);
    try {
      const res = await fetch("/sample-portrait.svg");
      if (!res.ok) {
        throw new Error("Sample photo could not be loaded.");
      }
      const blob = await res.blob();
      const dataUrl = await blobToDataUrl(blob);
      setSourceImage(dataUrl);
      setSourceFileName("sample-portrait.svg");
      setProtectResult(null);
      setMutatedImage(null);
      setAppliedTransforms([]);
      setVerifyResult(null);
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : "Failed to load sample photo."
      );
    } finally {
      setIsLoadingSample(false);
    }
  };

  const handleProtectPhoto = async () => {
    if (!sourceImage) return;
    setErrorMessage(null);
    setIsProtecting(true);
    try {
      const response = await protectSocial(sourceImage);
      const protectedDataUrl = toDataUrl(response.protected_image_base64);
      setProtectResult({
        ...response,
        protected_image_base64: protectedDataUrl,
      });
      setMutatedImage(protectedDataUrl);
      setAppliedTransforms([]);
      setVerifyResult(null);

      const protections: string[] = [];
      if (enableWatermark) protections.push("Invisible Signature");
      if (enableCloaking) protections.push("Anti-Deepfake Shield");

      const thumbnail = await createThumbnailDataUrl(protectedDataUrl);
      addHistoryItem({
        type: "social",
        fileName: sourceFileName || "Protected Photo",
        protections,
        ownerId: "usr_devishree_07",
        watermarkId: response.watermark_id,
        thumbnail,
      });
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : "Could not protect your photo."
      );
    } finally {
      setIsProtecting(false);
    }
  };

  const handleDownloadProtected = () => {
    if (!protectResult) return;
    const link = document.createElement("a");
    link.href = toDataUrl(protectResult.protected_image_base64);
    link.download = `protected-${sourceFileName.replace(/\.[^.]+$/, "") || "portrait"}.png`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const applyCanvasTransform = async (
    mode: "crop" | "vintage" | "compress"
  ) => {
    const currentSrc =
      mutatedImage ??
      (protectResult ? toDataUrl(protectResult.protected_image_base64) : null);
    if (!currentSrc) return;

    setErrorMessage(null);
    setIsMutating(true);
    setVerifyResult(null);

    try {
      const img = await loadImageElement(currentSrc);
      const canvas =
        sandboxCanvasRef.current ?? document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      if (!ctx) {
        throw new Error("Could not prepare image preview.");
      }

      const srcW = img.naturalWidth || img.width || 640;
      const srcH = img.naturalHeight || img.height || 640;

      if (mode === "crop") {
        const cropX = Math.round(srcW * 0.15);
        const cropY = Math.round(srcH * 0.15);
        const cropW = Math.max(1, Math.round(srcW * 0.7));
        const cropH = Math.max(1, Math.round(srcH * 0.7));

        canvas.width = cropW;
        canvas.height = cropH;
        ctx.filter = "none";
        ctx.clearRect(0, 0, cropW, cropH);
        ctx.drawImage(img, cropX, cropY, cropW, cropH, 0, 0, cropW, cropH);

        setMutatedImage(canvas.toDataURL("image/png"));
        setAppliedTransforms((prev) =>
          prev.includes("Cropped") ? prev : [...prev, "Cropped"]
        );
      } else if (mode === "vintage") {
        canvas.width = srcW;
        canvas.height = srcH;
        ctx.clearRect(0, 0, srcW, srcH);
        ctx.filter = "contrast(1.18) sepia(0.45) brightness(0.94)";
        ctx.drawImage(img, 0, 0, srcW, srcH);
        ctx.filter = "none";

        setMutatedImage(canvas.toDataURL("image/png"));
        setAppliedTransforms((prev) =>
          prev.includes("Filtered") ? prev : [...prev, "Filtered"]
        );
      } else {
        canvas.width = srcW;
        canvas.height = srcH;
        ctx.filter = "none";
        ctx.clearRect(0, 0, srcW, srcH);
        ctx.drawImage(img, 0, 0, srcW, srcH);

        setMutatedImage(canvas.toDataURL("image/jpeg", 0.35));
        setAppliedTransforms((prev) =>
          prev.includes("Lower Quality") ? prev : [...prev, "Lower Quality"]
        );
      }
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : "Failed to update photo preview."
      );
    } finally {
      setIsMutating(false);
    }
  };

  const handleResetMutatedImage = () => {
    if (!protectResult) return;
    setMutatedImage(toDataUrl(protectResult.protected_image_base64));
    setAppliedTransforms([]);
    setVerifyResult(null);
    setErrorMessage(null);
  };

  const handleScanAndVerify = async () => {
    const targetImage =
      mutatedImage ??
      (protectResult ? toDataUrl(protectResult.protected_image_base64) : null);
    if (!targetImage) return;

    setErrorMessage(null);
    setIsVerifying(true);
    try {
      const transformsToReport =
        appliedTransforms.length > 0
          ? appliedTransforms
          : ["Original Protected Photo"];
      const res = await verifyWatermark(targetImage, transformsToReport);
      setVerifyResult(res);
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : "Could not check signature."
      );
    } finally {
      setIsVerifying(false);
    }
  };

  const humanSimilarityPercent = protectResult
    ? Math.round(protectResult.ssim_score * 100)
    : 0;
  const disruptionPercent = protectResult
    ? Math.round(protectResult.ai_embedding_shift * 100)
    : 0;
  const matchPercent = verifyResult
    ? Math.round(verifyResult.confidence_score * 100)
    : 0;

  return (
    <div className="space-y-6">
      <canvas ref={sandboxCanvasRef} className="hidden" aria-hidden="true" />

      {errorMessage && (
        <Alert
          variant="destructive"
          className="rounded-[24px] border border-red-300/40 bg-red-950/80 text-red-100 shadow-lg"
        >
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{errorMessage}</AlertDescription>
        </Alert>
      )}

      {/* 1. Primary Bento Card: Upload & Controls */}
      <section className="rounded-[28px] border-t border-l border-white/25 bg-[#7E77B8] p-6 shadow-[0_18px_40px_rgba(32,27,66,0.35)] sm:p-7">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 text-lg font-bold text-[#F5F4FF]">
              <ShieldCheck className="h-5 w-5 text-emerald-300" />
              Choose Your Photo &amp; Protection
            </h2>
            <p className="mt-1 text-sm text-[#EAE7FD]">
              Add an invisible signature and block AI face-cloning before you
              post.
            </p>
          </div>
          <span className="rounded-full bg-[#332D59] px-3.5 py-1 text-xs font-semibold text-[#DCD8FA] shadow-inner">
            Step 1 of 3
          </span>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          {/* Pastel Lavender Dropzone Bento Block */}
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
            className={`flex h-56 cursor-pointer flex-col items-center justify-center rounded-[24px] border-2 border-dashed p-5 text-center transition-all ${
              isDragging
                ? "border-[#473E88] bg-[#DCD8FA] text-[#272248] scale-[1.01]"
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
            {sourceImage ? (
              <div className="flex flex-col items-center gap-2.5">
                <img
                  src={sourceImage}
                  alt="Uploaded portrait preview"
                  className="h-24 w-24 rounded-2xl object-cover shadow-md ring-2 ring-[#473E88]/30"
                />
                <div className="flex items-center gap-1.5 font-mono text-xs font-medium text-[#272248]">
                  <FileImage className="h-3.5 w-3.5 text-[#473E88]" />
                  <span className="max-w-[220px] truncate">
                    {sourceFileName || "Selected Photo"}
                  </span>
                </div>
                <Button
                  type="button"
                  size="sm"
                  className="h-8 rounded-full bg-[#DCD8FA] px-3.5 text-xs font-semibold text-[#272248] shadow-md transition-all hover:-translate-y-0.5 hover:bg-white"
                  onClick={(e) => {
                    e.stopPropagation();
                    void handleLoadSamplePortrait();
                  }}
                  disabled={isLoadingSample}
                >
                  {isLoadingSample ? (
                    <Loader2 className="mr-1.5 h-3 w-3 animate-spin" />
                  ) : (
                    <Sparkles className="mr-1.5 h-3 w-3 text-[#473E88]" />
                  )}
                  Try Another Sample Photo
                </Button>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2.5">
                <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-[#DCD8FA] text-[#272248] shadow-sm">
                  <Upload className="h-5 w-5" />
                </div>
                <p className="text-sm font-bold text-[#272248]">
                  Drop a photo here or click to browse
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
                    void handleLoadSamplePortrait();
                  }}
                  disabled={isLoadingSample}
                >
                  {isLoadingSample ? (
                    <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Sparkles className="mr-1.5 h-3.5 w-3.5 text-[#473E88]" />
                  )}
                  Try with a Sample Photo
                  <span className="ml-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-[#473E88] text-[11px] text-white">
                    <ArrowRight className="h-3 w-3" />
                  </span>
                </Button>
              </div>
            )}
          </div>

          {/* Inset Dark Card for Toggles & Primary Action */}
          <div className="flex flex-col justify-between gap-5 rounded-[24px] border border-white/10 bg-[#332D59] p-5 text-[#F5F4FF] shadow-[0_12px_28px_rgba(24,20,52,0.35)]">
            <div className="space-y-4">
              <div className="flex items-center justify-between gap-4 rounded-2xl bg-[#272248]/80 p-3.5">
                <div className="space-y-0.5">
                  <p className="text-sm font-bold text-[#F5F4FF]">
                    Invisible Signature
                  </p>
                  <p className="text-xs text-[#C8C3F0]">
                    Proves this photo is yours, even if someone crops or
                    screenshots it.
                  </p>
                </div>
                <Switch
                  checked={enableWatermark}
                  onCheckedChange={setEnableWatermark}
                  aria-label="Invisible Signature"
                />
              </div>

              <div className="flex items-center justify-between gap-4 rounded-2xl bg-[#272248]/80 p-3.5">
                <div className="space-y-0.5">
                  <p className="text-sm font-bold text-[#F5F4FF]">
                    Anti-Deepfake Shield
                  </p>
                  <p className="text-xs text-[#C8C3F0]">
                    Stops AI apps from copying your face or art style.
                  </p>
                </div>
                <Switch
                  checked={enableCloaking}
                  onCheckedChange={setEnableCloaking}
                  aria-label="Anti-Deepfake Shield"
                />
              </div>
            </div>

            <Button
              type="button"
              size="lg"
              className="h-12 w-full rounded-full bg-[#473E88] font-bold text-[#F5F4FF] shadow-[0_10px_22px_rgba(20,16,44,0.45)] transition-all hover:-translate-y-0.5 hover:bg-[#574DA3] disabled:opacity-50"
              disabled={
                !sourceImage ||
                isProtecting ||
                (!enableWatermark && !enableCloaking)
              }
              onClick={handleProtectPhoto}
            >
              {isProtecting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Protecting Your Photo...
                </>
              ) : (
                <>
                  <ShieldCheck className="mr-2 h-4 w-4" />
                  Protect My Photo
                  <span className="ml-2 inline-flex h-6 w-6 items-center justify-center rounded-full bg-[#DCD8FA] text-[#272248]">
                    <ArrowRight className="h-3.5 w-3.5" />
                  </span>
                </>
              )}
            </Button>
          </div>
        </div>
      </section>

      {/* Centered Pill Step Indicator */}
      <div className="flex justify-center">
        <div className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-[#332D59] px-4 py-1.5 text-xs font-semibold text-[#DCD8FA] shadow-md">
          <ArrowDown className="h-3.5 w-3.5 text-emerald-300" />
          <span>Step 1: Pick Photo</span>
          <span className="text-white/40">→</span>
          <span>Step 2: Compare</span>
          <span className="text-white/40">→</span>
          <span>Step 3: Test Theft</span>
        </div>
      </div>

      {/* 2. Visual Proof & Metrics Bento Card */}
      {protectResult && sourceImage && (
        <section className="space-y-5 rounded-[28px] border-t border-l border-white/25 bg-[#7E77B8] p-6 shadow-[0_18px_40px_rgba(32,27,66,0.35)] sm:p-7">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-bold text-[#F5F4FF]">
                Compare Original vs. Protected
              </h2>
              <p className="mt-0.5 text-sm text-[#EAE7FD]">
                Slide across to see there&apos;s no visible difference to human
                eyes.
              </p>
            </div>
            <Button
              type="button"
              size="sm"
              className="rounded-full bg-[#DCD8FA] px-4 font-bold text-[#272248] shadow-md transition-all hover:-translate-y-0.5 hover:bg-white"
              onClick={handleDownloadProtected}
            >
              <Download className="mr-2 h-4 w-4" />
              Download Safe Photo
            </Button>
          </div>

          {/* Metric Pills */}
          <div className="flex flex-wrap items-center gap-2.5">
            <Badge className="rounded-full bg-[#DCD8FA] px-3.5 py-1 text-xs font-bold text-[#272248] shadow-sm">
              Looks {humanSimilarityPercent}% identical to human eyes
            </Badge>
            <Badge className="rounded-full bg-[#332D59] px-3.5 py-1 text-xs font-semibold text-[#F5F4FF] shadow-sm">
              {disruptionPercent}% scrambled for AI models
            </Badge>
            <Badge className="rounded-full bg-[#C8C3F0] px-3.5 py-1 font-mono text-xs font-semibold text-[#272248] shadow-sm">
              Signature ID: {protectResult.watermark_id}
            </Badge>
          </div>

          <div className="overflow-hidden rounded-[24px] border border-white/15 bg-[#332D59] p-2 shadow-[0_12px_28px_rgba(24,20,52,0.35)]">
            <ReactCompareSlider
              className="max-h-[420px] w-full rounded-[18px]"
              itemOne={
                <ReactCompareSliderImage
                  src={sourceImage}
                  alt="Original photo"
                  style={{ objectFit: "contain", maxHeight: "420px" }}
                />
              }
              itemTwo={
                <ReactCompareSliderImage
                  src={toDataUrl(protectResult.protected_image_base64)}
                  alt="Protected photo"
                  style={{ objectFit: "contain", maxHeight: "420px" }}
                />
              }
            />
          </div>
        </section>
      )}

      {/* 3. Interactive "Test If Your Signature Survives Theft" Bento Card */}
      {protectResult && mutatedImage && (
        <section className="space-y-5 rounded-[28px] border-t border-l border-white/25 bg-[#7E77B8] p-6 shadow-[0_18px_40px_rgba(32,27,66,0.35)] sm:p-7">
          <div>
            <h2 className="flex items-center gap-2 text-lg font-bold text-[#F5F4FF]">
              <ScanSearch className="h-5 w-5 text-[#DCD8FA]" />
              Test If Your Signature Survives Theft
            </h2>
            <p className="mt-1 text-sm text-[#EAE7FD]">
              Try cropping, filtering, or lowering the quality of your photo,
              then check if your signature is still there.
            </p>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            {/* Left: Pastel Lavender Attack Controls + Inset Preview */}
            <div className="space-y-4 rounded-[24px] border-t border-l border-white/50 bg-[#C8C3F0] p-5 text-[#272248] shadow-[0_10px_24px_rgba(32,27,66,0.22)]">
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  size="sm"
                  className="rounded-full bg-[#DCD8FA] px-3.5 text-xs font-bold text-[#272248] shadow-sm transition-all hover:-translate-y-0.5 hover:bg-white"
                  disabled={isMutating}
                  onClick={() => void applyCanvasTransform("crop")}
                >
                  <Crop className="mr-1.5 h-3.5 w-3.5 text-[#473E88]" />
                  Crop Photo
                </Button>
                <Button
                  type="button"
                  size="sm"
                  className="rounded-full bg-[#DCD8FA] px-3.5 text-xs font-bold text-[#272248] shadow-sm transition-all hover:-translate-y-0.5 hover:bg-white"
                  disabled={isMutating}
                  onClick={() => void applyCanvasTransform("vintage")}
                >
                  <Wand2 className="mr-1.5 h-3.5 w-3.5 text-[#473E88]" />
                  Add Filter
                </Button>
                <Button
                  type="button"
                  size="sm"
                  className="rounded-full bg-[#DCD8FA] px-3.5 text-xs font-bold text-[#272248] shadow-sm transition-all hover:-translate-y-0.5 hover:bg-white"
                  disabled={isMutating}
                  onClick={() => void applyCanvasTransform("compress")}
                >
                  <FileImage className="mr-1.5 h-3.5 w-3.5 text-[#473E88]" />
                  Lower Quality
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="rounded-full text-xs font-semibold text-[#272248]/80 hover:bg-[#DCD8FA]"
                  disabled={isMutating || appliedTransforms.length === 0}
                  onClick={handleResetMutatedImage}
                >
                  <RotateCcw className="mr-1.5 h-3.5 w-3.5" />
                  Reset Photo
                </Button>
              </div>

              <div className="flex min-h-[240px] items-center justify-center rounded-[20px] bg-[#332D59] p-4 shadow-inner">
                <img
                  src={mutatedImage}
                  alt="Edited protected photo preview"
                  className="max-h-[240px] rounded-xl object-contain"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2 text-xs font-medium text-[#272248]">
                <span>Changes applied:</span>
                {appliedTransforms.length === 0 ? (
                  <span className="rounded-full bg-[#DCD8FA] px-2.5 py-0.5 font-mono text-xs font-semibold text-[#272248]">
                    None yet
                  </span>
                ) : (
                  appliedTransforms.map((t) => (
                    <span
                      key={t}
                      className="rounded-full bg-[#332D59] px-2.5 py-0.5 font-mono text-xs text-[#F5F4FF]"
                    >
                      {t}
                    </span>
                  ))
                )}
              </div>
            </div>

            {/* Right: Inset Dark Verification Card */}
            <div className="flex flex-col justify-between gap-4 rounded-[24px] border border-white/10 bg-[#332D59] p-5 text-[#F5F4FF] shadow-[0_12px_28px_rgba(24,20,52,0.35)]">
              <div className="space-y-4">
                <Button
                  type="button"
                  size="lg"
                  className="h-12 w-full rounded-full bg-[#473E88] font-bold text-[#F5F4FF] shadow-md transition-all hover:-translate-y-0.5 hover:bg-[#574DA3] disabled:opacity-50"
                  disabled={isVerifying || isMutating}
                  onClick={handleScanAndVerify}
                >
                  {isVerifying ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Checking Signature...
                    </>
                  ) : (
                    <>
                      <ScanSearch className="mr-2 h-4 w-4" />
                      Check If It&apos;s Still Mine
                      <span className="ml-2 inline-flex h-6 w-6 items-center justify-center rounded-full bg-[#DCD8FA] text-[#272248]">
                        <ArrowRight className="h-3.5 w-3.5" />
                      </span>
                    </>
                  )}
                </Button>

                {verifyResult ? (
                  <div className="space-y-4 rounded-[20px] border border-emerald-300/30 bg-[#262047] p-5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-300" />
                        <span className="text-sm font-bold text-emerald-200">
                          {verifyResult.is_verified
                            ? `Verified! This photo belongs to you (${matchPercent}% match).`
                            : "Signature not found."}
                        </span>
                      </div>
                      <span className="rounded-full bg-[#DCD8FA] px-3 py-0.5 font-mono text-xs font-bold text-[#272248]">
                        {verifyResult.owner_id}
                      </span>
                    </div>

                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-[#C8C3F0]">Signature Match</span>
                        <span className="font-mono text-xs font-bold text-[#F5F4FF]">
                          {matchPercent}%
                        </span>
                      </div>
                      <Progress value={matchPercent} />
                    </div>

                    <div className="space-y-2">
                      <p className="text-xs text-[#C8C3F0]">
                        Survived These Changes
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {verifyResult.surviving_transforms.map((transform) => (
                          <span
                            key={transform}
                            className="rounded-full bg-[#3E376C] px-3 py-1 font-mono text-xs text-[#F5F4FF]"
                          >
                            {transform}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex min-h-[190px] items-center justify-center rounded-[20px] border border-dashed border-white/20 p-6 text-center text-sm text-[#C8C3F0]">
                    Try cropping or filtering the photo on the left, then click{" "}
                    <span className="mx-1 font-bold text-[#F5F4FF]">
                      Check If It&apos;s Still Mine
                    </span>{" "}
                    to confirm your signature survived.
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
