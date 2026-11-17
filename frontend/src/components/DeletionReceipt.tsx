"use client";

import React from "react";
import { Download, FileCheck2, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { SafeAgentChatResponse } from "@/types/api";

interface DeletionReceiptProps {
  receipt: SafeAgentChatResponse["deletion_receipt"];
}

export function DeletionReceipt({ receipt }: DeletionReceiptProps) {
  const handleDownloadJson = () => {
    const jsonPayload = JSON.stringify(receipt, null, 2);
    const blob = new Blob([jsonPayload], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `deletion-receipt-${receipt.receipt_id}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <section
      id="receipt-section"
      className="space-y-4 rounded-[24px] border border-white/15 bg-[#332D59] p-6 text-[#F5F4FF] shadow-[0_14px_30px_rgba(24,20,52,0.38)]"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="flex items-center gap-2 text-base font-bold text-[#F5F4FF]">
            <FileCheck2 className="h-4 w-4 text-emerald-300" />
            Proof Your Photo Was Deleted
          </h3>
          <p className="mt-0.5 text-xs text-[#D5D1F5]">
            Your photo was removed from temporary memory right after the AI
            answered.
          </p>
        </div>
        <Badge className="rounded-full border border-emerald-300/40 bg-emerald-400/20 px-3 py-1 text-xs font-semibold text-emerald-200">
          <span className="mr-1.5 inline-block h-2 w-2 animate-pulse rounded-full bg-emerald-300" />
          Wiped from Memory
        </Badge>
      </div>

      <div className="space-y-2.5 rounded-[18px] bg-[#262047] p-4 text-xs">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-[#C8C3F0]">Proof ID</span>
          <span className="rounded-full bg-[#DCD8FA] px-2.5 py-0.5 font-mono text-[11px] font-semibold text-[#272248]">
            {receipt.receipt_id}
          </span>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-[#C8C3F0]">Deleted At</span>
          <span className="rounded-full bg-[#3E376C] px-2.5 py-0.5 font-mono text-[11px] text-[#F5F4FF]">
            {receipt.purged_at}
          </span>
        </div>

        <div className="space-y-1">
          <span className="block text-[#C8C3F0]">Photo Fingerprint</span>
          <span className="block break-all rounded-xl bg-[#3E376C] px-3 py-1.5 font-mono text-[11px] text-[#F5F4FF]">
            {receipt.image_sha256}
          </span>
        </div>

        <div className="space-y-1">
          <span className="block text-[#C8C3F0]">Digital Stamp</span>
          <span className="block break-all rounded-xl bg-[#3E376C] px-3 py-1.5 font-mono text-[11px] text-emerald-200">
            {receipt.signature}
          </span>
        </div>
      </div>

      <div className="flex items-center justify-between gap-3 pt-1">
        <div className="flex items-center gap-1.5 text-xs text-[#D5D1F5]">
          <ShieldCheck className="h-4 w-4 text-emerald-300" />
          <span>Nothing saved or stored</span>
        </div>
        <Button
          type="button"
          size="sm"
          onClick={handleDownloadJson}
          className="rounded-full bg-[#DCD8FA] px-4 font-semibold text-[#272248] shadow-md transition-all hover:-translate-y-0.5 hover:bg-[#EAE7FD]"
        >
          <Download className="mr-1.5 h-3.5 w-3.5" />
          Save Proof
        </Button>
      </div>
    </section>
  );
}
