"use client";

import React, { useEffect, useState } from "react";
import {
  Bot,
  Clock,
  Download,
  EyeOff,
  FileCheck2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  clearHistory,
  formatRelativeTime,
  getHistory,
  HISTORY_UPDATED_EVENT,
  type HistoryItem,
} from "@/lib/historyStore";

export function HistoryTab() {
  const [items, setItems] = useState<HistoryItem[]>([]);

  useEffect(() => {
    const sync = () => setItems(getHistory());
    sync();

    window.addEventListener(HISTORY_UPDATED_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(HISTORY_UPDATED_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const totalPhotosProtected = items.length;
  const totalDetailsHidden = items.reduce(
    (sum, item) =>
      sum + (item.type === "agent" ? item.hiddenItems.length : 0),
    0
  );
  const totalLeaksBlocked = items.filter(
    (item) => item.type === "agent" && item.leakStatus === "Blocked Sneaky Leak"
  ).length;

  const handleClear = () => {
    clearHistory();
    setItems([]);
  };

  const handleDownloadProof = (item: HistoryItem) => {
    const proofPayload =
      item.type === "agent"
        ? {
            mode: "Sharing with AI",
            timestamp: item.timestamp,
            prompt: item.prompt,
            hidden_details: item.hiddenItems,
            leak_status: item.leakStatus,
            blocked_destination: item.blockedDestination ?? null,
            deletion_receipt: item.deletionReceipt,
          }
        : {
            mode: "Posting Online",
            timestamp: item.timestamp,
            file_name: item.fileName,
            protections_applied: item.protections,
            owner_id: item.ownerId,
            watermark_id: item.watermarkId,
          };

    const blob = new Blob([JSON.stringify(proofPayload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `trustlens-proof-${item.id}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Summary Bento Card */}
      <section className="rounded-[28px] border-t border-l border-white/25 bg-[#7E77B8] p-6 shadow-[0_18px_40px_rgba(32,27,66,0.35)] sm:p-7">
        <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="flex items-center gap-2 text-lg font-bold text-[#F5F4FF]">
              <FileCheck2 className="h-5 w-5 text-emerald-300" />
              Activity &amp; Proof History
            </h2>
            <p className="mt-1 text-sm text-[#EAE7FD]">
              Saved locally on your device. Raw unredacted photos are never
              stored.
            </p>
          </div>

          <Button
            type="button"
            size="sm"
            onClick={handleClear}
            disabled={items.length === 0}
            className="w-fit rounded-full bg-[#DCD8FA] px-4 font-bold text-[#272248] shadow-md transition-all hover:-translate-y-0.5 hover:bg-white disabled:opacity-50"
          >
            <Trash2 className="mr-1.5 h-3.5 w-3.5" />
            Clear History
          </Button>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <div className="rounded-[22px] border border-white/15 bg-[#332D59] p-4 text-[#F5F4FF] shadow-md">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#C8C3F0]">
                Photos Protected
              </span>
              <ShieldCheck className="h-4 w-4 text-emerald-300" />
            </div>
            <p className="mt-2 text-3xl font-extrabold">{totalPhotosProtected}</p>
          </div>

          <div className="rounded-[22px] border-t border-l border-white/50 bg-[#DCD8FA] p-4 text-[#272248] shadow-md">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-[#473E88]">
                Private Details Hidden
              </span>
              <EyeOff className="h-4 w-4 text-[#473E88]" />
            </div>
            <p className="mt-2 text-3xl font-extrabold">{totalDetailsHidden}</p>
          </div>

          <div className="rounded-[22px] border border-white/15 bg-[#332D59] p-4 text-[#F5F4FF] shadow-md">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#C8C3F0]">
                Leaks Blocked
              </span>
              <ShieldAlert className="h-4 w-4 text-amber-300" />
            </div>
            <p className="mt-2 text-3xl font-extrabold">{totalLeaksBlocked}</p>
          </div>
        </div>
      </section>

      {/* History Entries */}
      {items.length === 0 ? (
        <section className="rounded-[28px] border border-dashed border-white/25 bg-[#332D59]/60 p-10 text-center">
          <p className="text-base font-bold text-[#F5F4FF]">No activity yet</p>
          <p className="mt-1.5 text-sm text-[#D5D1F5]">
            Protect a photo in <span className="font-semibold">Posting Online</span>{" "}
            or ask a question in <span className="font-semibold">Sharing with AI</span>{" "}
            to see your proof cards here.
          </p>
        </section>
      ) : (
        <div className="grid gap-5 md:grid-cols-2">
          {items.map((item) => {
            const isSocial = item.type === "social";

            if (isSocial) {
              return (
                <article
                  key={item.id}
                  className="flex flex-col justify-between gap-4 rounded-[24px] border-t border-l border-white/50 bg-[#DCD8FA] p-5 text-[#272248] shadow-[0_14px_30px_rgba(32,27,66,0.28)]"
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between gap-2">
                      <Badge className="rounded-full bg-[#473E88] px-3 py-1 text-xs font-bold text-white">
                        <Sparkles className="mr-1.5 h-3 w-3" />
                        Posting Online
                      </Badge>
                      <span className="inline-flex items-center gap-1 text-xs font-medium text-[#473E88]">
                        <Clock className="h-3 w-3" />
                        {formatRelativeTime(item.timestamp)}
                      </span>
                    </div>

                    <div className="flex items-start gap-3.5">
                      <img
                        src={item.thumbnail}
                        alt={item.fileName}
                        className="h-16 w-16 shrink-0 rounded-2xl object-cover shadow-sm ring-2 ring-[#473E88]/25"
                      />
                      <div className="min-w-0 space-y-1">
                        <p className="truncate text-sm font-bold text-[#272248]">
                          Protected &ldquo;{item.fileName}&rdquo;
                        </p>
                        <p className="text-xs text-[#272248]/80">
                          Added {item.protections.join(" & ")} for owner{" "}
                          <span className="font-mono font-semibold">
                            {item.ownerId}
                          </span>
                          .
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-1.5">
                      {item.protections.map((prot) => (
                        <span
                          key={prot}
                          className="rounded-full bg-[#C8C3F0] px-2.5 py-0.5 text-[11px] font-semibold text-[#272248]"
                        >
                          {prot}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center justify-between gap-2 border-t border-[#473E88]/15 pt-3">
                    <span className="font-mono text-[11px] font-semibold text-[#473E88]">
                      {item.watermarkId}
                    </span>
                    <Button
                      type="button"
                      size="sm"
                      onClick={() => handleDownloadProof(item)}
                      className="rounded-full bg-[#473E88] px-3.5 text-xs font-bold text-white shadow-sm transition-all hover:-translate-y-0.5 hover:bg-[#3A3274]"
                    >
                      <Download className="mr-1.5 h-3 w-3" />
                      Download Proof
                    </Button>
                  </div>
                </article>
              );
            }

            return (
              <article
                key={item.id}
                className="flex flex-col justify-between gap-4 rounded-[24px] border border-white/15 bg-[#332D59] p-5 text-[#F5F4FF] shadow-[0_14px_30px_rgba(24,20,52,0.38)]"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <Badge className="rounded-full bg-[#DCD8FA] px-3 py-1 text-xs font-bold text-[#272248]">
                      <Bot className="mr-1.5 h-3 w-3" />
                      Sharing with AI
                    </Badge>
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-[#C8C3F0]">
                      <Clock className="h-3 w-3" />
                      {formatRelativeTime(item.timestamp)}
                    </span>
                  </div>

                  <div className="flex items-start gap-3.5">
                    <img
                      src={item.thumbnail}
                      alt="Censored photo thumbnail"
                      className="h-16 w-16 shrink-0 rounded-2xl bg-[#262047] object-cover shadow-sm ring-1 ring-white/20"
                    />
                    <div className="min-w-0 space-y-1">
                      <p className="line-clamp-2 text-sm font-bold text-[#F5F4FF]">
                        Asked: &ldquo;{item.prompt}&rdquo;
                      </p>
                      <p className="text-xs text-[#D5D1F5]">
                        Hid {item.hiddenItems.join(", ")} before sending, then
                        wiped photo from memory.
                      </p>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <span
                      className={`rounded-full px-2.5 py-0.5 text-[11px] font-bold ${
                        item.leakStatus === "Blocked Sneaky Leak"
                          ? "bg-red-500/25 text-red-200 border border-red-300/30"
                          : "bg-emerald-400/20 text-emerald-200 border border-emerald-300/30"
                      }`}
                    >
                      {item.leakStatus}
                    </span>
                    {item.hiddenItems.map((h) => (
                      <span
                        key={h}
                        className="rounded-full bg-[#262047] px-2.5 py-0.5 text-[11px] font-medium text-[#C8C3F0]"
                      >
                        {h}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex items-center justify-between gap-2 border-t border-white/10 pt-3">
                  <span className="font-mono text-[11px] text-[#C8C3F0]">
                    {item.receiptId}
                  </span>
                  <Button
                    type="button"
                    size="sm"
                    onClick={() => handleDownloadProof(item)}
                    className="rounded-full bg-[#DCD8FA] px-3.5 text-xs font-bold text-[#272248] shadow-sm transition-all hover:-translate-y-0.5 hover:bg-white"
                  >
                    <Download className="mr-1.5 h-3 w-3" />
                    Download Proof
                  </Button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}

