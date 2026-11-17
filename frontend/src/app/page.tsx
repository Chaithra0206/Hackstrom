"use client";

import React, { useState } from "react";

import { HistoryTab } from "@/components/HistoryTab";
import { SafeAgentTab } from "@/components/SafeAgentTab";
import { SocialShieldTab } from "@/components/SocialShieldTab";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function Home() {
  const [activeTab, setActiveTab] = useState<string>("social-shield");

  return (
    <div className="min-h-screen bg-[#595386] text-[#F5F4FF]">
      <div className="mx-auto max-w-6xl px-5 py-7 sm:px-6 sm:py-8">
        <Tabs
          value={activeTab}
          onValueChange={setActiveTab}
          className="space-y-6"
        >
          <div className="flex justify-center sm:justify-start">
            <TabsList className="inline-flex h-auto rounded-full border border-white/20 bg-[#332D59] p-1.5 shadow-md">
              <TabsTrigger
                value="social-shield"
                className="rounded-full px-5 py-2 text-sm font-bold text-[#C8C3F0] transition-all data-active:bg-[#DCD8FA] data-active:text-[#272248] data-active:shadow-sm"
              >
                Posting Online
              </TabsTrigger>
              <TabsTrigger
                value="safe-agent"
                className="rounded-full px-5 py-2 text-sm font-bold text-[#C8C3F0] transition-all data-active:bg-[#DCD8FA] data-active:text-[#272248] data-active:shadow-sm"
              >
                Sharing with AI
              </TabsTrigger>
              <TabsTrigger
                value="history"
                className="rounded-full px-5 py-2 text-sm font-bold text-[#C8C3F0] transition-all data-active:bg-[#DCD8FA] data-active:text-[#272248] data-active:shadow-sm"
              >
                History
              </TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value="social-shield">
            <SocialShieldTab />
          </TabsContent>

          <TabsContent value="safe-agent">
            <SafeAgentTab />
          </TabsContent>

          <TabsContent value="history">
            <HistoryTab />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
