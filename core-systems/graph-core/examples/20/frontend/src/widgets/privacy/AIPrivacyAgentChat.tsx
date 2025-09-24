import { useState, useEffect, useRef } from "react";
import { Card, CardHeader, CardContent, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { useTranslation } from "react-i18next";
import { sendPrivacyQuery, streamPrivacyResponse } from "@/services/ai/privacyAgentService";
import { Logger } from "@/shared/utils/logger";
import { cn } from "@/shared/utils/classNames";
import { useUserContext } from "@/shared/context/UserContext";
import { trackEvent } from "@/services/analytics/tracker";

interface Message {
  id: string;
  role: "user" | "agent";
  content: string;
}

export const AIPrivacyAgentChat = ({ className }: { className?: string }) => {
  const { t } = useTranslation();
  const { user } = useUserContext();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleSend = async () => {
    const trimmed = input.trim();
    if (!trimmed || streaming) return;

    const userMessage: Message = {
      id: `u-${Date.now()}`,
      role: "user",
      content: trimmed,
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setLoading(true);
    setStreaming(true);

    try {
      const stream = await streamPrivacyResponse(trimmed, user?.id);
      let agentContent = "";
      const agentMessage: Message = {
        id: `a-${Date.now()}`,
        role: "agent",
        content: "",
      };
      setMessages((prev) => [...prev, agentMessage]);

      for await (const token of stream) {
        agentContent += token;
        setMessages((prev) =>
          prev.map((msg) =>
            msg.id === agentMessage.id ? { ...msg, content: agentContent } : msg
          )
        );
        scrollToBottom();
      }

      trackEvent("privacy_chat_asked", {
        question: trimmed,
        userId: user?.id,
      });
    } catch (err) {
      Logger.error("Privacy agent chat failed", err);
      setMessages((prev) => [
        ...prev,
        {
          id: `error-${Date.now()}`,
          role: "agent",
          content: t("privacy_agent.error_generic"),
        },
      ]);
    } finally {
      setLoading(false);
      setStreaming(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  return (
    <Card className={cn("flex flex-col h-full", className)}>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm sm:text-base">{t("privacy_agent.title")}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4 overflow-hidden h-full">
        <ScrollArea className="flex-1 pr-2 space-y-4 overflow-y-auto">
          {messages.length === 0 && (
            <div className="text-xs text-muted-foreground">
              {t("privacy_agent.welcome")}
            </div>
          )}
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={cn(
                "rounded-lg px-3 py-2 text-sm whitespace-pre-wrap",
                msg.role === "user"
                  ? "bg-muted text-right ml-auto max-w-[80%]"
                  : "bg-background text-left mr-auto max-w-[90%] border"
              )}
            >
              {msg.content}
            </div>
          ))}
          {loading && (
            <div className="w-full flex justify-start">
              <Skeleton className="h-4 w-1/2" />
            </div>
          )}
          <div ref={scrollRef} />
        </ScrollArea>

        <div className="flex items-center gap-2 pt-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={t("privacy_agent.input_placeholder")}
            disabled={streaming}
          />
          <Button onClick={handleSend} disabled={streaming || input.trim() === ""}>
            {t("privacy_agent.send")}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};
