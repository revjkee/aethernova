import { FC, useEffect, useRef, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermission } from "@/shared/hooks/usePermission";
import { Role } from "@/shared/constants/roles";
import { useHRComments } from "@/features/hr-core/hooks/useHRComments";
import { useXAIToxicityFilter } from "@/features/xai/hooks/useXAIToxicityFilter";
import { AlertTriangleIcon, SendHorizonalIcon, Loader2Icon, DownloadIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import html2canvas from "html2canvas";
import { saveAs } from "file-saver";

interface Props {
  candidateId: string;
  compact?: boolean;
  readonly?: boolean;
}

export const HRReviewCommentBox: FC<Props> = ({ candidateId, compact = false, readonly = false }) => {
  const { can } = usePermission();
  const {
    comments,
    loading,
    sendComment,
    refetch,
    exporting,
    exportAllComments
  } = useHRComments(candidateId);
  const [input, setInput] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const { toxic, checkToxic } = useXAIToxicityFilter();
  const containerRef = useRef<HTMLDivElement | null>(null);

  const handleSubmit = async () => {
    if (!input.trim()) return;
    setSubmitting(true);
    const isToxic = await checkToxic(input);
    if (isToxic) {
      setSubmitting(false);
      return;
    }
    await sendComment(input);
    setInput("");
    setSubmitting(false);
  };

  const handleExport = async () => {
    if (!containerRef.current) return;
    const canvas = await html2canvas(containerRef.current);
    canvas.toBlob(blob => {
      if (blob) saveAs(blob, `hr_comments_${candidateId}.png`);
    });
  };

  useEffect(() => {
    const timer = setInterval(() => refetch(), 15000);
    return () => clearInterval(timer);
  }, [refetch]);

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-48 mb-2" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[100px] w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card ref={containerRef} className={cn("transition-shadow hover:shadow-md", compact && "max-w-2xl")}>
      <CardHeader className="flex flex-col md:flex-row justify-between md:items-center">
        <div>
          <CardTitle className="text-xl">Комментарии HR</CardTitle>
          <p className="text-sm text-muted-foreground">Обратная связь и аналитика от команды подбора</p>
        </div>
        <div className="flex gap-2 mt-4 md:mt-0">
          {can(Role.SUPERVISOR) && (
            <Button size="sm" variant="outline" onClick={handleExport} disabled={exporting}>
              <DownloadIcon className="w-4 h-4 mr-2" />
              Экспорт PNG
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="space-y-3 max-h-[240px] overflow-y-auto pr-2">
          {comments.length === 0 ? (
            <p className="text-sm text-muted-foreground">Комментариев пока нет.</p>
          ) : (
            comments.map((c, idx) => (
              <div
                key={c.id || idx}
                className={cn("p-3 border rounded-md", c.role === "SUPERVISOR" ? "border-green-500" : "border-muted")}
              >
                <div className="flex justify-between items-center">
                  <div className="text-sm font-medium">
                    {c.authorName} <Badge variant="outline">{c.role}</Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {new Date(c.createdAt).toLocaleString()}
                  </div>
                </div>
                <p className="text-sm mt-1 whitespace-pre-wrap">{c.text}</p>
              </div>
            ))
          )}
        </div>

        {!readonly && (
          <>
            <Textarea
              placeholder="Написать комментарий..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              rows={3}
              className="resize-none"
            />
            {toxic && (
              <div className="flex items-center gap-2 text-red-600 text-sm mt-2">
                <AlertTriangleIcon className="w-4 h-4" />
                Обнаружена токсичность — сообщение заблокировано AI-фильтром.
              </div>
            )}
            <div className="flex justify-end mt-2">
              <Button
                onClick={handleSubmit}
                disabled={!input.trim() || submitting}
                className="gap-2"
              >
                {submitting ? (
                  <>
                    <Loader2Icon className="w-4 h-4 animate-spin" />
                    Отправка...
                  </>
                ) : (
                  <>
                    <SendHorizonalIcon className="w-4 h-4" />
                    Отправить
                  </>
                )}
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};
