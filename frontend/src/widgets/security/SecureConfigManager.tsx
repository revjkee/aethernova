// src/widgets/Security/SecureConfigManager.tsx

import React, { useState, useMemo } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Download, Upload, ShieldCheck, EyeOff, AlertTriangle, Settings2 } from "lucide-react";
import { useSecureConfig } from "@/hooks/security/useSecureConfig";
import { toast } from "@/components/ui/use-toast";
import { validateConfig } from "@/lib/security/configValidator";
import { cn } from "@/lib/utils";

export const SecureConfigManager: React.FC = () => {
  const { configData, saveConfig, restoreBackup, isSaving } = useSecureConfig();
  const [editorContent, setEditorContent] = useState<string>(configData?.raw || "");
  const [activeTab, setActiveTab] = useState<"raw" | "parsed">("raw");

  const validation = useMemo(() => validateConfig(editorContent), [editorContent]);

  const handleSave = () => {
    if (!validation.isValid) {
      toast({
        title: "Ошибка валидации",
        description: "Конфигурация содержит ошибки и не может быть сохранена.",
        variant: "destructive",
      });
      return;
    }
    saveConfig(editorContent);
  };

  const handleRestore = () => {
    const confirmed = confirm("Вы уверены, что хотите восстановить последнюю резервную копию?");
    if (confirmed) {
      restoreBackup();
    }
  };

  return (
    <Card className="w-full border shadow-sm bg-background">
      <CardHeader className="flex flex-col gap-2">
        <CardTitle className="flex items-center gap-2">
          <Settings2 className="h-5 w-5 text-primary" />
          Менеджер Безопасных Конфигураций
        </CardTitle>
        <span className="text-muted-foreground text-sm">
          Управляйте критически важными параметрами системы. Все изменения проходят контроль соответствия, валидацию и логирование.
        </span>
      </CardHeader>

      <CardContent className="pt-0">
        <div className="flex justify-between items-center mb-4">
          <Tabs value={activeTab} onValueChange={(val) => setActiveTab(val as any)}>
            <TabsList>
              <TabsTrigger value="raw">RAW JSON</TabsTrigger>
              <TabsTrigger value="parsed">Обработанное</TabsTrigger>
            </TabsList>
          </Tabs>

          <div className="flex gap-2">
            <Button
              size="sm"
              variant="ghost"
              onClick={handleRestore}
              className="text-destructive hover:text-red-700"
            >
              <EyeOff className="h-4 w-4 mr-1" />
              Восстановить
            </Button>
            <Button size="sm" disabled={!validation.isValid || isSaving} onClick={handleSave}>
              <ShieldCheck className="h-4 w-4 mr-1" />
              Сохранить конфигурацию
            </Button>
          </div>
        </div>

        {activeTab === "raw" && (
          <>
            <Label htmlFor="rawConfig" className="text-xs text-muted-foreground mb-1 block">
              Редактируйте конфигурацию в JSON-формате. Все поля проверяются автоматически.
            </Label>
            <Textarea
              id="rawConfig"
              className={cn(
                "font-mono h-[300px]",
                !validation.isValid && "border-destructive"
              )}
              value={editorContent}
              onChange={(e) => setEditorContent(e.target.value)}
            />
            {!validation.isValid && (
              <div className="mt-2 text-destructive text-sm flex gap-2 items-start">
                <AlertTriangle className="w-4 h-4 mt-0.5" />
                {validation.errors?.[0]?.message || "Ошибка конфигурации"}
              </div>
            )}
          </>
        )}

        {activeTab === "parsed" && (
          <div className="text-sm bg-muted px-4 py-3 rounded-md">
            <pre className="whitespace-pre-wrap">{JSON.stringify(validation.parsed, null, 2)}</pre>
          </div>
        )}

        <div className="mt-4 flex flex-wrap gap-2">
          {validation.tags?.map((tag, idx) => (
            <Badge key={idx} variant="outline" className="text-xs">
              {tag}
            </Badge>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
