// src/widgets/Security/SignatureAnalysisPanel.tsx

import React, { useState, useEffect, useMemo } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, TerminalSquare, Brain, Activity, Search } from "lucide-react";
import { useSignatureAnalysis } from "@/hooks/security/useSignatureAnalysis";
import { AI_SIGNATURES_SOURCE, BEHAVIOR_FEEDS } from "@/lib/security/constants";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export const SignatureAnalysisPanel: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"ai" | "rules" | "behavior">("ai");
  const [searchQuery, setSearchQuery] = useState("");

  const {
    aiSignatures,
    yaraSignatures,
    behavioralModels,
    fetchSignatures,
    isLoading,
  } = useSignatureAnalysis();

  useEffect(() => {
    fetchSignatures();
  }, []);

  const filteredAI = useMemo(
    () =>
      aiSignatures.filter((sig) =>
        sig.name.toLowerCase().includes(searchQuery.toLowerCase())
      ),
    [searchQuery, aiSignatures]
  );

  const renderSigRow = (sig: any, type: "ai" | "rule" | "behavior", key: number) => (
    <TableRow key={`${type}-${key}`}>
      <TableCell className="font-mono text-sm">{sig.id}</TableCell>
      <TableCell>{sig.name}</TableCell>
      <TableCell>
        <Badge variant="outline" className={cn(
          sig.severity === "high" && "border-red-600 text-red-600",
          sig.severity === "medium" && "border-yellow-600 text-yellow-600",
          sig.severity === "low" && "border-green-600 text-green-600"
        )}>
          {sig.severity}
        </Badge>
      </TableCell>
      <TableCell className="text-muted-foreground text-xs">{sig.source}</TableCell>
      <TableCell className="text-right">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="cursor-help text-muted-foreground text-xs">
              {sig.description.slice(0, 30)}...
            </span>
          </TooltipTrigger>
          <TooltipContent className="max-w-sm">
            {sig.description}
          </TooltipContent>
        </Tooltip>
      </TableCell>
    </TableRow>
  );

  return (
    <Card className="w-full shadow-md bg-background border">
      <CardHeader className="flex flex-col gap-2">
        <CardTitle className="flex items-center gap-2">
          <TerminalSquare className="h-5 w-5 text-primary" />
          Анализ Поведенческих Сигнатур
        </CardTitle>
        <span className="text-muted-foreground text-sm">
          Обнаруживайте сложные угрозы с помощью AI, YARA, Sigma и моделей поведения. Все данные валидируются и логируются.
        </span>
      </CardHeader>

      <CardContent className="pt-2">
        <div className="flex justify-between items-center mb-3">
          <Tabs value={activeTab} onValueChange={(val) => setActiveTab(val as any)}>
            <TabsList>
              <TabsTrigger value="ai">
                <Brain className="h-4 w-4 mr-1" /> AI Сигнатуры
              </TabsTrigger>
              <TabsTrigger value="rules">
                <Search className="h-4 w-4 mr-1" /> YARA / Sigma
              </TabsTrigger>
              <TabsTrigger value="behavior">
                <Activity className="h-4 w-4 mr-1" /> Поведение
              </TabsTrigger>
            </TabsList>
          </Tabs>

          <Input
            className="w-64"
            placeholder="Поиск сигнатур..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <TabsContent value="ai">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Наименование</TableHead>
                <TableHead>Уровень</TableHead>
                <TableHead>Источник</TableHead>
                <TableHead className="text-right">Описание</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAI.map((sig, idx) => renderSigRow(sig, "ai", idx))}
            </TableBody>
          </Table>
        </TabsContent>

        <TabsContent value="rules">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Наименование</TableHead>
                <TableHead>Уровень</TableHead>
                <TableHead>Источник</TableHead>
                <TableHead className="text-right">Описание</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {yaraSignatures.map((sig, idx) => renderSigRow(sig, "rule", idx))}
            </TableBody>
          </Table>
        </TabsContent>

        <TabsContent value="behavior">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Наименование</TableHead>
                <TableHead>Уровень</TableHead>
                <TableHead>Источник</TableHead>
                <TableHead className="text-right">Описание</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {behavioralModels.map((sig, idx) => renderSigRow(sig, "behavior", idx))}
            </TableBody>
          </Table>
        </TabsContent>
      </CardContent>
    </Card>
  );
};
