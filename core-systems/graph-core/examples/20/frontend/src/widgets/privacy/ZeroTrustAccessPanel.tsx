import React, { useState, useEffect, useMemo, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Table, TableHeader, TableBody, TableRow, TableCell } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectTrigger, SelectContent, SelectItem } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ShieldCheck, KeyRound, Eye, Edit3, Plus } from "lucide-react";
import { useZeroTrustRules, useUpdateAccessRule, useCreateAccessRule } from "@/hooks/privacy/ztHooks";
import { AccessRule } from "@/types/privacy";
import { toast } from "@/components/ui/use-toast";

export const ZeroTrustAccessPanel: React.FC = () => {
  const { rules, loading, refetch } = useZeroTrustRules();
  const updateRule = useUpdateAccessRule();
  const createRule = useCreateAccessRule();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<AccessRule | null>(null);
  const [filter, setFilter] = useState("");

  const filteredRules = useMemo(() => {
    return filter.length > 1
      ? rules.filter((r) =>
          [r.actor, r.resource, r.context].some((f) => f?.toLowerCase().includes(filter.toLowerCase()))
        )
      : rules;
  }, [rules, filter]);

  const handleSubmit = async (rule: AccessRule) => {
    try {
      if (rule.id) {
        await updateRule(rule.id, rule);
        toast({ title: "Правило обновлено", variant: "success" });
      } else {
        await createRule(rule);
        toast({ title: "Новое правило создано", variant: "success" });
      }
      setDialogOpen(false);
      refetch();
    } catch (err) {
      toast({ title: "Ошибка сохранения", description: String(err), variant: "destructive" });
    }
  };

  return (
    <Card className="w-full h-full">
      <CardHeader className="flex flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-green-600" />
          <CardTitle className="text-lg font-semibold">Zero Trust: Правила доступа</CardTitle>
        </div>
        <div className="flex gap-2">
          <Input
            placeholder="Фильтр по пользователю, ресурсу..."
            className="w-[280px]"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <Plus className="w-4 h-4 mr-2" /> Новое правило
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-xl p-6">
              <AccessRuleForm initial={editingRule} onSubmit={handleSubmit} />
            </DialogContent>
          </Dialog>
        </div>
      </CardHeader>
      <CardContent className="pt-2">
        <ScrollArea className="h-[520px] pr-3">
          <Table>
            <TableHeader>
              <TableRow>
                <TableCell>Актор</TableCell>
                <TableCell>Ресурс</TableCell>
                <TableCell>Контекст</TableCell>
                <TableCell>Политика</TableCell>
                <TableCell>Действия</TableCell>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground text-center">
                    Загрузка...
                  </TableCell>
                </TableRow>
              )}
              {!loading &&
                filteredRules.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell>{rule.actor}</TableCell>
                    <TableCell>{rule.resource}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{rule.context || "—"}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={rule.effect === "allow" ? "success" : "destructive"}
                      >
                        {rule.effect.toUpperCase()}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => {
                          setEditingRule(rule);
                          setDialogOpen(true);
                        }}
                      >
                        <Edit3 className="w-4 h-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

const AccessRuleForm: React.FC<{
  initial?: AccessRule | null;
  onSubmit: (data: AccessRule) => void;
}> = ({ initial, onSubmit }) => {
  const [actor, setActor] = useState(initial?.actor ?? "");
  const [resource, setResource] = useState(initial?.resource ?? "");
  const [context, setContext] = useState(initial?.context ?? "");
  const [effect, setEffect] = useState<"allow" | "deny">(initial?.effect ?? "deny");

  const handleSubmit = () => {
    if (!actor || !resource) return;
    onSubmit({ id: initial?.id, actor, resource, context, effect });
  };

  return (
    <div className="space-y-4">
      <Input label="Актор (user/agent)" value={actor} onChange={(e) => setActor(e.target.value)} />
      <Input label="Ресурс (endpoint/key/module)" value={resource} onChange={(e) => setResource(e.target.value)} />
      <Input label="Контекст (optional)" value={context} onChange={(e) => setContext(e.target.value)} />
      <Select value={effect} onValueChange={(val) => setEffect(val as "allow" | "deny")}>
        <SelectTrigger>
          <span>{effect === "allow" ? "Разрешить" : "Запретить"}</span>
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="allow">Разрешить</SelectItem>
          <SelectItem value="deny">Запретить</SelectItem>
        </SelectContent>
      </Select>
      <Button className="w-full" onClick={handleSubmit}>
        Сохранить
      </Button>
    </div>
  );
};

ZeroTrustAccessPanel.displayName = "ZeroTrustAccessPanel";
