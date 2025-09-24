import React, { useEffect, useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator } from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { DatePicker } from '@/components/ui/date-picker'
import { Clock, BellOff, Plus, Check, XCircle, Settings2 } from 'lucide-react'
import { cn } from '@/shared/utils/classNames'
import { useMuteStore } from '@/state/muteStore'
import { motion, AnimatePresence } from 'framer-motion'
import { format } from 'date-fns'
import { ScrollArea } from '@/components/ui/scroll-area'

type MuteRule = {
  id: string
  source: string
  tag: string
  expiresAt: string
  reason: string
  createdBy: string
}

export const AlertMuteControl: React.FC = () => {
  const { rules, addRule, removeRule, fetchRules } = useMuteStore()
  const [newTag, setNewTag] = useState('')
  const [newSource, setNewSource] = useState('')
  const [reason, setReason] = useState('')
  const [expiresAt, setExpiresAt] = useState<Date | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    fetchRules()
  }, [])

  const handleSave = async () => {
    if (!newTag || !newSource || !expiresAt) return
    setSaving(true)
    await addRule({
      tag: newTag,
      source: newSource,
      reason: reason || 'Без причины',
      expiresAt: expiresAt.toISOString(),
    })
    setNewTag('')
    setNewSource('')
    setReason('')
    setExpiresAt(null)
    setSaving(false)
  }

  const handleRemove = async (id: string) => {
    await removeRule(id)
  }

  const sortedRules = useMemo(
    () => [...rules].sort((a, b) => new Date(a.expiresAt).getTime() - new Date(b.expiresAt).getTime()),
    [rules]
  )

  return (
    <Card className="h-full shadow-md">
      <CardContent className="p-4 flex flex-col gap-4 h-full">
        <div className="flex justify-between items-center mb-2">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <BellOff className="w-5 h-5" />
            Управление приглушением оповещений
          </h2>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="gap-1">
                <Plus className="w-4 h-4" />
                Новое правило
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="w-96">
              <DropdownMenuLabel>Новое правило приглушения</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <div className="p-2 flex flex-col gap-2">
                <Input
                  placeholder="Источник (например: ai-core)"
                  value={newSource}
                  onChange={(e) => setNewSource(e.target.value)}
                />
                <Input
                  placeholder="Тег алерта (например: cpu-usage)"
                  value={newTag}
                  onChange={(e) => setNewTag(e.target.value)}
                />
                <Input
                  placeholder="Причина"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
                <DatePicker
                  value={expiresAt}
                  onChange={setExpiresAt}
                  placeholder="Выберите срок действия"
                />
                <Button onClick={handleSave} disabled={saving || !newTag || !newSource || !expiresAt}>
                  Сохранить
                </Button>
              </div>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <ScrollArea className="h-full border rounded-md p-2">
          <AnimatePresence>
            {sortedRules.length === 0 ? (
              <div className="text-muted-foreground text-sm italic">Нет активных правил</div>
            ) : (
              <ul className="space-y-3">
                {sortedRules.map(rule => (
                  <motion.li
                    key={rule.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="bg-muted p-3 rounded-md border shadow-sm"
                  >
                    <div className="flex justify-between items-start">
                      <div className="flex flex-col gap-1">
                        <span className="text-sm font-semibold">{rule.source}</span>
                        <span className="text-xs text-muted-foreground">
                          Тег: <code className="text-xs font-mono">{rule.tag}</code>
                        </span>
                        <span className="text-xs text-muted-foreground">
                          До: {format(new Date(rule.expiresAt), 'dd.MM.yyyy HH:mm')}
                        </span>
                        <span className="text-xs text-muted-foreground italic">
                          Причина: {rule.reason}
                        </span>
                        <span className="text-[10px] text-muted-foreground">Создал: {rule.createdBy}</span>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-red-500"
                        onClick={() => handleRemove(rule.id)}
                      >
                        <XCircle className="w-4 h-4" />
                      </Button>
                    </div>
                  </motion.li>
                ))}
              </ul>
            )}
          </AnimatePresence>
        </ScrollArea>
      </CardContent>
    </Card>
  )
}

export default AlertMuteControl
