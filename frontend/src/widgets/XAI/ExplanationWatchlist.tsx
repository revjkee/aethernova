import React, { useState, useMemo, useEffect } from 'react'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import { AlertTriangle, Eye, ShieldX } from 'lucide-react'
import clsx from 'clsx'

type ExplanationSeverity = 'critical' | 'warning' | 'info'
type ExplanationCategory = 'bias' | 'inconsistency' | 'opacity' | 'non-fairness'

interface WatchItem {
  id: string
  model: string
  severity: ExplanationSeverity
  category: ExplanationCategory
  timestamp: string
  summary: string
  status: 'unverified' | 'flagged' | 'dismissed'
}

interface Props {
  items: WatchItem[]
}

export const ExplanationWatchlist: React.FC<Props> = ({ items }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [search, setSearch] = useState<string>('')

  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      const matchesSeverity = filterSeverity === 'all' || item.severity === filterSeverity
      const matchesSearch = item.summary.toLowerCase().includes(search.toLowerCase())
      return matchesSeverity && matchesSearch
    })
  }, [items, filterSeverity, search])

  const getSeverityBadge = (severity: ExplanationSeverity) => {
    switch (severity) {
      case 'critical':
        return <Badge className="bg-red-600 text-white">Критично</Badge>
      case 'warning':
        return <Badge className="bg-yellow-500 text-white">Предупреждение</Badge>
      case 'info':
      default:
        return <Badge className="bg-gray-300 text-gray-900">Инфо</Badge>
    }
  }

  const getCategoryLabel = (category: ExplanationCategory) => {
    switch (category) {
      case 'bias':
        return 'Смещение'
      case 'inconsistency':
        return 'Непоследовательность'
      case 'opacity':
        return 'Непрозрачность'
      case 'non-fairness':
        return 'Несправедливость'
      default:
        return 'Неизвестно'
    }
  }

  return (
    <div className="w-full p-4 bg-background rounded-lg shadow-sm border">
      <div className="flex justify-between mb-4">
        <h2 className="text-lg font-bold">Монитор XAI-аномалий</h2>
        <div className="flex gap-2">
          <Input
            type="text"
            placeholder="Поиск по объяснению..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-64"
          />
          <Select value={filterSeverity} onValueChange={setFilterSeverity}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Фильтр по важности" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Все</SelectItem>
              <SelectItem value="critical">Критично</SelectItem>
              <SelectItem value="warning">Предупреждение</SelectItem>
              <SelectItem value="info">Инфо</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Модель</TableHead>
            <TableHead>Тип</TableHead>
            <TableHead>Уровень</TableHead>
            <TableHead>Описание</TableHead>
            <TableHead>Время</TableHead>
            <TableHead>Статус</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filteredItems.map((item) => (
            <TableRow key={item.id} className={clsx(item.severity === 'critical' && 'bg-red-50')}>
              <TableCell className="font-medium">{item.model}</TableCell>
              <TableCell>{getCategoryLabel(item.category)}</TableCell>
              <TableCell>{getSeverityBadge(item.severity)}</TableCell>
              <TableCell>{item.summary}</TableCell>
              <TableCell className="text-xs text-muted-foreground">{item.timestamp}</TableCell>
              <TableCell>
                {item.status === 'flagged' && (
                  <Badge variant="destructive" className="flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> Помечено
                  </Badge>
                )}
                {item.status === 'unverified' && (
                  <Badge variant="outline" className="flex items-center gap-1">
                    <Eye className="w-3 h-3" /> Не проверено
                  </Badge>
                )}
                {item.status === 'dismissed' && (
                  <Badge className="bg-muted text-muted-foreground">
                    <ShieldX className="w-3 h-3" /> Игнор
                  </Badge>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {filteredItems.length === 0 && (
        <div className="text-center text-muted-foreground mt-4 text-sm">
          Нет записей, соответствующих критериям.
        </div>
      )}
    </div>
  )
}
