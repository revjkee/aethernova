import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Search, XCircle } from 'lucide-react'
import { useDebouncedCallback } from 'use-debounce'
import { cn } from '@/shared/utils/classNames'
import { useMarketplaceStore } from '@/state/marketplaceStore'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'

type SearchResult = {
  id: string
  name: string
  tags: string[]
  type: string
}

export const MarketplaceSearchBar: React.FC = () => {
  const [query, setQuery] = useState('')
  const [focusedIndex, setFocusedIndex] = useState(0)
  const [isOpen, setIsOpen] = useState(false)
  const { results, fetchResults, clearResults } = useMarketplaceStore()
  const containerRef = useRef<HTMLDivElement | null>(null)

  const debouncedSearch = useDebouncedCallback((q: string) => {
    if (q.trim().length > 1) {
      fetchResults(q.trim())
      setIsOpen(true)
    } else {
      clearResults()
      setIsOpen(false)
    }
  }, 300)

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value
    setQuery(val)
    debouncedSearch(val)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!isOpen || results.length === 0) return

    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setFocusedIndex((prev) => Math.min(prev + 1, results.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setFocusedIndex((prev) => Math.max(prev - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const selected = results[focusedIndex]
      if (selected) {
        handleSelect(selected)
      }
    } else if (e.key === 'Escape') {
      setIsOpen(false)
    }
  }

  const handleSelect = (item: SearchResult) => {
    // Открыть товар / перейти к карточке
    console.log('Выбрано:', item)
    setIsOpen(false)
    setQuery(item.name)
    clearResults()
  }

  const handleClear = () => {
    setQuery('')
    clearResults()
    setIsOpen(false)
  }

  const highlightMatch = (text: string): React.ReactNode => {
    const lower = query.toLowerCase()
    if (!lower) return text

    const index = text.toLowerCase().indexOf(lower)
    if (index === -1) return text

    return (
      <>
        {text.slice(0, index)}
        <mark className="bg-yellow-200">{text.slice(index, index + query.length)}</mark>
        {text.slice(index + query.length)}
      </>
    )
  }

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [])

  return (
    <div className="relative w-full" ref={containerRef}>
      <div className="flex gap-2">
        <Input
          type="search"
          placeholder="Поиск по названию, ID, тегам..."
          className="w-full"
          value={query}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          aria-label="Marketplace Search"
          role="combobox"
          aria-expanded={isOpen}
          aria-controls="marketplace-results"
        />
        {query && (
          <Button
            size="icon"
            variant="ghost"
            onClick={handleClear}
            aria-label="Очистить поиск"
          >
            <XCircle className="w-4 h-4 text-muted-foreground" />
          </Button>
        )}
        <Button size="icon" variant="outline" disabled>
          <Search className="w-4 h-4" />
        </Button>
      </div>

      {isOpen && results.length > 0 && (
        <ScrollArea className="absolute z-50 mt-2 w-full max-h-64 border rounded-md bg-popover shadow-lg" id="marketplace-results">
          <ul role="listbox" className="divide-y divide-border">
            {results.map((item, index) => (
              <li
                key={item.id}
                role="option"
                aria-selected={index === focusedIndex}
                className={cn(
                  'p-3 cursor-pointer hover:bg-accent flex flex-col gap-1',
                  index === focusedIndex && 'bg-accent/60'
                )}
                onClick={() => handleSelect(item)}
              >
                <span className="font-medium text-sm">
                  {highlightMatch(item.name)} <span className="text-xs text-muted-foreground">({item.id})</span>
                </span>
                <div className="flex gap-2 flex-wrap text-xs">
                  <Badge variant="outline">{item.type}</Badge>
                  {item.tags.slice(0, 3).map(tag => (
                    <Badge key={tag} variant="secondary">{highlightMatch(tag)}</Badge>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </ScrollArea>
      )}
    </div>
  )
}

export default MarketplaceSearchBar
