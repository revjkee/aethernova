import React from "react"
import { usePaginationStore } from "@/store/pagination"
import { Button } from "@/shared/components/Button"
import { Input } from "@/shared/components/Input"
import { Select, SelectItem } from "@/shared/components/Select"
import { IconChevronLeft, IconChevronRight, IconChevronsLeft, IconChevronsRight } from "lucide-react"
import { cn } from "@/shared/utils/style"

const MAX_VISIBLE_PAGES = 5

export const MarketplacePagination: React.FC = () => {
  const {
    page,
    totalPages,
    perPage,
    setPage,
    setPerPage
  } = usePaginationStore()

  const renderPageNumbers = () => {
    const start = Math.max(1, page - Math.floor(MAX_VISIBLE_PAGES / 2))
    const end = Math.min(totalPages, start + MAX_VISIBLE_PAGES - 1)
    const pages = []

    for (let i = start; i <= end; i++) {
      pages.push(
        <Button
          key={i}
          size="sm"
          variant={i === page ? "default" : "ghost"}
          onClick={() => setPage(i)}
        >
          {i}
        </Button>
      )
    }

    return pages
  }

  return (
    <div className="w-full flex flex-col xl:flex-row justify-between items-center gap-4 px-2 py-3 border-t border-neutral-800 bg-neutral-900">
      <div className="flex items-center gap-2">
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setPage(1)}
          disabled={page === 1}
        >
          <IconChevronsLeft className="w-4 h-4" />
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setPage(Math.max(1, page - 1))}
          disabled={page === 1}
        >
          <IconChevronLeft className="w-4 h-4" />
        </Button>

        <div className="flex gap-1">
          {renderPageNumbers()}
        </div>

        <Button
          size="sm"
          variant="ghost"
          onClick={() => setPage(Math.min(totalPages, page + 1))}
          disabled={page === totalPages}
        >
          <IconChevronRight className="w-4 h-4" />
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setPage(totalPages)}
          disabled={page === totalPages}
        >
          <IconChevronsRight className="w-4 h-4" />
        </Button>
      </div>

      <div className="flex items-center gap-3">
        <span className="text-sm text-neutral-400">На странице:</span>
        <Select value={perPage.toString()} onValueChange={(v) => setPerPage(parseInt(v))}>
          {[10, 20, 50, 100].map((n) => (
            <SelectItem key={n} value={n.toString()}>{n}</SelectItem>
          ))}
        </Select>

        <span className="text-sm text-neutral-400">/ Всего: {totalPages} стр.</span>
        <Input
          type="number"
          value={page}
          min={1}
          max={totalPages}
          onChange={(e) => {
            const newPage = parseInt(e.target.value)
            if (!isNaN(newPage) && newPage >= 1 && newPage <= totalPages) {
              setPage(newPage)
            }
          }}
          className="w-[60px] text-center text-sm"
        />
      </div>
    </div>
  )
}
