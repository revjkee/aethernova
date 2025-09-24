import React, { useMemo, useState, useEffect } from "react"
import { useMarketplaceFilters } from "@/services/marketplace/useMarketplaceFilters"
import { useFilterStore } from "@/store/filters"
import { Input } from "@/shared/components/Input"
import { Select, SelectItem } from "@/shared/components/Select"
import { MultiSelect } from "@/shared/components/MultiSelect"
import { Button } from "@/shared/components/Button"
import { Checkbox } from "@/shared/components/Checkbox"
import { DateRangePicker } from "@/shared/components/DateRangePicker"
import { IconSearch, IconX, IconChevronDown } from "lucide-react"
import { cn } from "@/shared/utils/style"

export const MarketplaceFilterPanel: React.FC = () => {
  const {
    categories,
    tags,
    sellers,
    aiRecommendedTags,
    loading
  } = useMarketplaceFilters()

  const {
    setSearch,
    setCategory,
    setTags,
    setSortBy,
    setDateRange,
    clearFilters,
    filters
  } = useFilterStore()

  const [localSearch, setLocalSearch] = useState(filters.search || "")

  const debouncedSearch = useMemo(() => {
    const timeout = setTimeout(() => {
      setSearch(localSearch)
    }, 400)
    return () => clearTimeout(timeout)
  }, [localSearch])

  useEffect(() => debouncedSearch, [localSearch])

  return (
    <div className="w-full bg-neutral-900 border border-neutral-700 rounded-xl p-6 flex flex-col gap-5">
      <div className="flex flex-col xl:flex-row gap-4 items-start xl:items-center justify-between">
        <div className="flex gap-3 w-full xl:w-1/2">
          <Input
            value={localSearch}
            onChange={(e) => setLocalSearch(e.target.value)}
            placeholder="Поиск по названию, описанию, AI-тегам"
            prefix={<IconSearch className="w-4 h-4 text-neutral-400" />}
            className="w-full"
          />
          <Button onClick={clearFilters} variant="ghost" size="sm" className="shrink-0 text-neutral-400 hover:text-red-500">
            <IconX className="w-4 h-4" />
          </Button>
        </div>

        <Select
          label="Сортировка"
          value={filters.sortBy}
          onValueChange={setSortBy}
          className="w-full xl:w-[220px]"
        >
          <SelectItem value="relevance">По релевантности</SelectItem>
          <SelectItem value="price_low">Цена: по возрастанию</SelectItem>
          <SelectItem value="price_high">Цена: по убыванию</SelectItem>
          <SelectItem value="newest">Новизна</SelectItem>
          <SelectItem value="rating">Рейтинг</SelectItem>
          <SelectItem value="sales">Популярность</SelectItem>
        </Select>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
        <MultiSelect
          label="Категории"
          items={categories}
          selected={filters.category}
          onChange={setCategory}
        />

        <MultiSelect
          label="Теги"
          items={tags}
          selected={filters.tags}
          onChange={setTags}
        />

        <MultiSelect
          label="AI-рекомендации"
          items={aiRecommendedTags}
          selected={filters.tags}
          onChange={setTags}
          badgeColor="indigo"
        />
      </div>

      <div className="flex flex-wrap gap-4 items-center">
        <DateRangePicker
          label="Дата размещения"
          value={filters.dateRange}
          onChange={setDateRange}
        />

        <Checkbox
          label="Только NFT"
          checked={filters.onlyNFT}
          onCheckedChange={(v) => useFilterStore.setState({ onlyNFT: v })}
        />
        <Checkbox
          label="Скидка > 20%"
          checked={filters.onlyDiscounted}
          onCheckedChange={(v) => useFilterStore.setState({ onlyDiscounted: v })}
        />
        <Checkbox
          label="В наличии"
          checked={filters.onlyInStock}
          onCheckedChange={(v) => useFilterStore.setState({ onlyInStock: v })}
        />
      </div>
    </div>
  )
}
