import React, { useEffect, useState, useMemo } from "react"
import { useFormContext, Controller } from "react-hook-form"
import { Command, CommandInput, CommandItem, CommandList } from "@/shared/components/Command"
import { ScrollArea } from "@/shared/components/ScrollArea"
import { Badge } from "@/shared/components/Badge"
import { useCategoryStore } from "@/store/marketplace/categoryStore"
import { Skeleton } from "@/shared/components/Skeleton"
import { cn } from "@/shared/utils/classNames"
import { Check, ChevronRight } from "lucide-react"

interface Props {
  disabled?: boolean
  className?: string
}

export const ProductCategorySelector: React.FC<Props> = ({ disabled = false, className }) => {
  const {
    categories,
    fetchCategories,
    loading: loadingCategories
  } = useCategoryStore()

  const { control } = useFormContext()

  useEffect(() => {
    fetchCategories()
  }, [fetchCategories])

  const renderCategoryPath = (categoryId: string) => {
    const path: string[] = []
    let current = categories.find(c => c.id === categoryId)
    while (current) {
      path.unshift(current.name)
      current = categories.find(c => c.id === current.parentId)
    }
    return path.join(" / ")
  }

  const structuredOptions = useMemo(() => {
    return categories.filter(c => !c.hidden).sort((a, b) => a.order - b.order)
  }, [categories])

  return (
    <Controller
      name="categoryId"
      control={control}
      render={({ field }) => (
        <div className={cn("flex flex-col gap-2", className)}>
          <label className="text-sm font-medium">Категория</label>

          {loadingCategories ? (
            <Skeleton className="h-10 w-full rounded-md" />
          ) : (
            <Command className="w-full">
              <CommandInput
                disabled={disabled}
                placeholder="Поиск категории..."
                className="h-10"
              />
              <ScrollArea className="h-64 w-full rounded-md border mt-2">
                <CommandList>
                  {structuredOptions.map(category => (
                    <CommandItem
                      key={category.id}
                      value={category.id}
                      onSelect={() => field.onChange(category.id)}
                      className={cn(
                        "flex items-center justify-between px-2 py-1 text-sm",
                        category.id === field.value && "bg-muted/50"
                      )}
                    >
                      <span className="flex items-center gap-1">
                        {category.id === field.value && <Check size={14} />}
                        {renderCategoryPath(category.id)}
                      </span>
                      {category.children?.length > 0 && (
                        <ChevronRight size={14} className="opacity-60" />
                      )}
                    </CommandItem>
                  ))}
                </CommandList>
              </ScrollArea>
            </Command>
          )}

          {field.value && (
            <Badge variant="outline" className="mt-1 max-w-full truncate" title={renderCategoryPath(field.value)}>
              {renderCategoryPath(field.value)}
            </Badge>
          )}
        </div>
      )}
    />
  )
}
