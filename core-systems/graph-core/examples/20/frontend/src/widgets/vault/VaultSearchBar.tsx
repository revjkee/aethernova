import { useState, useEffect, useCallback, useRef, memo } from "react"
import { Input } from "@/shared/components/Input"
import { debounce } from "@/shared/utils/debounce"
import { useVaultSearchStore } from "@/state/vaultSearch"
import { VaultSearchResults } from "./VaultSearchResults"
import { useOutsideClick } from "@/shared/hooks/useOutsideClick"
import { Spinner } from "@/shared/components/Spinner"
import { trackEvent } from "@/shared/utils/telemetry"
import { IconSearch, IconClose } from "@/shared/assets/icons"
import clsx from "clsx"

interface VaultSearchBarProps {
  placeholder?: string
  autoFocus?: boolean
}

const SEARCH_DELAY = 300

export const VaultSearchBar = memo(({ placeholder = "Поиск по ключу, ID, тегу...", autoFocus = false }: VaultSearchBarProps) => {
  const [input, setInput] = useState("")
  const [loading, setLoading] = useState(false)
  const [focused, setFocused] = useState(false)
  const inputRef = useRef<HTMLInputElement | null>(null)
  const containerRef = useRef<HTMLDivElement | null>(null)
  const { results, setResults, clearResults, searchVault } = useVaultSearchStore()

  const debouncedSearch = useCallback(
    debounce(async (query: string) => {
      if (!query.trim()) {
        clearResults()
        setLoading(false)
        return
      }
      setLoading(true)
      try {
        const data = await searchVault(query)
        setResults(data)
        trackEvent("vault_search_success", { query, resultsCount: data.length })
      } catch (error) {
        trackEvent("vault_search_error", { query, error: String(error) })
      } finally {
        setLoading(false)
      }
    }, SEARCH_DELAY),
    []
  )

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    setInput(value)
    debouncedSearch(value)
  }

  const handleClear = () => {
    setInput("")
    clearResults()
    inputRef.current?.focus()
  }

  const handleFocus = () => setFocused(true)

  useOutsideClick(containerRef, () => setFocused(false))

  useEffect(() => {
    if (autoFocus) inputRef.current?.focus()
  }, [autoFocus])

  return (
    <div ref={containerRef} className="relative w-full max-w-3xl mx-auto">
      <div className={clsx("flex items-center bg-white dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-700 rounded-xl shadow-sm px-4 py-2", focused && "ring-2 ring-blue-500")}>
        <IconSearch className="w-5 h-5 text-neutral-400" />
        <Input
          ref={inputRef}
          type="text"
          value={input}
          onChange={handleInputChange}
          onFocus={handleFocus}
          placeholder={placeholder}
          className="flex-1 bg-transparent text-base px-2 outline-none"
          autoComplete="off"
        />
        {loading && <Spinner size="sm" className="ml-2" />}
        {input && !loading && (
          <button onClick={handleClear} className="ml-2 text-neutral-400 hover:text-neutral-600">
            <IconClose className="w-4 h-4" />
          </button>
        )}
      </div>
      {focused && results.length > 0 && (
        <div className="absolute z-50 mt-1 w-full bg-white dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-700 rounded-lg shadow-lg overflow-hidden">
          <VaultSearchResults results={results} />
        </div>
      )}
    </div>
  )
})
