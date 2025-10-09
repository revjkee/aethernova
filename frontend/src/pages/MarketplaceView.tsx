import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search,
  SlidersHorizontal,
  X,
  Star,
  Heart,
  ShoppingCart,
  Filter,
  RefreshCw,
  AlertCircle,
  Check,
} from "lucide-react";

// shadcn/ui components (common project convention: "@/components/ui/*")
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";

// -----------------------------
// Types
// -----------------------------

type MarketplaceItem = {
  id: string;
  title: string;
  description?: string;
  imageUrl: string;
  priceCents: number; // integer minor units for precision
  currency: string; // e.g., "USD", "EUR"
  rating?: number; // 0..5
  ratingCount?: number;
  tags?: string[];
  badge?: "new" | "hot" | "sale" | "limited";
  inStock: boolean;
};

type ApiResponse = {
  items: MarketplaceItem[];
  total: number;
  page: number; // 1-based
  pageSize: number;
};

// -----------------------------
// Utilities
// -----------------------------

const DEFAULT_PAGE_SIZE = 12;
const MAX_PRICE_LIMIT = 10_000_00; // 10000.00 in cents

const formatPrice = (cents: number, currency: string) => {
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency }).format(cents / 100);
  } catch {
    // Fallback in case unsupported currency code
    return `${(cents / 100).toFixed(2)} ${currency}`;
  }
};

const debounce = <T extends (...args: any[]) => void>(fn: T, delay = 300) => {
  let timer: ReturnType<typeof setTimeout> | null = null;
  return (...args: Parameters<T>) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
};

const buildQueryString = (params: Record<string, string | number | boolean | undefined>) => {
  const sp = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v === undefined || v === null || v === "") return;
    sp.set(k, String(v));
  });
  return sp.toString();
};

// Simple robust fetch with AbortController, timeout and JSON guard
async function fetchJSON<T>(input: RequestInfo, init?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), init?.timeoutMs ?? 10_000);
  try {
    const res = await fetch(input, { ...init, signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as T;
    return data;
  } finally {
    clearTimeout(id);
  }
}

// Mock fallback (ensures page works without backend). Disabled automatically if API returns data.
const MOCK_DATA: ApiResponse = {
  items: Array.from({ length: 24 }).map((_, i) => ({
    id: `mock-${i + 1}`,
    title: `Demo Product ${i + 1}`,
    description: "High-quality demo item for testing UI flows.",
    imageUrl: `https://picsum.photos/seed/market-${i}/600/400`,
    priceCents: 1999 + i * 137,
    currency: "EUR",
    rating: Math.round(((i % 5) + 1) * 10) / 10,
    ratingCount: 10 + i * 3,
    tags: i % 2 === 0 ? ["digital", "ai"] : ["creator"],
    badge: (i % 4 === 0 ? "new" : i % 4 === 1 ? "hot" : i % 4 === 2 ? "sale" : "limited"),
    inStock: i % 7 !== 0,
  })),
  total: 24,
  page: 1,
  pageSize: 12,
};

// -----------------------------
// Hooks
// -----------------------------

function useDebouncedValue<T>(value: T, delay = 400) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

function useURLState() {
  const [searchParams, setSearchParams] = useSearchParams();

  const state = useMemo(() => {
    const q = searchParams.get("q") ?? "";
    const page = Math.max(1, Number(searchParams.get("page") ?? 1));
    const sort = searchParams.get("sort") ?? "relevance"; // relevance | price_asc | price_desc | rating_desc | newest
    const min = Number(searchParams.get("min") ?? 0);
    const max = Number(searchParams.get("max") ?? MAX_PRICE_LIMIT);
    const tags = (searchParams.get("tags") ?? "").split(",").filter(Boolean);
    return { q, page, sort, min, max, tags };
  }, [searchParams]);

  const update = useCallback(
    (patch: Partial<typeof state>, replace = false) => {
      const next = { ...state, ...patch };
      // Normalize bounds
      const min = Math.max(0, Math.min(next.min ?? 0, MAX_PRICE_LIMIT));
      const max = Math.max(min, Math.min(next.max ?? MAX_PRICE_LIMIT, MAX_PRICE_LIMIT));
      const qs = buildQueryString({
        q: next.q || undefined,
        page: next.page,
        sort: next.sort,
        min,
        max,
        tags: next.tags && next.tags.length ? next.tags.join(",") : undefined,
      });
      setSearchParams(qs, { replace });
    },
    [setSearchParams, state]
  );

  return [state, update] as const;
}

// -----------------------------
// Data Client
// -----------------------------

async function loadItems(opts: {
  q: string;
  page: number;
  pageSize: number;
  sort: string;
  min: number;
  max: number;
  tags: string[];
}): Promise<ApiResponse> {
  const { q, page, pageSize, sort, min, max, tags } = opts;
  const qs = buildQueryString({ q, page, pageSize, sort, min, max, tags: tags.join(",") });

  try {
    // Replace "/api/marketplace/items" with your backend endpoint
    const data = await fetchJSON<ApiResponse>(`/api/marketplace/items?${qs}`, { timeoutMs: 12_000 });
    // Guard: ensure shape
    if (!Array.isArray(data.items)) throw new Error("Invalid payload");
    return data;
  } catch (err) {
    // Fallback to mock for local development or if backend is unavailable
    const start = (page - 1) * pageSize;
    const sliced = MOCK_DATA.items
      .filter((it) => (q ? it.title.toLowerCase().includes(q.toLowerCase()) : true))
      .filter((it) => it.priceCents >= min && it.priceCents <= max)
      .filter((it) => (tags.length ? tags.every((t) => it.tags?.includes(t)) : true));

    const sorted = [...sliced].sort((a, b) => {
      switch (sort) {
        case "price_asc":
          return a.priceCents - b.priceCents;
        case "price_desc":
          return b.priceCents - a.priceCents;
        case "rating_desc":
          return (b.rating ?? 0) - (a.rating ?? 0);
        case "newest":
          return a.id < b.id ? 1 : -1; // mock heuristic
        default:
          return 0;
      }
    });

    const pageItems = sorted.slice(start, start + pageSize);
    return {
      items: pageItems,
      total: sorted.length,
      page,
      pageSize,
    };
  }
}

// -----------------------------
// UI: Building Blocks
// -----------------------------

const RatingStars: React.FC<{ value?: number; count?: number }> = ({ value = 0, count = 0 }) => {
  const v = Math.max(0, Math.min(5, value));
  return (
    <div className="flex items-center gap-1" aria-label={`Rating ${v} out of 5 from ${count} reviews`}>
      {Array.from({ length: 5 }).map((_, i) => (
        <Star key={i} className={`h-4 w-4 ${i < Math.round(v) ? "fill-current" : ""}`} aria-hidden />
      ))}
      <span className="ml-1 text-xs text-muted-foreground">{count}</span>
    </div>
  );
};

const StockBadge: React.FC<{ inStock: boolean }> = ({ inStock }) => (
  <Badge variant={inStock ? "default" : "secondary"} className={inStock ? "bg-green-600 hover:bg-green-600" : "opacity-70"}>
    {inStock ? "In stock" : "Out of stock"}
  </Badge>
);

const ItemBadge: React.FC<{ badge?: MarketplaceItem["badge"] }> = ({ badge }) => {
  if (!badge) return null;
  const map: Record<string, string> = {
    new: "bg-blue-600",
    hot: "bg-red-600",
    sale: "bg-pink-600",
    limited: "bg-amber-600",
  };
  return (
    <Badge className={`${map[badge]} text-white`}>{badge.toUpperCase()}</Badge>
  );
};

const ProductCard: React.FC<{
  item: MarketplaceItem;
  onAddToCart: (id: string) => void;
  onWishlist: (id: string) => void;
}> = ({ item, onAddToCart, onWishlist }) => {
  return (
    <motion.div layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
      <Card className="group overflow-hidden rounded-2xl border-muted/60 shadow-sm transition hover:shadow-lg">
        <CardHeader className="p-0">
          <div className="relative aspect-[4/3] w-full overflow-hidden">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={item.imageUrl}
              alt={item.title}
              className="h-full w-full object-cover transition-transform duration-300 group-hover:scale-105"
              loading="lazy"
            />
            <div className="absolute left-3 top-3 flex gap-2">
              <ItemBadge badge={item.badge} />
              <StockBadge inStock={item.inStock} />
            </div>
            <div className="pointer-events-none absolute inset-0 bg-gradient-to-t from-background/40 via-transparent to-transparent" />
          </div>
        </CardHeader>
        <CardContent className="space-y-2 p-4">
          <CardTitle className="line-clamp-1 text-base font-semibold">{item.title}</CardTitle>
          <div className="flex items-center justify-between gap-3">
            <div className="font-semibold">{formatPrice(item.priceCents, item.currency)}</div>
            <RatingStars value={item.rating} count={item.ratingCount} />
          </div>
          {item.tags?.length ? (
            <div className="mt-1 flex flex-wrap gap-1">
              {item.tags.slice(0, 3).map((t) => (
                <Badge key={t} variant="secondary" className="rounded-full text-xs">{t}</Badge>
              ))}
            </div>
          ) : null}
        </CardContent>
        <CardFooter className="flex items-center justify-between gap-2 p-4 pt-0">
          <TooltipProvider>
            <div className="flex items-center gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button size="sm" variant="outline" className="rounded-full" onClick={() => onAddToCart(item.id)} aria-label="Add to cart">
                    <ShoppingCart className="mr-2 h-4 w-4" /> Add
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Add to cart</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button size="icon" variant="ghost" className="rounded-full" onClick={() => onWishlist(item.id)} aria-label="Add to wishlist">
                    <Heart className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Add to wishlist</TooltipContent>
              </Tooltip>
            </div>
          </TooltipProvider>
        </CardFooter>
      </Card>
    </motion.div>
  );
};

const ProductCardSkeleton: React.FC = () => (
  <Card className="overflow-hidden rounded-2xl">
    <Skeleton className="aspect-[4/3] w-full" />
    <CardContent className="space-y-3 p-4">
      <Skeleton className="h-5 w-3/4" />
      <div className="flex items-center justify-between">
        <Skeleton className="h-5 w-20" />
        <Skeleton className="h-4 w-24" />
      </div>
      <div className="flex gap-2">
        <Skeleton className="h-5 w-12" />
        <Skeleton className="h-5 w-10" />
        <Skeleton className="h-5 w-16" />
      </div>
    </CardContent>
    <CardFooter className="p-4 pt-0">
      <Skeleton className="h-9 w-24" />
      <Skeleton className="ml-2 h-9 w-9" />
    </CardFooter>
  </Card>
);

// -----------------------------
// Filters Bar
// -----------------------------

const ALL_TAGS = ["ai", "digital", "creator", "video", "nft", "education", "analytics"] as const;

const FiltersBar: React.FC<{
  q: string;
  sort: string;
  min: number;
  max: number;
  tags: string[];
  onChange: (patch: Partial<{ q: string; sort: string; min: number; max: number; tags: string[] }>) => void;
  onReset: () => void;
}> = ({ q, sort, min, max, tags, onChange, onReset }) => {
  const [search, setSearch] = useState(q);
  const debouncedSearch = useDebouncedValue(search, 500);

  useEffect(() => {
    onChange({ q: debouncedSearch, /* page reset happens in parent */ });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch]);

  useEffect(() => setSearch(q), [q]);

  const toggleTag = (t: string) => {
    const set = new Set(tags);
    set.has(t) ? set.delete(t) : set.add(t);
    onChange({ tags: Array.from(set) });
  };

  return (
    <div className="w-full rounded-2xl border bg-card p-4 shadow-sm">
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div className="flex w-full flex-col gap-3 md:max-w-xl">
          <Label htmlFor="search" className="sr-only">Search</Label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              id="search"
              placeholder="Search items..."
              className="pl-9"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            {search && (
              <button
                aria-label="Clear"
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:bg-muted"
                onClick={() => setSearch("")}
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label>Price range</Label>
              <div className="flex items-center gap-3">
                <Slider
                  min={0}
                  max={MAX_PRICE_LIMIT}
                  step={50}
                  value={[min, max]}
                  onValueChange={([lo, hi]) => onChange({ min: lo, max: hi })}
                />
              </div>
              <div className="mt-1 text-sm text-muted-foreground">
                {formatPrice(min, "EUR")} – {formatPrice(max, "EUR")}
              </div>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>Sort</Label>
              <Select value={sort} onValueChange={(v) => onChange({ sort: v })}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Sort by" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="relevance">Relevance</SelectItem>
                  <SelectItem value="newest">Newest</SelectItem>
                  <SelectItem value="price_asc">Price: Low to High</SelectItem>
                  <SelectItem value="price_desc">Price: High to Low</SelectItem>
                  <SelectItem value="rating_desc">Rating: High to Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        <div className="flex w-full flex-col gap-2 md:max-w-sm">
          <div className="flex items-center gap-2 text-sm font-medium">
            <Filter className="h-4 w-4" /> Tags
          </div>
          <div className="flex flex-wrap gap-2">
            {ALL_TAGS.map((t) => (
              <Button
                key={t}
                type="button"
                variant={tags.includes(t) ? "default" : "outline"}
                className="h-8 rounded-full px-3"
                onClick={() => toggleTag(t)}
                aria-pressed={tags.includes(t)}
              >
                {tags.includes(t) ? <Check className="mr-1 h-3.5 w-3.5" /> : null}
                {t}
              </Button>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={onReset}>
              <RefreshCw className="mr-2 h-4 w-4" /> Reset
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

// -----------------------------
// Pagination
// -----------------------------

const Pagination: React.FC<{
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}> = ({ page, pageSize, total, onPage }) => {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const canPrev = page > 1;
  const canNext = page < totalPages;

  const move = (delta: number) => {
    const next = Math.min(totalPages, Math.max(1, page + delta));
    if (next !== page) onPage(next);
  };

  return (
    <div className="mt-4 flex items-center justify-between">
      <div className="text-sm text-muted-foreground">
        Page {page} of {totalPages} • {total} items
      </div>
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" onClick={() => move(-1)} disabled={!canPrev} aria-label="Previous page">
          Prev
        </Button>
        <Button variant="outline" size="sm" onClick={() => move(1)} disabled={!canNext} aria-label="Next page">
          Next
        </Button>
      </div>
    </div>
  );
};

// -----------------------------
// Main Page
// -----------------------------

const gridVariants = {
  show: { transition: { staggerChildren: 0.04 } },
};

export default function MarketplaceView() {
  const [urlState, updateURL] = useURLState();
  const { q, page, sort, min, max, tags } = urlState;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<ApiResponse | null>(null);
  const [pageSize] = useState(DEFAULT_PAGE_SIZE);

  const mounted = useRef(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await loadItems({ q, page, pageSize, sort, min, max, tags });
      setData(res);
    } catch (e: any) {
      setError(e?.message ?? "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [q, page, pageSize, sort, min, max, tags]);

  // Load on mount & whenever the URL state changes
  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, page, sort, min, max, tags]);

  // Reset page to 1 on search/sort/filters change (but not on initial mount)
  const setFilters = (patch: Partial<typeof urlState>) => {
    const keysExceptPage = ["q", "sort", "min", "max", "tags"] as const;
    const affectPaging = keysExceptPage.some((k) => k in patch);
    updateURL({ ...patch, page: affectPaging ? 1 : urlState.page });
  };

  const handleAddToCart = (id: string) => {
    // Placeholder integration point: dispatch to cart store or call API
    console.debug("add-to-cart", id);
  };

  const handleWishlist = (id: string) => {
    // Placeholder integration point: dispatch to wishlist store or call API
    console.debug("wishlist", id);
  };

  const total = data?.total ?? 0;
  const items = data?.items ?? [];

  return (
    <div className="mx-auto max-w-7xl px-3 py-6 md:px-6">
      <div className="mb-4 flex items-center gap-2">
        <SlidersHorizontal className="h-5 w-5" />
        <h1 className="text-xl font-semibold tracking-tight md:text-2xl">Marketplace</h1>
      </div>

      <FiltersBar
        q={q}
        sort={sort}
        min={min}
        max={max}
        tags={tags}
        onChange={(patch) => setFilters(patch)}
        onReset={() => updateURL({ q: "", sort: "relevance", min: 0, max: MAX_PRICE_LIMIT, tags: [], page: 1 })}
      />

      <Separator className="my-4" />

      {/* Content */}
      {error ? (
        <div className="flex items-start gap-3 rounded-2xl border border-destructive/40 bg-destructive/5 p-4 text-destructive">
          <AlertCircle className="mt-0.5 h-4 w-4" />
          <div>
            <div className="font-medium">Failed to load items</div>
            <div className="text-sm opacity-80">{error}</div>
            <div className="mt-2">
              <Button size="sm" onClick={refresh}>
                Retry
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      <div aria-busy={loading} aria-live="polite" className="min-h-[200px]">
        {loading ? (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4">
            {Array.from({ length: DEFAULT_PAGE_SIZE }).map((_, i) => (
              <ProductCardSkeleton key={i} />
            ))}
          </div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-2xl border bg-card p-10 text-center">
            <Search className="mb-2 h-6 w-6" />
            <div className="text-lg font-medium">No items found</div>
            <div className="text-sm text-muted-foreground">
              Try adjusting your filters or search query.
            </div>
            <Button className="mt-4" variant="outline" onClick={() => updateURL({ q: "", tags: [], min: 0, max: MAX_PRICE_LIMIT, page: 1 })}>
              Clear filters
            </Button>
          </div>
        ) : (
          <>
            <motion.div
              layout
              variants={gridVariants}
              initial="hidden"
              animate="show"
              className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4"
            >
              <AnimatePresence>
                {items.map((it) => (
                  <ProductCard key={it.id} item={it} onAddToCart={handleAddToCart} onWishlist={handleWishlist} />)
                )}
              </AnimatePresence>
            </motion.div>
            <Pagination page={page} pageSize={pageSize} total={total} onPage={(p) => updateURL({ page: p })} />
          </>
        )}
      </div>
    </div>
  );
}
