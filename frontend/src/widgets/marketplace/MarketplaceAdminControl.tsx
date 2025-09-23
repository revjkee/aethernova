import React, { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardHeader, CardContent } from '@/components/ui/card'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { useToast } from '@/components/ui/use-toast'
import { MoreHorizontal, Edit2, Archive, EyeOff, Eye, Loader2 } from 'lucide-react'
import { AdminGuard } from '@/components/security/AdminGuard'
import { useCatalogStore } from '@/state/catalogStore'
import { cn } from '@/shared/utils/classNames'
import { ProductCardMini } from '@/components/marketplace/ProductCardMini'
import { ProductStatus, Product } from '@/types/marketplace'
import { formatDate } from '@/shared/utils/formatDate'

const FILTERS: { label: string; value: ProductStatus | 'all' }[] = [
  { label: 'Все', value: 'all' },
  { label: 'Активные', value: 'published' },
  { label: 'В архиве', value: 'archived' },
  { label: 'Черновики', value: 'draft' },
]

export const MarketplaceAdminControl: React.FC = () => {
  const { products, fetchAll, updateProductStatus, loading } = useCatalogStore()
  const [statusFilter, setStatusFilter] = useState<ProductStatus | 'all'>('all')
  const { toast } = useToast()

  useEffect(() => {
    fetchAll()
  }, [])

  const handleStatusUpdate = async (id: string, newStatus: ProductStatus) => {
    try {
      await updateProductStatus(id, newStatus)
      toast({ title: 'Успешно', description: `Статус обновлён: ${newStatus}`, variant: 'success' })
    } catch (e: any) {
      toast({ title: 'Ошибка', description: e.message || 'Не удалось обновить статус', variant: 'destructive' })
    }
  }

  const filteredProducts = products.filter((p) => statusFilter === 'all' || p.status === statusFilter)

  return (
    <AdminGuard>
      <Card className="w-full border bg-background shadow-md">
        <CardHeader className="flex justify-between items-center">
          <div className="text-lg font-semibold">Управление каталогом</div>
          <div className="flex gap-2">
            {FILTERS.map((filter) => (
              <Button
                key={filter.value}
                variant={statusFilter === filter.value ? 'default' : 'outline'}
                size="sm"
                onClick={() => setStatusFilter(filter.value)}
              >
                {filter.label}
              </Button>
            ))}
          </div>
        </CardHeader>

        <CardContent className="pt-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {loading && (
            <div className="col-span-full text-muted-foreground flex items-center justify-center gap-2 py-12">
              <Loader2 className="h-5 w-5 animate-spin" />
              Загрузка товаров...
            </div>
          )}
          {!loading && filteredProducts.length === 0 && (
            <div className="col-span-full text-sm text-center text-muted-foreground py-8">
              Нет товаров по заданному фильтру
            </div>
          )}

          {!loading &&
            filteredProducts.map((product) => (
              <ProductCardMini key={product.id} product={product}>
                <div className="flex justify-between items-center mt-3">
                  <Badge variant="outline" className="text-xs">
                    {product.status}
                  </Badge>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon">
                        <MoreHorizontal className="w-4 h-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem
                        onClick={() => handleStatusUpdate(product.id, 'draft')}
                      >
                        <EyeOff className="w-4 h-4 mr-2" />
                        Перевести в черновик
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => handleStatusUpdate(product.id, 'archived')}
                      >
                        <Archive className="w-4 h-4 mr-2" />
                        Архивировать
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => handleStatusUpdate(product.id, 'published')}
                      >
                        <Eye className="w-4 h-4 mr-2" />
                        Опубликовать
                      </DropdownMenuItem>
                      <DropdownMenuItem disabled>
                        <Edit2 className="w-4 h-4 mr-2" />
                        Редактировать (скоро)
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
                <div className="text-[10px] text-muted-foreground mt-1">
                  Обновлено: {formatDate(product.updatedAt)}
                </div>
              </ProductCardMini>
            ))}
        </CardContent>
      </Card>
    </AdminGuard>
  )
}

export default MarketplaceAdminControl
