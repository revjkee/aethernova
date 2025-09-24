import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { Drawer, DrawerContent, DrawerHeader, DrawerTitle, DrawerClose } from '@/components/ui/drawer';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { useCartStore } from '@/store/cartStore';
import { CartItem } from '@/components/cart/CartItem';
import { CartSummary } from '@/components/cart/CartSummary';
import { ShoppingBag, Loader, X } from 'lucide-react';
import { useWebSocketSync } from '@/hooks/useWebSocketSync';
import { formatCurrency } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useUser } from '@/hooks/useUser';

type ShoppingCartSidebarProps = {
  open: boolean;
  onClose: () => void;
};

export const ShoppingCartSidebar: React.FC<ShoppingCartSidebarProps> = ({ open, onClose }) => {
  const { items, total, isSyncing, syncCart } = useCartStore();
  const { user } = useUser();
  const [loading, setLoading] = useState(false);

  useWebSocketSync({
    topic: user?.id ? `cart/${user.id}` : undefined,
    onMessage: (updatedCart) => {
      if (updatedCart) {
        syncCart(updatedCart);
      }
    },
  });

  const handleCheckout = useCallback(async () => {
    setLoading(true);
    try {
      // Replace with modular payment router (TON/USDT/NFT)
      await new Promise((resolve) => setTimeout(resolve, 2000));
    } catch (error) {
      console.error('Checkout error:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  const hasItems = useMemo(() => items.length > 0, [items]);

  return (
    <Drawer open={open} onOpenChange={onClose}>
      <DrawerContent className="w-full sm:w-[450px] bg-background border-l border-border shadow-xl">
        <DrawerHeader className="flex items-center justify-between p-4 border-b border-muted">
          <div className="flex items-center gap-2">
            <ShoppingBag className="w-5 h-5 text-muted-foreground" />
            <DrawerTitle className="text-lg font-semibold">Корзина</DrawerTitle>
          </div>
          <DrawerClose asChild>
            <Button variant="ghost" size="icon" aria-label="Закрыть">
              <X className="w-5 h-5" />
            </Button>
          </DrawerClose>
        </DrawerHeader>

        <ScrollArea className="h-[calc(100vh-180px)] px-4 pt-2">
          {hasItems ? (
            items.map((item) => <CartItem key={item.id} item={item} />)
          ) : (
            <div className="text-muted-foreground text-sm text-center py-8">Ваша корзина пуста</div>
          )}
        </ScrollArea>

        <div className="p-4 border-t border-border">
          <CartSummary total={total} isSyncing={isSyncing} />

          <Button
            onClick={handleCheckout}
            disabled={!hasItems || loading}
            className={cn('w-full mt-3', loading && 'opacity-70')}
          >
            {loading ? <Loader className="w-4 h-4 mr-2 animate-spin" /> : 'Оформить заказ'}
          </Button>
        </div>
      </DrawerContent>
    </Drawer>
  );
};
