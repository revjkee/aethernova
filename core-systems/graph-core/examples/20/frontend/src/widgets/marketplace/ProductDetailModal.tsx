import React, { useEffect } from 'react';
import { Dialog, DialogContent, DialogTitle, DialogDescription, DialogHeader, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Product } from '@/types/marketplace';
import { formatCurrency, formatDate, cn } from '@/lib/utils';
import { useProductStore } from '@/store/productStore';
import { useWallet } from '@/hooks/useWallet';
import { useTokenActions } from '@/hooks/useTokenActions';
import { StarRating } from '@/components/ui/star-rating';
import { ProductImageGallery } from './ProductImageGallery';
import { ProductPropertiesPanel } from './ProductPropertiesPanel';
import { ProductReviewsSection } from './ProductReviewsSection';

type ProductDetailModalProps = {
  open: boolean;
  product: Product | null;
  onClose: () => void;
};

export const ProductDetailModal: React.FC<ProductDetailModalProps> = ({ open, product, onClose }) => {
  const { purchaseProduct } = useProductStore();
  const { isConnected, connectWallet } = useWallet();
  const { mintNFT, tokenizeAsset } = useTokenActions();

  useEffect(() => {
    if (!open) return;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, [open]);

  if (!product) return null;

  const handleBuy = async () => {
    if (!isConnected) {
      await connectWallet();
      return;
    }
    await purchaseProduct(product.id);
  };

  const handleTokenize = async () => {
    await tokenizeAsset(product.id);
  };

  const handleMint = async () => {
    await mintNFT(product.id);
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-5xl h-[90vh] overflow-hidden p-0 flex flex-col">
        <DialogHeader className="px-6 pt-4">
          <DialogTitle>{product.title}</DialogTitle>
          <DialogDescription className="text-sm text-muted-foreground">
            {product.description}
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="flex-1 overflow-y-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 px-6 py-4">
            <ProductImageGallery images={product.images} />
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{product.category}</Badge>
                <Badge variant="default">{product.type}</Badge>
              </div>

              <div className="text-3xl font-bold text-primary">
                {formatCurrency(product.price)} {product.currency}
              </div>

              <div className="text-sm text-muted-foreground">
                Дата добавления: {formatDate(product.createdAt)}
              </div>

              <Separator className="my-2" />

              <ProductPropertiesPanel product={product} />

              <StarRating rating={product.rating} />

              <div className="text-xs text-muted-foreground">
                ID: {product.id}
              </div>
            </div>
          </div>

          <Separator className="my-4" />

          <ProductReviewsSection productId={product.id} />
        </ScrollArea>

        <DialogFooter className="bg-muted px-6 py-4 gap-2 justify-between">
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={handleMint}>
              Выпустить NFT
            </Button>
            <Button variant="outline" onClick={handleTokenize}>
              Токенизировать
            </Button>
          </div>
          <Button onClick={handleBuy} disabled={!isConnected}>
            Купить сейчас
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
