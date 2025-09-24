// path: src/pages/MarketplaceView.tsx

import { useEffect, useMemo, useState, Suspense } from "react";
import { useWebAppTheme } from "@/shared/telegram/useWebAppTheme";
import { useProductQuery } from "@/features/product/productAPI";
import { ProductCard } from "@/features/product/ProductCard";
import { FilterPanel } from "@/features/product/FilterPanel";
import { Loader } from "@/shared/components/Spinner";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { TonPayButton } from "@/features/payment/TonPayButton";
import { formatPrice } from "@/shared/utils/formatPrice";
import { Modal } from "@/shared/components/Modal";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";
import { AnimatePresence, motion } from "framer-motion";
import { Helmet } from "react-helmet";

type FilterParams = {
  category: string;
  priceRange: [number, number];
  inStockOnly: boolean;
};

const MarketplaceView = () => {
  const { theme } = useWebAppTheme();
  const { isAuthenticated } = useAuth();

  const [filters, setFilters] = useState<FilterParams>({
    category: "all",
    priceRange: [0, 10000],
    inStockOnly: false,
  });

  const debouncedFilters = useDebounce(filters, 300);
  const { data: products, isLoading } = useProductQuery(debouncedFilters);

  const [selectedProduct, setSelectedProduct] = useState<null | Product | undefined>(undefined);
  const [modalOpen, setModalOpen] = useState(false);

  useEffect(() => {
    if (!selectedProduct) setModalOpen(false);
  }, [selectedProduct]);

  const handleCardClick = (product: Product) => {
    setSelectedProduct(product);
    setModalOpen(true);
  };

  const renderedProducts = useMemo(() => {
    if (!products?.length) return <p className="text-center text-gray-500">Нет доступных товаров</p>;

    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {products.map((product) => (
          <motion.div
            key={product.id}
            layout
            initial={{ opacity: 0.8, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 10 }}
            transition={{ duration: 0.2 }}
          >
            <ProductCard
              product={product}
              onClick={() => handleCardClick(product)}
              showZKProof={product.verified}
            />
          </motion.div>
        ))}
      </div>
    );
  }, [products]);

  return (
    <div className={`px-4 py-6 min-h-screen ${theme === "dark" ? "bg-black text-white" : "bg-white text-black"}`}>
      <Helmet>
        <title>Маркетплейс | NeuroCity</title>
        <meta name="description" content="Выберите продукты из AI/Web3 экосистемы. Оплата через TON." />
      </Helmet>

      <h1 className="text-3xl font-bold mb-6">Цифровой маркетплейс</h1>

      <div className="flex flex-col lg:flex-row gap-8">
        <aside className="w-full lg:w-1/4">
          <FilterPanel filters={filters} onChange={setFilters} />
        </aside>

        <main className="w-full lg:w-3/4 relative">
          {isLoading ? (
            <div className="flex justify-center items-center min-h-[200px]">
              <Loader />
            </div>
          ) : (
            <AnimatePresence mode="wait">{renderedProducts}</AnimatePresence>
          )}
        </main>
      </div>

      <AnimatePresence>
        {modalOpen && selectedProduct && (
          <Modal onClose={() => setModalOpen(false)}>
            <div className="space-y-4">
              <h2 className="text-xl font-semibold">{selectedProduct.name}</h2>
              <img src={selectedProduct.image} alt={selectedProduct.name} className="w-full h-auto rounded-lg" />
              <p>{selectedProduct.description}</p>
              <div className="flex items-center justify-between">
                <span className="text-lg font-bold">{formatPrice(selectedProduct.price)} TON</span>
                <ZKProofBadge verified={selectedProduct.verified} />
              </div>
              {isAuthenticated && (
                <TonPayButton productId={selectedProduct.id} amount={selectedProduct.price} />
              )}
            </div>
          </Modal>
        )}
      </AnimatePresence>
    </div>
  );
};

export default MarketplaceView;
