// path: src/pages/MarketplaceAdmin.tsx

import { useEffect, useState, useMemo } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useAdminProducts, useUpdateProduct, useDeleteProduct, useCreateProduct } from "@/features/product/productAPI";
import { AdminProductForm } from "@/features/product/AdminProductForm";
import { AdminProductRow } from "@/features/product/AdminProductRow";
import { Modal } from "@/shared/components/Modal";
import { Button } from "@/shared/components/Button";
import { Spinner } from "@/shared/components/Spinner";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { useZKSession } from "@/shared/hooks/useZKSession";
import { Helmet } from "react-helmet";
import { AnimatePresence, motion } from "framer-motion";
import { toast } from "react-toastify";
import { ExportAuditLogButton } from "@/features/audit/ExportAuditLogButton";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { Product } from "@/features/product/types";

const MarketplaceAdmin = () => {
  const { isAuthenticated, user } = useAuth();
  const { validateZKSession } = useZKSession();
  const [search, setSearch] = useState<string>("");
  const debouncedSearch = useDebounce(search, 300);

  const { data: products, isLoading, refetch } = useAdminProducts({ search: debouncedSearch });
  const updateProduct = useUpdateProduct();
  const deleteProduct = useDeleteProduct();
  const createProduct = useCreateProduct();

  const [editProduct, setEditProduct] = useState<Product | null>(null);
  const [isModalOpen, setModalOpen] = useState(false);

  useEffect(() => {
    validateZKSession(user?.id);
  }, [user]);

  const handleEdit = (product: Product) => {
    setEditProduct(product);
    setModalOpen(true);
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteProduct.mutateAsync(id);
      toast.success("Товар удалён");
      refetch();
    } catch {
      toast.error("Ошибка удаления");
    }
  };

  const handleSubmit = async (product: Product) => {
    try {
      if (product.id) {
        await updateProduct.mutateAsync(product);
        toast.success("Товар обновлён");
      } else {
        await createProduct.mutateAsync(product);
        toast.success("Товар создан");
      }
      refetch();
      setModalOpen(false);
    } catch {
      toast.error("Ошибка при сохранении");
    }
  };

  const filteredProducts = useMemo(() => {
    if (!products) return [];
    return products.filter(p => p.name.toLowerCase().includes(debouncedSearch.toLowerCase()));
  }, [products, debouncedSearch]);

  return (
    <AccessGuard roles={[ROLE.ADMIN]}>
      <Helmet>
        <title>Админка Маркетплейса | NeuroCity</title>
        <meta name="description" content="Управление цифровыми товарами, аудитами и AI-инфраструктурой" />
      </Helmet>

      <div className="px-6 py-8">
        <h1 className="text-2xl font-semibold mb-4">Панель управления маркетплейсом</h1>

        <div className="flex items-center justify-between mb-6">
          <input
            type="text"
            placeholder="Поиск по названию"
            className="border px-4 py-2 rounded-md w-full max-w-md"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <div className="ml-4 flex gap-2">
            <Button onClick={() => { setEditProduct(null); setModalOpen(true); }}>+ Новый товар</Button>
            <ExportAuditLogButton entity="product" />
          </div>
        </div>

        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="flex justify-center items-center min-h-[200px]">
              <Spinner />
            </div>
          ) : (
            <table className="min-w-full border border-gray-200">
              <thead>
                <tr className="bg-gray-100 text-left text-sm font-semibold">
                  <th className="px-4 py-2">ID</th>
                  <th className="px-4 py-2">Название</th>
                  <th className="px-4 py-2">Цена (TON)</th>
                  <th className="px-4 py-2">Статус</th>
                  <th className="px-4 py-2">Действия</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence initial={false}>
                  {filteredProducts.map((product) => (
                    <motion.tr
                      key={product.id}
                      layout
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.2 }}
                    >
                      <AdminProductRow
                        product={product}
                        onEdit={() => handleEdit(product)}
                        onDelete={() => handleDelete(product.id)}
                      />
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          )}
        </div>

        <AnimatePresence>
          {isModalOpen && (
            <Modal onClose={() => setModalOpen(false)}>
              <AdminProductForm product={editProduct} onSubmit={handleSubmit} />
            </Modal>
          )}
        </AnimatePresence>
      </div>
    </AccessGuard>
  );
};

export default MarketplaceAdmin;
