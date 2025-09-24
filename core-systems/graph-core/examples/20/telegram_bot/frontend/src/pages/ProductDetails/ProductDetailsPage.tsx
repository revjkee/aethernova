import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { fetchProductById } from '../../features/product/productAPI';
import ProductCard from '../../features/product/components/ProductCard';
import styles from './ProductDetailsPage.module.css';

const ProductDetailsPage: React.FC = () => {
  const { productId } = useParams<{ productId: string }>();
  const [product, setProduct] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!productId) return;

    setLoading(true);
    fetchProductById(productId)
      .then(data => setProduct(data))
      .finally(() => setLoading(false));
  }, [productId]);

  if (loading) return <div className={styles.loader}>Загрузка...</div>;
  if (!product) return <div className={styles.notFound}>Товар не найден</div>;

  return (
    <div className={styles.container}>
      <ProductCard product={product} detailedView />
      {/* Можно добавить отзывы, рекомендации и т.п. */}
    </div>
  );
};

export default ProductDetailsPage;
