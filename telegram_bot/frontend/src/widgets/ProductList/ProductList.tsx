// src/widgets/ProductList/ProductList.tsx
import React from 'react';
import { ProductCard } from '@/features/product/ProductCard';
import { Product } from '@/entities/product/product.model';
import styles from './ProductList.module.css';

type ProductListProps = {
  products: Product[];
};

export const ProductList: React.FC<ProductListProps> = ({ products }) => {
  if (!products.length) {
    return <div className={styles.empty}>Товары не найдены</div>;
  }

  return (
    <section className={styles.wrapper}>
      {products.map((product) => (
        <ProductCard key={product.id} product={product} />
      ))}
    </section>
  );
};
