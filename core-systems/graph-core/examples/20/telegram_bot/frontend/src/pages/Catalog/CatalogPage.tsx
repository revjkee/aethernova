import React, { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { fetchProducts, selectProducts, selectLoading } from '../../features/product/productSlice';
import ProductCard from '../../features/product/components/ProductCard';
import Loader from '../../shared/components/Loader';

const CatalogPage: React.FC = () => {
  const dispatch = useDispatch();
  const products = useSelector(selectProducts);
  const loading = useSelector(selectLoading);

  useEffect(() => {
    dispatch(fetchProducts());
  }, [dispatch]);

  if (loading) {
    return <Loader />;
  }

  return (
    <div>
      <h1>Каталог товаров</h1>
      <div className="product-grid">
        {products.length ? (
          products.map(product => (
            <ProductCard key={product.id} product={product} />
          ))
        ) : (
          <p>Товары не найдены.</p>
        )}
      </div>
    </div>
  );
};

export default CatalogPage;
