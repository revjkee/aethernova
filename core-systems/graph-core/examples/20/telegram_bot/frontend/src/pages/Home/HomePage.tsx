import React from 'react';
import ProductList from '../../features/product/components/ProductList';
import ReviewList from '../../features/review/components/ReviewList';
import Banner from '../../shared/components/Banner';

const HomePage: React.FC = () => {
  return (
    <main>
      <Banner />
      <section>
        <h2>Популярные товары</h2>
        <ProductList />
      </section>
      <section>
        <h2>Отзывы</h2>
        <ReviewList productId={1} />
      </section>
    </main>
  );
};

export default HomePage;
