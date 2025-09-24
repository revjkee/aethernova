// src/widgets/Header/Header.tsx
import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/shared/components/button';
import styles from './Header.module.css';

export const Header: React.FC = () => {
  return (
    <header className={styles.header}>
      <div className={styles.container}>
        <Link to="/" className={styles.logo}>
          <span className={styles.logoText}>TapTrade</span>
        </Link>

        <nav className={styles.nav}>
          <Link to="/" className={styles.link}>Главная</Link>
          <Link to="/products" className={styles.link}>Товары</Link>
          <Link to="/cart" className={styles.link}>Корзина</Link>
          <Link to="/about" className={styles.link}>О нас</Link>
        </nav>

        <div className={styles.actions}>
          <Link to="/login">
            <Button variant="outline">Войти</Button>
          </Link>
        </div>
      </div>
    </header>
  );
};
