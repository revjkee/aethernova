// src/widgets/Footer/Footer.tsx
import React from 'react';
import styles from './Footer.module.css';

export const Footer: React.FC = () => {
  return (
    <footer className={styles.footer}>
      <div className={styles.container}>
        <div className={styles.left}>
          © {new Date().getFullYear()} Студия Красоты — Все права защищены
        </div>
        <div className={styles.center}>
          <a href="/privacy" className={styles.link}>Политика конфиденциальности</a>
          <a href="/terms" className={styles.link}>Условия использования</a>
          <a href="/contacts" className={styles.link}>Контакты</a>
        </div>
        <div className={styles.right}>
          <a href="https://t.me/your_telegram" target="_blank" rel="noopener noreferrer" className={styles.social}>
            Telegram
          </a>
          <a href="https://instagram.com/your_instagram" target="_blank" rel="noopener noreferrer" className={styles.social}>
            Instagram
          </a>
        </div>
      </div>
    </footer>
  );
};
