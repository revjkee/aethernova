// src/widgets/CartWidget/CartWidget.tsx

import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { RootState } from '@/app/store';
import { removeItem, updateQuantity } from '@/features/cart/cartSlice';
import styles from './CartWidget.module.css';

export const CartWidget: React.FC = () => {
  const dispatch = useDispatch();
  const items = useSelector((state: RootState) => state.cart.items);
  const totalPrice = items.reduce((sum, item) => sum + item.price * item.quantity, 0);

  const handleRemove = (id: string) => {
    dispatch(removeItem(id));
  };

  const handleQuantityChange = (id: string, qty: number) => {
    if (qty > 0) {
      dispatch(updateQuantity({ id, quantity: qty }));
    }
  };

  if (items.length === 0) {
    return <div className={styles.empty}>Корзина пуста</div>;
  }

  return (
    <div className={styles.cartWidget}>
      <h3>Корзина</h3>
      <ul className={styles.list}>
        {items.map(item => (
          <li key={item.id} className={styles.item}>
            <div className={styles.name}>{item.name}</div>
            <input
              type="number"
              min={1}
              value={item.quantity}
              onChange={e => handleQuantityChange(item.id, Number(e.target.value))}
              className={styles.qtyInput}
            />
            <div className={styles.price}>{(item.price * item.quantity).toFixed(2)} ₽</div>
            <button onClick={() => handleRemove(item.id)} className={styles.removeBtn}>×</button>
          </li>
        ))}
      </ul>
      <div className={styles.total}>Итого: {totalPrice.toFixed(2)} ₽</div>
    </div>
  );
};
