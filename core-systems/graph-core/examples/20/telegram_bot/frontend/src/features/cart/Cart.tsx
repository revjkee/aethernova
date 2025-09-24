import React from "react";
import { useSelector, useDispatch } from "react-redux";
import { RootState } from "../../app/store";
import { removeItem, clearCart } from "./cartSlice";

export const Cart: React.FC = () => {
  const dispatch = useDispatch();
  const cartItems = useSelector((state: RootState) => state.cart.items);

  const handleRemove = (id: number) => {
    dispatch(removeItem(id));
  };

  const handleClear = () => {
    dispatch(clearCart());
  };

  const totalPrice = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);

  return (
    <div className="cart-container">
      <h2>Корзина</h2>
      {cartItems.length === 0 ? (
        <p>Корзина пуста</p>
      ) : (
        <>
          <ul>
            {cartItems.map((item) => (
              <li key={item.id}>
                <span>{item.name}</span> — <b>{item.price} ₽</b> x {item.quantity}
                <button onClick={() => handleRemove(item.id)}>Удалить</button>
              </li>
            ))}
          </ul>
          <div className="cart-total">
            <strong>Итого: {totalPrice.toFixed(2)} ₽</strong>
          </div>
          <button onClick={handleClear}>Очистить корзину</button>
        </>
      )}
    </div>
  );
};
