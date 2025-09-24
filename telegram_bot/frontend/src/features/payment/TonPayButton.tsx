import React, { useState } from "react";
import { useAppDispatch, useAppSelector } from "../../shared/hooks/redux";
import { initiatePayment, resetPaymentState } from "./paymentSlice";

interface TonPayButtonProps {
  amount: number;           // сумма в копейках/центах
  orderId: string;
  description?: string;
}

const TonPayButton: React.FC<TonPayButtonProps> = ({ amount, orderId, description }) => {
  const dispatch = useAppDispatch();
  const paymentState = useAppSelector(state => state.payment);
  const [isClicked, setClicked] = useState(false);

  const handlePayClick = () => {
    if (isClicked) return;  // защита от повторных кликов
    setClicked(true);

    dispatch(initiatePayment({
      amount,
      currency: "RUB",
      method: "ton",
      orderId,
      description,
    })).unwrap()
      .catch(() => setClicked(false));
  };

  return (
    <div>
      {paymentState.status === "success" && paymentState.paymentUrl ? (
        <a href={paymentState.paymentUrl} target="_blank" rel="noopener noreferrer">
          Оплатить через TON кошелек
        </a>
      ) : (
        <button onClick={handlePayClick} disabled={paymentState.status === "pending"}>
          {paymentState.status === "pending" ? "Обработка..." : "Оплатить TON"}
        </button>
      )}
      {paymentState.error && <p style={{ color: "red" }}>{paymentState.error}</p>}
    </div>
  );
};

export default TonPayButton;
