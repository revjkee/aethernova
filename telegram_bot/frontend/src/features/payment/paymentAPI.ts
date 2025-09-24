import axios from "axios";

const API_BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000/api";

export interface PaymentRequest {
  amount: number;            // сумма к оплате в копейках/центах
  currency: string;          // валюта, например "RUB", "USD"
  method: string;            // способ оплаты, например "ton", "card"
  orderId: string;           // уникальный идентификатор заказа
  description?: string;      // описание платежа
}

export interface PaymentResponse {
  paymentUrl: string;        // ссылка для проведения оплаты (если нужно)
  status: "pending" | "success" | "failed";
  transactionId?: string;   // ID транзакции в платежной системе
  errorMessage?: string;
}

export const createPayment = async (data: PaymentRequest): Promise<PaymentResponse> => {
  const response = await axios.post<PaymentResponse>(`${API_BASE_URL}/payment/create`, data);
  return response.data;
};

export const checkPaymentStatus = async (transactionId: string): Promise<PaymentResponse> => {
  const response = await axios.get<PaymentResponse>(`${API_BASE_URL}/payment/status/${transactionId}`);
  return response.data;
};
