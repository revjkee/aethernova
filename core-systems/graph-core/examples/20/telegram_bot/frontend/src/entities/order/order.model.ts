// src/entities/order/order.model.ts

export interface OrderItem {
  productId: string;
  quantity: number;
  price: number; // цена за единицу в копейках/центах
}

export interface Order {
  id: string;
  userId: string;
  items: OrderItem[];
  totalAmount: number;      // итоговая сумма в копейках/центах
  currency: string;         // валюта, например "RUB"
  status: 'pending' | 'paid' | 'cancelled' | 'completed';
  createdAt: string;        // дата создания в ISO формате
  updatedAt?: string;       // дата обновления (опционально)
  paymentMethod?: string;   // например, "ton", "card"
  deliveryAddress?: string; // адрес доставки (если нужно)
}

// Шаблон пустого заказа

export const createEmptyOrder = (): Order => ({
  id: '',
  userId: '',
  items: [],
  totalAmount: 0,
  currency: 'RUB',
  status: 'pending',
  createdAt: new Date().toISOString(),
});
