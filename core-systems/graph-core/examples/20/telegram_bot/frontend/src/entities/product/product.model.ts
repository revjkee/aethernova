// entities/product/product.model.ts

export interface Product {
  id: string;
  name: string;
  description: string;
  price: number;           // цена в копейках/центах или float
  currency: string;        // например, "RUB", "USD"
  images: string[];        // URL картинок товара
  categoryId: string;      // ID категории (если есть)
  isAvailable: boolean;    // доступность товара
  rating?: number;         // средний рейтинг (опционально)
  createdAt: string;       // дата создания ISO
  updatedAt?: string;      // дата обновления (опционально)
}

// Вспомогательные функции

export const createEmptyProduct = (): Product => ({
  id: '',
  name: '',
  description: '',
  price: 0,
  currency: 'RUB',
  images: [],
  categoryId: '',
  isAvailable: true,
  createdAt: new Date().toISOString(),
});

export const formatPrice = (price: number, currency = 'RUB'): string => {
  // Форматируем цену для UI, например, 12345 => "123.45 ₽"
  const formatter = new Intl.NumberFormat('ru-RU', {
    style: 'currency',
    currency,
    minimumFractionDigits: 2,
  });
  return formatter.format(price / 100);
};
