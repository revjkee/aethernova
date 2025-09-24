// entities/review/review.model.ts

export interface Review {
  id: string;
  userId: string;            // ID пользователя, оставившего отзыв
  productId: string;         // ID товара/услуги, к которому относится отзыв
  rating: number;            // Оценка, например, от 1 до 5
  comment: string;           // Текст отзыва
  createdAt: string;         // Дата создания (ISO строка)
  updatedAt?: string;        // Дата обновления (необязательное поле)
  isApproved: boolean;       // Одобрен ли отзыв (для модерации)
}

// Утилиты
export const createEmptyReview = (): Review => ({
  id: '',
  userId: '',
  productId: '',
  rating: 0,
  comment: '',
  createdAt: new Date().toISOString(),
  isApproved: false,
});

// Функция проверки валидности рейтинга
export const isValidRating = (rating: number): boolean =>
  rating >= 1 && rating <= 5;
