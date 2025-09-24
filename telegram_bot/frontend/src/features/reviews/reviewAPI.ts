import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

export interface Review {
  id: number;
  userName: string;
  rating: number;
  comment: string;
  createdAt: string;
}

// Получить список отзывов по продукту
export async function fetchReviews(productId: number): Promise<Review[]> {
  const response = await axios.get(`${API_BASE_URL}/reviews`, {
    params: { product_id: productId },
  });
  return response.data;
}

// Отправить новый отзыв
export async function postReview(productId: number, review: Omit<Review, 'id' | 'createdAt'>): Promise<Review> {
  const response = await axios.post(`${API_BASE_URL}/reviews`, {
    product_id: productId,
    user_name: review.userName,
    rating: review.rating,
    comment: review.comment,
  });
  return response.data;
}
