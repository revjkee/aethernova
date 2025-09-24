import React, { useEffect, useState } from "react";
import { fetchReviews, Review } from "./reviewAPI";

interface ReviewListProps {
  productId: number;
}

const ReviewList: React.FC<ReviewListProps> = ({ productId }) => {
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    fetchReviews(productId)
      .then(data => {
        setReviews(data);
        setError(null);
      })
      .catch(() => setError("Ошибка загрузки отзывов"))
      .finally(() => setLoading(false));
  }, [productId]);

  if (loading) return <p>Загрузка отзывов...</p>;
  if (error) return <p>{error}</p>;

  if (reviews.length === 0) return <p>Пока нет отзывов.</p>;

  return (
    <ul>
      {reviews.map(({ id, userName, rating, comment, createdAt }) => (
        <li key={id} className="review-item">
          <strong>{userName}</strong> — <em>{new Date(createdAt).toLocaleDateString()}</em>
          <div>Рейтинг: {rating} / 5</div>
          <p>{comment}</p>
        </li>
      ))}
    </ul>
  );
};

export default ReviewList;
