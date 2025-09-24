import React, { useState } from "react";

interface AddReviewsFormProps {
  onSubmit: (review: { name: string; rating: number; comment: string }) => void;
}

const AddReviewsForm: React.FC<AddReviewsFormProps> = ({ onSubmit }) => {
  const [name, setName] = useState("");
  const [rating, setRating] = useState(5);
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError("Введите имя");
      return;
    }
    if (rating < 1 || rating > 5) {
      setError("Рейтинг должен быть от 1 до 5");
      return;
    }
    if (!comment.trim()) {
      setError("Введите комментарий");
      return;
    }
    setError(null);
    onSubmit({ name, rating, comment });
    setName("");
    setRating(5);
    setComment("");
  };

  return (
    <form onSubmit={handleSubmit} className="add-review-form">
      <h3>Оставить отзыв</h3>

      <label>
        Имя:
        <input
          type="text"
          value={name}
          onChange={e => setName(e.target.value)}
          required
          maxLength={50}
        />
      </label>

      <label>
        Рейтинг:
        <select value={rating} onChange={e => setRating(+e.target.value)}>
          {[1, 2, 3, 4, 5].map(n => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </label>

      <label>
        Комментарий:
        <textarea
          value={comment}
          onChange={e => setComment(e.target.value)}
          required
          maxLength={500}
        />
      </label>

      {error && <p className="error">{error}</p>}

      <button type="submit">Отправить</button>
    </form>
  );
};

export default AddReviewsForm;
