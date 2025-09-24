import React from "react";

interface ProductCardProps {
  id: number;
  name: string;
  description: string;
  price: number;
  imageUrl: string;
  onAddToCart?: (productId: number) => void;
}

const ProductCard: React.FC<ProductCardProps> = ({
  id,
  name,
  description,
  price,
  imageUrl,
  onAddToCart,
}) => {
  return (
    <div className="product-card">
      <img
        src={imageUrl}
        alt={name}
        className="product-card__image"
        loading="lazy"
      />
      <div className="product-card__info">
        <h3 className="product-card__name">{name}</h3>
        <p className="product-card__description">{description}</p>
        <div className="product-card__footer">
          <span className="product-card__price">{price.toFixed(2)} ₽</span>
          {onAddToCart && (
            <button
              className="product-card__button"
              type="button"
              onClick={() => onAddToCart(id)}
            >
              В корзину
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default ProductCard;
