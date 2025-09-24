import React from 'react';
import '../styles/location.css';

interface ItemContainerProps {
  id: string;
  position: { x: number; y: number };
  image?: string; // путь к иконке или модели
  title?: string;
  onClick?: () => void;
}

export const ItemContainer: React.FC<ItemContainerProps> = ({
  id,
  position,
  image,
  title = 'Контейнер для предмета',
  onClick,
}) => {
  return (
    <div
      className="item-container"
      title={title}
      style={{
        left: position.x,
        top: position.y,
        backgroundImage: image ? `url(${image})` : 'none',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        cursor: onClick ? 'pointer' : 'default',
      }}
      onClick={onClick}
    >
      {/* можно добавить иконку загрузки, если image нет */}
    </div>
  );
};
