import React from 'react';
import '../styles/location.css';
import { NPC } from '../components/NPC';
import { npcPositions, roomSizes, doorPosition } from '../utils/constants';

export const CorridorScene: React.FC = () => {
  const npcList = [
    {
      name: 'Мастер-Гуру',
      image: '/sprites/girl_01.png',
      description: 'Личный помощник в выборе процедур, прокачке и развитии.',
    },
    {
      name: 'Запись в студию',
      image: '/sprites/girl_02.png',
      description: 'Позволяет выбрать мастера, записаться на процедуры.',
    },
    {
      name: 'Beauty Маркетплейс',
      image: '/sprites/girl_03.png',
      description: 'Здесь можно приобрести косметику, уходовые товары, образы.',
    },
    {
      name: 'NFT Карточки',
      image: '/sprites/girl_04.png',
      description: 'Коллекционируй, прокачивай и получай бонусы через NFT.',
    },
    {
      name: 'Рефералы',
      image: '/sprites/girl_05.png',
      description: 'Приглашай подруг — получай бонусы и NFT-награды.',
    },
    {
      name: 'Топ-лидеров',
      image: '/sprites/girl_06.png',
      description: 'Лучшие мастера и клиентки, топ по активности и отзывам.',
    },
    {
      name: 'Кошелёк',
      image: '/sprites/boy_wallet.png',
      description: 'Храни и трать токены. Поддержка TON, NFT и баланса.',
    },
  ];

  return (
    <div className="location-wrapper">
      {/* Коридор */}
      <div className="corridor" />

      {/* Комнаты */}
      {npcList.slice(0, 6).map((_, index) => (
        <div
          key={index}
          className="room"
          style={{
            left: npcPositions[index].x - roomSizes.width / 2,
            top: npcPositions[index].y - roomSizes.height,
          }}
        />
      ))}

      {/* NPC */}
      {npcList.map((npc, index) => (
        <NPC
          key={npc.name}
          name={npc.name}
          image={npc.image}
          position={npcPositions[index]}
          description={npc.description}
        />
      ))}

      {/* Контейнеры для предметов */}
      <div
        className="item-container"
        style={{ left: 180, top: 300 }}
        title="Место для предмета"
      />
      <div
        className="item-container"
        style={{ left: 420, top: 300 }}
        title="Будущий объект"
      />

      {/* Дверь снизу */}
      <div
        className="bottom-door"
        title="Вход / выход"
        onClick={() => alert('Переход к следующей локации')}
        style={{
          left: doorPosition.x,
        }}
      />
    </div>
  );
};

interface CorridorSceneProps {
  onEnterRoom: () => void;
}

export const CorridorScene: React.FC<CorridorSceneProps> = ({ onEnterRoom }) => {
  // ...
  return (
    <div className="location-wrapper">
      {/* ... */}
      <Player onEnterRoom={onEnterRoom} />
    </div>
  );
};
