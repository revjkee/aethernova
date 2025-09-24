import React, { useState, useEffect } from 'react';
import '../styles/location.css';
import { Joystick } from './Joystick';
import { doorPosition } from '../utils/constants';

export const Player: React.FC = () => {
  const [position, setPosition] = useState({ x: 600, y: 500 });
  const speed = 8;

  const move = (direction: 'up' | 'down' | 'left' | 'right') => {
    setPosition((prev) => {
      let { x, y } = prev;
      const maxX = window.innerWidth - 96;
      const maxY = window.innerHeight - 96;

      if (direction === 'up') y = Math.max(0, y - speed);
      if (direction === 'down') y = Math.min(maxY, y + speed);
      if (direction === 'left') x = Math.max(0, x - speed);
      if (direction === 'right') x = Math.min(maxX, x + speed);

      return { x, y };
    });
  };

  const checkDoorCollision = () => {
    const dx = Math.abs(position.x - doorPosition.x);
    const dy = Math.abs(position.y - doorPosition.y);
    if (dx < 60 && dy < 60) {
      alert('Переход в комнату или другую локацию');
      // Здесь можно вызывать смену сцены или переход в WebApp room
    }
  };

  useEffect(() => {
    checkDoorCollision();
  }, [position]);

  return (
    <>
      <div
        className="npc"
        style={{
          left: position.x,
          top: position.y,
          backgroundImage: `url('/sprites/player.png')`,
          zIndex: 10,
        }}
        title="Ты"
      />
      <Joystick onMove={move} />
    </>
  );
};

interface PlayerProps {
  onEnterRoom: () => void;
}

export const Player: React.FC<PlayerProps> = ({ onEnterRoom }) => {
  // ...
  const checkDoorCollision = () => {
    const dx = Math.abs(position.x - doorPosition.x);
    const dy = Math.abs(position.y - doorPosition.y);
    if (dx < 60 && dy < 60) {
      onEnterRoom();
    }
  };
