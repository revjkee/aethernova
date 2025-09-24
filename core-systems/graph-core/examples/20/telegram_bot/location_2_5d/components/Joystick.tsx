import React from 'react';
import '../styles/location.css';

interface JoystickProps {
  onMove: (direction: 'up' | 'down' | 'left' | 'right') => void;
}

export const Joystick: React.FC<JoystickProps> = ({ onMove }) => {
  return (
    <div className="joystick">
      <div className="joy-row">
        <button onClick={() => onMove('up')}>⬆</button>
      </div>
      <div className="joy-row">
        <button onClick={() => onMove('left')}>⬅</button>
        <button onClick={() => onMove('down')}>⬇</button>
        <button onClick={() => onMove('right')}>➡</button>
      </div>
    </div>
  );
};
