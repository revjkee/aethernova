import React from 'react';
import '../styles/location.css';

interface RoomSceneProps {
  onExit: () => void;
}

export const RoomScene: React.FC<RoomSceneProps> = ({ onExit }) => {
  return (
    <div className="location-wrapper" style={{ backgroundColor: '#fff0f5' }}>
      <h2 style={{ textAlign: 'center', marginTop: '40px', color: '#ff5ca0' }}>
        Ты внутри комнаты 💅
      </h2>

      <p style={{ textAlign: 'center', marginTop: '20px' }}>
        Здесь можно разместить услуги, диалог с мастером, прокачку, WebApp и другое.
      </p>

      <div style={{ textAlign: 'center', marginTop: '60px' }}>
        <button
          onClick={onExit}
          style={{
            padding: '12px 24px',
            backgroundColor: '#ff94c2',
            color: 'white',
            border: 'none',
            borderRadius: '12px',
            fontWeight: 'bold',
            cursor: 'pointer',
          }}
        >
          Вернуться в коридор
        </button>
      </div>
    </div>
  );
};
