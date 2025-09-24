import React, { useState } from 'react';
import ReactDOM from 'react-dom/client';
import { CorridorScene } from './scenes/corridor_scene';
import { RoomScene } from './scenes/RoomScene';

const App: React.FC = () => {
  const [insideRoom, setInsideRoom] = useState(false);

  return insideRoom ? (
    <RoomScene onExit={() => setInsideRoom(false)} />
  ) : (
    <CorridorScene onEnterRoom={() => setInsideRoom(true)} />
  );
};

const root = ReactDOM.createRoot(document.getElementById('root')!);
root.render(<App />);
