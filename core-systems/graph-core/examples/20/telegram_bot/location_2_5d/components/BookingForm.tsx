import React, { useEffect, useState } from 'react';

interface Master {
  id: string;
  name: string;
  availableSlots: string[]; // ISO-строки времени или формат по API
}

interface BookingFormProps {
  onClose: () => void;
}

export const BookingForm: React.FC<BookingFormProps> = ({ onClose }) => {
  const [masters, setMasters] = useState<Master[]>([]);
  const [selectedMaster, setSelectedMaster] = useState<string>('');
  const [selectedSlot, setSelectedSlot] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetch('/api/masters')
      .then(res => res.json())
      .then(data => {
        setMasters(data);
        if (data.length > 0) setSelectedMaster(data[0].id);
      })
      .catch(() => setMessage('Ошибка загрузки мастеров'));
  }, []);

  const handleSubmit = async () => {
    if (!selectedMaster || !selectedSlot) {
      setMessage('Выберите мастера и время');
      return;
    }
    setLoading(true);
    setMessage('');
    try {
      const res = await fetch('/api/booking', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ masterId: selectedMaster, time: selectedSlot }),
      });
      if (res.ok) {
        setMessage('Запись успешно создана!');
      } else {
        const err = await res.json();
        setMessage('Ошибка: ' + (err.message || 'Неизвестная ошибка'));
      }
    } catch {
      setMessage('Ошибка сети');
    }
    setLoading(false);
  };

  const currentMaster = masters.find(m => m.id === selectedMaster);

  return (
    <div style={{ marginTop: 20 }}>
      <h3>Записаться на процедуру</h3>

      <label>
        Мастер:
        <select
          value={selectedMaster}
          onChange={e => setSelectedMaster(e.target.value)}
          disabled={loading}
        >
          {masters.map(m => (
            <option key={m.id} value={m.id}>
              {m.name}
            </option>
          ))}
        </select>
      </label>

      <br />

      <label>
        Время:
        <select
          value={selectedSlot}
          onChange={e => setSelectedSlot(e.target.value)}
          disabled={loading || !currentMaster}
        >
          <option value="">Выберите время</option>
          {currentMaster?.availableSlots.map(slot => (
            <option key={slot} value={slot}>
              {new Date(slot).toLocaleString()}
            </option>
          ))}
        </select>
      </label>

      <br />

      <button onClick={handleSubmit} disabled={loading}>
        {loading ? 'Записываем...' : 'Записаться'}
      </button>

      {message && <p>{message}</p>}
    </div>
  );
};
