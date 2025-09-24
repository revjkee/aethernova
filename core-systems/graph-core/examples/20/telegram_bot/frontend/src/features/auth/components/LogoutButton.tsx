import React from 'react';

interface LogoutButtonProps {
  onLogout: () => void;
  disabled?: boolean;
}

const LogoutButton: React.FC<LogoutButtonProps> = ({ onLogout, disabled = false }) => {
  return (
    <button
      type="button"
      onClick={onLogout}
      disabled={disabled}
      className="logout-button"
      aria-label="Выйти из аккаунта"
    >
      Выйти
    </button>
  );
};

export default LogoutButton;
