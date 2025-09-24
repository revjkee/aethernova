import React, { useEffect, useState } from 'react';
import { useAuth } from '../../features/auth/hooks/useAuth';
import { fetchUserProfile } from '../../features/profile/profileAPI';
import styles from './ProfilePage.module.css';

const ProfilePage: React.FC = () => {
  const { userId } = useAuth();
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!userId) return;

    setLoading(true);
    fetchUserProfile(userId)
      .then(data => setProfile(data))
      .finally(() => setLoading(false));
  }, [userId]);

  if (loading) return <div className={styles.loader}>Загрузка профиля...</div>;
  if (!profile) return <div className={styles.error}>Профиль не найден</div>;

  return (
    <div className={styles.container}>
      <h1>{profile.name}</h1>
      <p>Email: {profile.email}</p>
      <p>Телефон: {profile.phone}</p>
      {/* Добавьте другие данные профиля */}
    </div>
  );
};

export default ProfilePage;
