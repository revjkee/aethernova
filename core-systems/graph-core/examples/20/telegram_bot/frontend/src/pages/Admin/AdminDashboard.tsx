import React, { useEffect, useState, useCallback } from 'react';
import { fetchUsers, fetchOrders, fetchAnalytics } from '../../features/admin/adminAPI';
import UsersTable from '../../features/admin/components/UsersTable';
import OrdersTable from '../../features/admin/components/OrdersTable';
import AnalyticsDashboard from '../../features/admin/components/AnalyticsDashboard';
import Sidebar from '../../shared/components/Sidebar';
import Header from '../../shared/components/Header';
import styles from './AdminDashboard.module.css';

const AdminDashboard: React.FC = () => {
  const [users, setUsers] = useState([]);
  const [orders, setOrders] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedSection, setSelectedSection] = useState<'users' | 'orders' | 'analytics'>('users');

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [usersData, ordersData, analyticsData] = await Promise.all([
        fetchUsers(),
        fetchOrders(),
        fetchAnalytics(),
      ]);
      setUsers(usersData);
      setOrders(ordersData);
      setAnalytics(analyticsData);
    } catch (error) {
      console.error('Ошибка загрузки данных админ-панели', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading) return <div className={styles.loader}>Загрузка данных...</div>;

  return (
    <div className={styles.adminDashboard}>
      <Sidebar
        selected={selectedSection}
        onSelect={setSelectedSection}
        items={[
          { key: 'users', label: 'Пользователи' },
          { key: 'orders', label: 'Заказы' },
          { key: 'analytics', label: 'Аналитика' },
        ]}
      />
      <main className={styles.mainContent}>
        <Header title="Админ панель" />
        {selectedSection === 'users' && <UsersTable users={users} />}
        {selectedSection === 'orders' && <OrdersTable orders={orders} />}
        {selectedSection === 'analytics' && analytics && <AnalyticsDashboard data={analytics} />}
      </main>
    </div>
  );
};

export default AdminDashboard;
