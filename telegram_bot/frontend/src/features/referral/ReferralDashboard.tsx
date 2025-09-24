import React, { useEffect, useState } from "react";
import { fetchReferrals, fetchReferralBalance } from "./referralAPI";

interface Referral {
  id: number;
  referrerId: number;
  referredUserId: number;
  rewardAmount: number;
  createdAt: string;
  status: string;
}

const ReferralDashboard: React.FC<{ userId: number }> = ({ userId }) => {
  const [referrals, setReferrals] = useState<Referral[]>([]);
  const [balance, setBalance] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const refs = await fetchReferrals(userId);
        const bal = await fetchReferralBalance(userId);
        setReferrals(refs);
        setBalance(bal);
      } catch (err) {
        setError("Ошибка загрузки данных");
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, [userId]);

  if (loading) return <div>Загрузка...</div>;
  if (error) return <div>{error}</div>;

  return (
    <div>
      <h2>Реферальная программа</h2>
      <p>Ваш бонусный баланс: <b>{balance} ₽</b></p>
      <table>
        <thead>
          <tr>
            <th>ID Реферала</th>
