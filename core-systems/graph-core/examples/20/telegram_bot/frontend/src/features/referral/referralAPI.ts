import axios from "axios";

export interface Referral {
  id: number;
  referrerId: number;
  referredUserId: number;
  rewardAmount: number;
  createdAt: string;
  status: "pending" | "completed" | "cancelled";
}

export interface CreateReferralPayload {
  referrerCode: string; // код или ссылка реферала
  newUserId: number;
}

const API_BASE = "/api/referral";

// Получить список рефералов пользователя
export const fetchReferrals = async (userId: number): Promise<Referral[]> => {
  const { data } = await axios.get(`${API_BASE}/user/${userId}`);
  return data;
};

// Создать реферальную запись при регистрации нового пользователя по коду
export const createReferral = async (payload: CreateReferralPayload): Promise<Referral> => {
  const { data } = await axios.post(`${API_BASE}/create`, payload);
  return data;
};

// Получить текущий баланс или накопленные бонусы рефералов
export const fetchReferralBalance = async (userId: number): Promise<number> => {
  const { data } = await axios.get(`${API_BASE}/balance/${userId}`);
  return data.balance;
};
