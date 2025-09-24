import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { fetchReferrals, fetchReferralBalance } from './referralAPI';

interface Referral {
  id: number;
  referrerId: number;
  referredUserId: number;
  rewardAmount: number;
  createdAt: string;
  status: 'pending' | 'completed' | 'cancelled';
}

interface ReferralState {
  referrals: Referral[];
  balance: number;
  loading: boolean;
  error: string | null;
}

const initialState: ReferralState = {
  referrals: [],
  balance: 0,
  loading: false,
  error: null,
};

// Async thunk для загрузки рефералов
export const loadReferrals = createAsyncThunk(
  'referral/loadReferrals',
  async (userId: number, { rejectWithValue }) => {
    try {
      const referrals = await fetchReferrals(userId);
      const balance = await fetchReferralBalance(userId);
      return { referrals, balance };
    } catch (error) {
      return rejectWithValue('Ошибка загрузки рефералов');
    }
  }
);

const referralSlice = createSlice({
  name: 'referral',
  initialState,
  reducers: {
    // Можно добавить синхронные экшены, если нужны
  },
  extraReducers: builder => {
    builder
      .addCase(loadReferrals.pending, state => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loadReferrals.fulfilled, (state, action: PayloadAction<{ referrals: Referral[]; balance: number }>) => {
        state.referrals = action.payload.referrals;
        state.balance = action.payload.balance;
        state.loading = false;
      })
      .addCase(loadReferrals.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });
  },
});

export default referralSlice.reducer;
