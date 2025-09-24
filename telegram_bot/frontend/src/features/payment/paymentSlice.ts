import { createSlice, PayloadAction, createAsyncThunk } from '@reduxjs/toolkit';
import { createPayment, checkPaymentStatus, PaymentRequest, PaymentResponse } from './paymentAPI';

interface PaymentState {
  status: 'idle' | 'pending' | 'success' | 'failed';
  paymentUrl?: string;
  transactionId?: string;
  error?: string;
}

const initialState: PaymentState = {
  status: 'idle',
};

export const initiatePayment = createAsyncThunk<
  PaymentResponse,
  PaymentRequest,
  { rejectValue: string }
>(
  'payment/initiate',
  async (paymentData, { rejectWithValue }) => {
    try {
      const response = await createPayment(paymentData);
      if (response.status === 'failed') {
        return rejectWithValue(response.errorMessage || 'Payment failed');
      }
      return response;
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
);

export const fetchPaymentStatus = createAsyncThunk<
  PaymentResponse,
  string,
  { rejectValue: string }
>(
  'payment/status',
  async (transactionId, { rejectWithValue }) => {
    try {
      const response = await checkPaymentStatus(transactionId);
      if (response.status === 'failed') {
        return rejectWithValue(response.errorMessage || 'Payment failed');
      }
      return response;
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
);

const paymentSlice = createSlice({
  name: 'payment',
  initialState,
  reducers: {
    resetPaymentState(state) {
      state.status = 'idle';
      state.paymentUrl = undefined;
      state.transactionId = undefined;
      state.error = undefined;
    },
  },
  extraReducers: builder => {
    builder
      .addCase(initiatePayment.pending, state => {
        state.status = 'pending';
        state.error = undefined;
      })
      .addCase(initiatePayment.fulfilled, (state, action) => {
        state.status = 'success';
        state.paymentUrl = action.payload.paymentUrl;
        state.transactionId = action.payload.transactionId;
      })
      .addCase(initiatePayment.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload || 'Unknown error';
      })
      .addCase(fetchPaymentStatus.pending, state => {
        state.status = 'pending';
        state.error = undefined;
      })
      .addCase(fetchPaymentStatus.fulfilled, (state, action) => {
        state.status = action.payload.status;
        state.error = undefined;
      })
      .addCase(fetchPaymentStatus.rejected, (state, action) => {
        state.status = 'failed';
        state.error = action.payload || 'Unknown error';
      });
  },
});

export const { resetPaymentState } = paymentSlice.actions;
export default paymentSlice.reducer;
