import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import axios from 'axios';

export interface Review {
  id: number;
  userName: string;
  rating: number;
  comment: string;
  createdAt: string;
}

interface ReviewsState {
  reviews: Review[];
  loading: boolean;
  error: string | null;
}

const initialState: ReviewsState = {
  reviews: [],
  loading: false,
  error: null,
};

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

// Асинхронный thunk для загрузки отзывов по продукту
export const fetchReviews = createAsyncThunk<Review[], number>(
  'reviews/fetchReviews',
  async (productId) => {
    const response = await axios.get(`${API_BASE_URL}/reviews`, {
      params: { product_id: productId },
    });
    return response.data;
  }
);

// Асинхронный thunk для добавления отзыва
export const addReview = createAsyncThunk<Review, { productId: number; review: Omit<Review, 'id' | 'createdAt'> }>(
  'reviews/addReview',
  async ({ productId, review }) => {
    const response = await axios.post(`${API_BASE_URL}/reviews`, {
      product_id: productId,
      user_name: review.userName,
      rating: review.rating,
      comment: review.comment,
    });
    return response.data;
  }
);

const reviewsSlice = createSlice({
  name: 'reviews',
  initialState,
  reducers: {
    clearError(state) {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      // fetchReviews
      .addCase(fetchReviews.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchReviews.fulfilled, (state, action: PayloadAction<Review[]>) => {
        state.loading = false;
        state.reviews = action.payload;
      })
      .addCase(fetchReviews.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Ошибка загрузки отзывов';
      })
      // addReview
      .addCase(addReview.pending, (state) => {
        state.error = null;
      })
      .addCase(addReview.fulfilled, (state, action: PayloadAction<Review>) => {
        state.reviews.push(action.payload);
      })
      .addCase(addReview.rejected, (state, action) => {
        state.error = action.error.message || 'Ошибка добавления отзыва';
      });
  },
});

export const { clearError } = reviewsSlice.actions;

export default reviewsSlice.reducer;
