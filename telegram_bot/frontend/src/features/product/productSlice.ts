import { createSlice, createAsyncThunk, PayloadAction } from "@reduxjs/toolkit";
import axios from "axios";

export interface Product {
  id: number;
  name: string;
  description: string;
  price: number;
  imageUrl: string;
}

interface ProductState {
  products: Product[];
  loading: boolean;
  error: string | null;
}

const initialState: ProductState = {
  products: [],
  loading: false,
  error: null,
};

// Асинхронный thunk для загрузки продуктов с API
export const fetchProducts = createAsyncThunk<Product[]>(
  "product/fetchProducts",
  async () => {
    const response = await axios.get<Product[]>("/api/products");
    return response.data;
  }
);

const productSlice = createSlice({
  name: "product",
  initialState,
  reducers: {
    // Пример редьюсера добавления продукта в локальное состояние (если нужно)
    addProduct(state, action: PayloadAction<Product>) {
      state.products.push(action.payload);
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchProducts.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchProducts.fulfilled, (state, action) => {
        state.loading = false;
        state.products = action.payload;
      })
      .addCase(fetchProducts.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message ?? "Ошибка загрузки продуктов";
      });
  },
});

export const { addProduct } = productSlice.actions;

export default productSlice.reducer;
