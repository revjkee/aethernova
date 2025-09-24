import axios from "axios";

const API_BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000/api";

export interface CartItem {
  id: number;
  productId: number;
  name: string;
  price: number;
  quantity: number;
}

export const fetchCartItems = async (): Promise<CartItem[]> => {
  const response = await axios.get<CartItem[]>(`${API_BASE_URL}/cart`);
  return response.data;
};

export const addToCart = async (productId: number, quantity: number = 1): Promise<void> => {
  await axios.post(`${API_BASE_URL}/cart/add`, { productId, quantity });
};

export const updateCartItem = async (productId: number, quantity: number): Promise<void> => {
  await axios.put(`${API_BASE_URL}/cart/update`, { productId, quantity });
};

export const removeCartItem = async (productId: number): Promise<void> => {
  await axios.delete(`${API_BASE_URL}/cart/remove`, { data: { productId } });
};

export const clearCart = async (): Promise<void> => {
  await axios.post(`${API_BASE_URL}/cart/clear`);
};
