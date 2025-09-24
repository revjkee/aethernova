import axios from "axios";

export interface Product {
  id: number;
  name: string;
  description: string;
  price: number;
  imageUrl: string;
  category: string;
  brand: string;
  available: boolean;
}

export interface ProductFilter {
  category?: string;
  brand?: string;
  priceMin?: number;
  priceMax?: number;
  search?: string;
}

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

export async function fetchProducts(filters: ProductFilter = {}): Promise<Product[]> {
  const params = new URLSearchParams();

  if (filters.category) params.append("category", filters.category);
  if (filters.brand) params.append("brand", filters.brand);
  if (filters.priceMin !== undefined) params.append("price_min", String(filters.priceMin));
  if (filters.priceMax !== undefined) params.append("price_max", String(filters.priceMax));
  if (filters.search) params.append("search", filters.search);

  const response = await axios.get<Product[]>(`${API_BASE}/products`, { params });
  return response.data;
}

export async function fetchProductById(id: number): Promise<Product> {
  const response = await axios.get<Product>(`${API_BASE}/products/${id}`);
  return response.data;
}

export async function createProduct(product: Omit<Product, "id">): Promise<Product> {
  const response = await axios.post<Product>(`${API_BASE}/products`, product);
  return response.data;
}

export async function updateProduct(id: number, product: Partial<Product>): Promise<Product> {
  const response = await axios.put<Product>(`${API_BASE}/products/${id}`, product);
  return response.data;
}

export async function deleteProduct(id: number): Promise<void> {
  await axios.delete(`${API_BASE}/products/${id}`);
}
