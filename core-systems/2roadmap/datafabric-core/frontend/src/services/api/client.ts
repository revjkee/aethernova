// API Configuration
export const API_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:8000/api';

// API Client
class ApiClient {
  private baseURL: string;
  private token: string | null = null;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
  }

  setAuthToken(token: string) {
    this.token = token;
  }

  clearAuthToken() {
    this.token = null;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    const config: RequestInit = {
      ...options,
      headers,
    };

    try {
      const response = await fetch(url, config);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  async get<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET' });
  }

  async post<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async put<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async delete<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }

  async patch<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PATCH',
      body: data ? JSON.stringify(data) : undefined,
    });
  }
}

// Export singleton instance
export const apiClient = new ApiClient(API_BASE_URL);

// API Endpoints
export const API_ENDPOINTS = {
  // Auth
  AUTH: {
    LOGIN: '/auth/login',
    LOGOUT: '/auth/logout',
    REFRESH: '/auth/refresh',
    PROFILE: '/auth/profile',
  },
  
  // Dashboard
  DASHBOARD: {
    STATS: '/dashboard/stats',
    HEALTH: '/dashboard/health',
    ACTIVITY: '/dashboard/activity',
  },
  
  // Data Catalog
  CATALOG: {
    ASSETS: '/catalog/assets',
    ASSET: (id: string) => `/catalog/assets/${id}`,
    SEARCH: '/catalog/search',
    TAGS: '/catalog/tags',
  },
  
  // Pipelines
  PIPELINES: {
    LIST: '/pipelines',
    DETAIL: (id: string) => `/pipelines/${id}`,
    RUNS: (id: string) => `/pipelines/${id}/runs`,
    START: (id: string) => `/pipelines/${id}/start`,
    STOP: (id: string) => `/pipelines/${id}/stop`,
    PAUSE: (id: string) => `/pipelines/${id}/pause`,
  },
  
  // Analytics
  ANALYTICS: {
    METRICS: '/analytics/metrics',
    CHARTS: '/analytics/charts',
    REPORTS: '/analytics/reports',
  },
  
  // Governance
  GOVERNANCE: {
    POLICIES: '/governance/policies',
    CLASSIFICATIONS: '/governance/classifications',
    ACCESS: '/governance/access',
    AUDIT: '/governance/audit',
  },
  
  // Settings
  SETTINGS: {
    USER: '/settings/user',
    SYSTEM: '/settings/system',
    NOTIFICATIONS: '/settings/notifications',
  },
} as const;