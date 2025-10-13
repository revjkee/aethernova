// Local Storage Keys
export const STORAGE_KEYS = {
  AUTH_TOKEN: 'auth_token',
  USER_PREFERENCES: 'user_preferences',
  THEME: 'theme',
  LANGUAGE: 'language',
  DASHBOARD_CONFIG: 'dashboard_config',
  PIPELINE_FILTERS: 'pipeline_filters',
  CATALOG_FILTERS: 'catalog_filters',
} as const;

// Storage Service
class StorageService {
  // Get item from localStorage with optional default value
  get<T>(key: string, defaultValue?: T): T | null {
    try {
      const item = localStorage.getItem(key);
      if (item === null) {
        return defaultValue ?? null;
      }
      return JSON.parse(item);
    } catch (error) {
      console.error(`Error reading from localStorage (${key}):`, error);
      return defaultValue ?? null;
    }
  }

  // Set item in localStorage
  set(key: string, value: any): void {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.error(`Error writing to localStorage (${key}):`, error);
    }
  }

  // Remove item from localStorage
  remove(key: string): void {
    try {
      localStorage.removeItem(key);
    } catch (error) {
      console.error(`Error removing from localStorage (${key}):`, error);
    }
  }

  // Clear all localStorage
  clear(): void {
    try {
      localStorage.clear();
    } catch (error) {
      console.error('Error clearing localStorage:', error);
    }
  }

  // Check if key exists
  exists(key: string): boolean {
    return localStorage.getItem(key) !== null;
  }

  // Get multiple items at once
  getMultiple(keys: string[]): Record<string, any> {
    const result: Record<string, any> = {};
    keys.forEach(key => {
      result[key] = this.get(key);
    });
    return result;
  }

  // Set multiple items at once
  setMultiple(items: Record<string, any>): void {
    Object.entries(items).forEach(([key, value]) => {
      this.set(key, value);
    });
  }
}

// Session Storage Service
class SessionStorageService {
  get<T>(key: string, defaultValue?: T): T | null {
    try {
      const item = sessionStorage.getItem(key);
      if (item === null) {
        return defaultValue ?? null;
      }
      return JSON.parse(item);
    } catch (error) {
      console.error(`Error reading from sessionStorage (${key}):`, error);
      return defaultValue ?? null;
    }
  }

  set(key: string, value: any): void {
    try {
      sessionStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.error(`Error writing to sessionStorage (${key}):`, error);
    }
  }

  remove(key: string): void {
    try {
      sessionStorage.removeItem(key);
    } catch (error) {
      console.error(`Error removing from sessionStorage (${key}):`, error);
    }
  }

  clear(): void {
    try {
      sessionStorage.clear();
    } catch (error) {
      console.error('Error clearing sessionStorage:', error);
    }
  }

  exists(key: string): boolean {
    return sessionStorage.getItem(key) !== null;
  }
}

// User Preferences Service
interface UserPreferences {
  theme: 'light' | 'dark' | 'system';
  language: string;
  timezone: string;
  notifications: {
    email: boolean;
    push: boolean;
    pipeline: boolean;
    quality: boolean;
    security: boolean;
  };
  dashboard: {
    layout: string;
    refreshInterval: number;
    autoRefresh: boolean;
  };
}

class PreferencesService {
  private defaultPreferences: UserPreferences = {
    theme: 'system',
    language: 'en',
    timezone: 'UTC',
    notifications: {
      email: true,
      push: false,
      pipeline: true,
      quality: true,
      security: true,
    },
    dashboard: {
      layout: 'default',
      refreshInterval: 30000,
      autoRefresh: true,
    },
  };

  getPreferences(): UserPreferences {
    return storageService.get(STORAGE_KEYS.USER_PREFERENCES, this.defaultPreferences) || this.defaultPreferences;
  }

  updatePreferences(updates: Partial<UserPreferences>): void {
    const current = this.getPreferences();
    const updated = { ...current, ...updates };
    storageService.set(STORAGE_KEYS.USER_PREFERENCES, updated);
  }

  resetPreferences(): void {
    storageService.set(STORAGE_KEYS.USER_PREFERENCES, this.defaultPreferences);
  }

  getPreference<K extends keyof UserPreferences>(key: K): UserPreferences[K] {
    const preferences = this.getPreferences();
    return preferences[key];
  }

  setPreference<K extends keyof UserPreferences>(key: K, value: UserPreferences[K]): void {
    const preferences = this.getPreferences();
    preferences[key] = value;
    storageService.set(STORAGE_KEYS.USER_PREFERENCES, preferences);
  }
}

// Export service instances
export const storageService = new StorageService();
export const sessionStorageService = new SessionStorageService();
export const preferencesService = new PreferencesService();

// Utility functions
export const clearAllStorages = () => {
  storageService.clear();
  sessionStorageService.clear();
};

export const exportUserData = () => {
  const userData = {
    preferences: preferencesService.getPreferences(),
    dashboardConfig: storageService.get(STORAGE_KEYS.DASHBOARD_CONFIG),
    pipelineFilters: storageService.get(STORAGE_KEYS.PIPELINE_FILTERS),
    catalogFilters: storageService.get(STORAGE_KEYS.CATALOG_FILTERS),
  };
  
  const blob = new Blob([JSON.stringify(userData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `datafabric-settings-${new Date().toISOString().split('T')[0]}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

export const importUserData = (file: File): Promise<void> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const userData = JSON.parse(e.target?.result as string);
        
        if (userData.preferences) {
          preferencesService.updatePreferences(userData.preferences);
        }
        if (userData.dashboardConfig) {
          storageService.set(STORAGE_KEYS.DASHBOARD_CONFIG, userData.dashboardConfig);
        }
        if (userData.pipelineFilters) {
          storageService.set(STORAGE_KEYS.PIPELINE_FILTERS, userData.pipelineFilters);
        }
        if (userData.catalogFilters) {
          storageService.set(STORAGE_KEYS.CATALOG_FILTERS, userData.catalogFilters);
        }
        
        resolve();
      } catch (error) {
        reject(new Error('Invalid file format'));
      }
    };
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
};