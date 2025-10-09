// Zustand store для управления состоянием приложения
import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import { AgentStatus, Task, SystemMetrics } from './api';

export interface AppState {
  // UI state
  theme: 'light' | 'dark';
  sidebarCollapsed: boolean;
  currentPage: string;
  
  // System state
  isConnected: boolean;
  systemStatus: 'healthy' | 'degraded' | 'error';
  
  // Data state
  agents: AgentStatus[];
  tasks: Task[];
  systemMetrics: SystemMetrics | null;
  
  // Loading states
  loading: {
    agents: boolean;
    tasks: boolean;
    metrics: boolean;
  };
  
  // Error states
  errors: {
    agents?: string;
    tasks?: string;
    metrics?: string;
  };
  
  // Actions
  setTheme: (theme: 'light' | 'dark') => void;
  toggleSidebar: () => void;
  setCurrentPage: (page: string) => void;
  setConnected: (connected: boolean) => void;
  setSystemStatus: (status: 'healthy' | 'degraded' | 'error') => void;
  
  // Data actions
  setAgents: (agents: AgentStatus[]) => void;
  updateAgent: (agent: AgentStatus) => void;
  removeAgent: (agentId: string) => void;
  
  setTasks: (tasks: Task[]) => void;
  updateTask: (task: Task) => void;
  removeTask: (taskId: string) => void;
  
  setSystemMetrics: (metrics: SystemMetrics) => void;
  
  // Loading actions
  setLoading: (key: keyof AppState['loading'], loading: boolean) => void;
  
  // Error actions
  setError: (key: keyof AppState['errors'], error: string | undefined) => void;
  clearErrors: () => void;
}

export const useAppStore = create<AppState>()(
  subscribeWithSelector((set, get) => ({
    // Initial state
    theme: (localStorage.getItem('theme') as 'light' | 'dark') || 'light',
    sidebarCollapsed: localStorage.getItem('sidebarCollapsed') === 'true',
    currentPage: 'dashboard',
    
    isConnected: false,
    systemStatus: 'healthy',
    
    agents: [],
    tasks: [],
    systemMetrics: null,
    
    loading: {
      agents: false,
      tasks: false,
      metrics: false,
    },
    
    errors: {},
    
    // UI actions
    setTheme: (theme) => {
      localStorage.setItem('theme', theme);
      document.documentElement.classList.toggle('dark', theme === 'dark');
      set({ theme });
    },
    
    toggleSidebar: () => {
      const collapsed = !get().sidebarCollapsed;
      localStorage.setItem('sidebarCollapsed', collapsed.toString());
      set({ sidebarCollapsed: collapsed });
    },
    
    setCurrentPage: (page) => set({ currentPage: page }),
    
    setConnected: (connected) => set({ isConnected: connected }),
    
    setSystemStatus: (status) => set({ systemStatus: status }),
    
    // Data actions
    setAgents: (agents) => set({ agents }),
    
    updateAgent: (updatedAgent) =>
      set((state) => ({
        agents: state.agents.map((agent) =>
          agent.id === updatedAgent.id ? updatedAgent : agent
        ),
      })),
    
    removeAgent: (agentId) =>
      set((state) => ({
        agents: state.agents.filter((agent) => agent.id !== agentId),
      })),
    
    setTasks: (tasks) => set({ tasks }),
    
    updateTask: (updatedTask) =>
      set((state) => ({
        tasks: state.tasks.map((task) =>
          task.id === updatedTask.id ? updatedTask : task
        ),
      })),
    
    removeTask: (taskId) =>
      set((state) => ({
        tasks: state.tasks.filter((task) => task.id !== taskId),
      })),
    
    setSystemMetrics: (metrics) => set({ systemMetrics: metrics }),
    
    // Loading actions
    setLoading: (key, loading) =>
      set((state) => ({
        loading: { ...state.loading, [key]: loading },
      })),
    
    // Error actions
    setError: (key, error) =>
      set((state) => ({
        errors: { ...state.errors, [key]: error },
      })),
    
    clearErrors: () => set({ errors: {} }),
  }))
);

// Initialize theme on app start
const theme = useAppStore.getState().theme;
document.documentElement.classList.toggle('dark', theme === 'dark');