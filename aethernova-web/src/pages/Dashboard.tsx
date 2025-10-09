import React, { useState, useEffect } from 'react';
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
// import { Button } from '@/components/ui/button';
import { 
  Activity, 
  Cpu, 
  Users, 
  CheckCircle2, 
  XCircle, 
  Clock,
  TrendingUp,
  Server,
  Zap,
  AlertTriangle
} from 'lucide-react';
import { api } from '@/lib/newApi';
import { wsClient, type SystemMetrics } from '@/lib/newWebSocket';
import { Alert, AlertDescription } from '@/components/ui/alert';

interface DashboardStats {
  totalAgents: number;
  activeAgents: number;
  totalTasks: number;
  completedTasks: number;
  failedTasks: number;
  systemHealth: 'healthy' | 'warning' | 'critical';
  uptime: string;
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats>({
    totalAgents: 0,
    activeAgents: 0,
    totalTasks: 0,
    completedTasks: 0,
    failedTasks: 0,
    systemHealth: 'healthy',
    uptime: '0m'
  });
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDashboardData();
    connectWebSocket();
    
    return () => {
      wsClient.disconnect();
    };
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // Load agents and calculate stats
      const agents = await api.getAgents();
      const activeAgents = agents.filter(agent => agent.status === 'active').length;
      
      // Load tasks data - mock for now since tasks API not ready
      const tasks: any[] = []; // await api.getTasks();
      const completedTasks = 0; // tasks.filter(task => task.status === 'completed').length;
      const failedTasks = 0; // tasks.filter(task => task.status === 'failed').length;
      
      // Calculate system health
      const errorAgents = agents.filter(agent => agent.status === 'error').length;
      const healthScore = agents.length > 0 ? (activeAgents / agents.length) : 1;
      
      let systemHealth: 'healthy' | 'warning' | 'critical' = 'healthy';
      if (errorAgents > 0 || healthScore < 0.5) {
        systemHealth = 'critical';
      } else if (healthScore < 0.8) {
        systemHealth = 'warning';
      }

      setStats({
        totalAgents: agents.length,
        activeAgents,
        totalTasks: tasks.length,
        completedTasks,
        failedTasks,
        systemHealth,
        uptime: calculateUptime()
      });
      
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки данных');
    } finally {
      setLoading(false);
    }
  };

  const connectWebSocket = async () => {
    try {
      await wsClient.connect();
      
      // Subscribe to system metrics updates
      wsClient.onSystemMetrics((newMetrics: SystemMetrics) => {
        setMetrics(newMetrics);
        
        // Update stats based on metrics
        setStats(prev => ({
          ...prev,
          activeAgents: newMetrics.active_agents,
          totalTasks: newMetrics.total_tasks,
          completedTasks: newMetrics.completed_tasks,
          failedTasks: newMetrics.failed_tasks
        }));
      });
    } catch (err) {
      console.error('WebSocket connection failed:', err);
    }
  };

  const calculateUptime = (): string => {
    // Mock uptime calculation - in real app this would come from backend
    const uptimeMinutes = Math.floor(Math.random() * 1440); // Random uptime up to 24 hours
    const hours = Math.floor(uptimeMinutes / 60);
    const minutes = uptimeMinutes % 60;
    
    if (hours > 0) {
      return `${hours}ч ${minutes}м`;
    }
    return `${minutes}м`;
  };

  const getHealthColor = (health: string) => {
    switch (health) {
      case 'healthy':
        return 'text-green-600 bg-green-100';
      case 'warning':
        return 'text-yellow-600 bg-yellow-100';
      case 'critical':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'healthy':
        return <CheckCircle2 className="w-4 h-4" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4" />;
      case 'critical':
        return <XCircle className="w-4 h-4" />;
      default:
        return <Activity className="w-4 h-4" />;
    }
  };

  const completionRate = stats.totalTasks > 0 
    ? Math.round((stats.completedTasks / stats.totalTasks) * 100) 
    : 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Панель управления
        </h1>
        <p className="text-gray-600">
          Мониторинг системы AetherNova в реальном времени
        </p>
      </div>

      {error && (
        <Alert className="mb-6 border-red-200 bg-red-50">
          <AlertTriangle className="h-4 w-4 text-red-600" />
          <AlertDescription className="text-red-800">
            {error}
          </AlertDescription>
        </Alert>
      )}

      {/* System Health Status */}
      <Card className="mb-6">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              <Server className="w-5 h-5" />
              <span>Состояние системы</span>
            </CardTitle>
            <Badge className={`${getHealthColor(stats.systemHealth)} border-0`}>
              <div className="flex items-center space-x-1">
                {getHealthIcon(stats.systemHealth)}
                <span className="capitalize">
                  {stats.systemHealth === 'healthy' ? 'Здорово' : 
                   stats.systemHealth === 'warning' ? 'Предупреждение' : 'Критическое'}
                </span>
              </div>
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-blue-600">{stats.activeAgents}</p>
              <p className="text-sm text-gray-500">Активных агентов</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-green-600">{completionRate}%</p>
              <p className="text-sm text-gray-500">Успешных задач</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-purple-600">{stats.uptime}</p>
              <p className="text-sm text-gray-500">Время работы</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-orange-600">
                {metrics?.cpu_usage.toFixed(1) || '0.0'}%
              </p>
              <p className="text-sm text-gray-500">Загрузка CPU</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Statistics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        {/* Total Agents */}
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Всего агентов</p>
                <p className="text-2xl font-bold text-gray-900">{stats.totalAgents}</p>
              </div>
              <div className="bg-blue-100 p-3 rounded-full">
                <Users className="w-6 h-6 text-blue-600" />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Active Agents */}
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Активных</p>
                <p className="text-2xl font-bold text-green-600">{stats.activeAgents}</p>
              </div>
              <div className="bg-green-100 p-3 rounded-full">
                <Zap className="w-6 h-6 text-green-600" />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Total Tasks */}
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Всего задач</p>
                <p className="text-2xl font-bold text-gray-900">{stats.totalTasks}</p>
              </div>
              <div className="bg-purple-100 p-3 rounded-full">
                <Activity className="w-6 h-6 text-purple-600" />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Success Rate */}
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Успешность</p>
                <p className="text-2xl font-bold text-orange-600">{completionRate}%</p>
              </div>
              <div className="bg-orange-100 p-3 rounded-full">
                <TrendingUp className="w-6 h-6 text-orange-600" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Performance Metrics */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          {/* CPU Usage */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Cpu className="w-5 h-5" />
                <span>Загрузка процессора</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>CPU</span>
                  <span className="font-medium">{metrics.cpu_usage.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full transition-all duration-300 ${
                      metrics.cpu_usage > 80 ? 'bg-red-500' :
                      metrics.cpu_usage > 60 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${Math.min(metrics.cpu_usage, 100)}%` }}
                  ></div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Memory Usage */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Activity className="w-5 h-5" />
                <span>Использование памяти</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>RAM</span>
                  <span className="font-medium">{metrics.memory_usage.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full transition-all duration-300 ${
                      metrics.memory_usage > 80 ? 'bg-red-500' :
                      metrics.memory_usage > 60 ? 'bg-yellow-500' : 'bg-blue-500'
                    }`}
                    style={{ width: `${Math.min(metrics.memory_usage, 100)}%` }}
                  ></div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Recent Activity Summary */}
      <Card>
        <CardHeader>
          <CardTitle>Сводка активности</CardTitle>
          <CardDescription>Последние события в системе</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between py-2 border-b border-gray-100">
              <div className="flex items-center space-x-3">
                <CheckCircle2 className="w-4 h-4 text-green-600" />
                <span className="text-sm">Задачи выполнены</span>
              </div>
              <Badge variant="secondary">{stats.completedTasks}</Badge>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-gray-100">
              <div className="flex items-center space-x-3">
                <XCircle className="w-4 h-4 text-red-600" />
                <span className="text-sm">Задачи с ошибками</span>
              </div>
              <Badge variant="secondary">{stats.failedTasks}</Badge>
            </div>
            <div className="flex items-center justify-between py-2">
              <div className="flex items-center space-x-3">
                <Clock className="w-4 h-4 text-yellow-600" />
                <span className="text-sm">Задачи в обработке</span>
              </div>
              <Badge variant="secondary">
                {stats.totalTasks - stats.completedTasks - stats.failedTasks}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Connection Status */}
      <div className="fixed bottom-4 right-4">
        <Badge 
          variant={wsClient.connected ? "default" : "secondary"}
          className={wsClient.connected ? "bg-green-600" : "bg-gray-600"}
        >
          {wsClient.connected ? "🟢 Реальное время" : "🔴 Офлайн"}
        </Badge>
      </div>
    </div>
  );
};

export default Dashboard;
