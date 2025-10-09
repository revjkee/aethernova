import React, { useState, useEffect } from 'react';
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { AlertTriangle, CheckCircle, Clock, Cpu, Refresh, PlayCircle, PauseCircle } from 'lucide-react';
import { api, type Agent } from '@/lib/newApi';
import { wsClient, type AgentStatusUpdate } from '@/lib/newWebSocket';
import { Alert, AlertDescription } from '@/components/ui/alert';

// Additional types for component state
interface ComponentAgent extends Agent {
  performance?: number;
}

const Agents: React.FC = () => {
  const [agents, setAgents] = useState<ComponentAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadAgents();
    connectWebSocket();
    
    return () => {
      wsClient.disconnect();
    };
  }, []);

  const loadAgents = async () => {
    try {
      setLoading(true);
      const agentList = await api.agents.list();
      setAgents(agentList);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки агентов');
    } finally {
      setLoading(false);
    }
  };

  const connectWebSocket = async () => {
    try {
      await wsClient.connect();
      
      // Subscribe to agent status updates
      wsClient.onAgentStatusChange((update: AgentStatusUpdate) => {
        setAgents(prev => prev.map(agent => 
          agent.id === update.agent_id 
            ? { ...agent, status: update.status as Agent['status'] }
            : agent
        ));
      });
    } catch (err) {
      console.error('WebSocket connection failed:', err);
    }
  };

  const handleStartAgent = async (agentId: string) => {
    try {
      await api.agents.start(agentId);
      await loadAgents();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка запуска агента');
    }
  };

  const handleStopAgent = async (agentId: string) => {
    try {
      await api.agents.stop(agentId);
      await loadAgents();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка остановки агента');
    }
  };

  const getStatusIcon = (status: Agent['status']) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="w-4 h-4 text-green-600" />;
      case 'idle':
        return <Clock className="w-4 h-4 text-yellow-600" />;
      case 'error':
        return <AlertTriangle className="w-4 h-4 text-red-600" />;
      default:
        return <Cpu className="w-4 h-4 text-gray-600" />;
    }
  };

  const getStatusColor = (status: Agent['status']) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800';
      case 'idle':
        return 'bg-yellow-100 text-yellow-800';
      case 'error':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getTypeIcon = (type: Agent['type']) => {
    switch (type) {
      case 'development':
        return '💻';
      case 'planning':
        return '📋';
      case 'security':
        return '🔒';
      case 'research':
        return '🔍';
      default:
        return '🤖';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Агентная система
          </h1>
          <p className="text-gray-600">
            Управление и мониторинг ИИ агентов
          </p>
        </div>
        <Button onClick={loadAgents} variant="outline" size="sm">
          <Refresh className="w-4 h-4 mr-2" />
          Обновить
        </Button>
      </div>

      {error && (
        <Alert className="mb-6 border-red-200 bg-red-50">
          <AlertTriangle className="h-4 w-4 text-red-600" />
          <AlertDescription className="text-red-800">
            {error}
          </AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {agents.map((agent) => (
          <Card key={agent.id} className="hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className="text-2xl">{getTypeIcon(agent.type)}</span>
                  <div>
                    <CardTitle className="text-lg">{agent.name}</CardTitle>
                    <CardDescription className="capitalize">
                      {agent.type}
                    </CardDescription>
                  </div>
                </div>
                <Badge 
                  variant="secondary" 
                  className={`${getStatusColor(agent.status)} border-0`}
                >
                  <div className="flex items-center space-x-1">
                    {getStatusIcon(agent.status)}
                    <span className="capitalize">{agent.status}</span>
                  </div>
                </Badge>
              </div>
            </CardHeader>
            
            <CardContent>
              <div className="space-y-4">
                {/* Agent Details */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-500">Версия:</span>
                    <p className="font-medium">{agent.version}</p>
                  </div>
                  <div>
                    <span className="text-gray-500">Конфигурация:</span>
                    <p className="font-medium text-xs">{agent.config_path}</p>
                  </div>
                </div>

                {/* Performance Metrics */}
                {agent.performance && (
                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span className="text-gray-500">Производительность</span>
                      <span className="font-medium">{agent.performance}%</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                        style={{ width: `${agent.performance}%` }}
                      ></div>
                    </div>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex space-x-2 pt-2">
                  {agent.status === 'active' ? (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleStopAgent(agent.id)}
                      className="flex-1"
                    >
                      <PauseCircle className="w-4 h-4 mr-2" />
                      Остановить
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      onClick={() => handleStartAgent(agent.id)}
                      className="flex-1"
                    >
                      <PlayCircle className="w-4 h-4 mr-2" />
                      Запустить
                    </Button>
                  )}
                  <Button size="sm" variant="ghost">
                    Настройки
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {agents.length === 0 && !loading && (
        <div className="text-center py-12">
          <Cpu className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-4 text-lg font-medium text-gray-900">
            Агенты не найдены
          </h3>
          <p className="mt-2 text-gray-500">
            Система агентов не активна или агенты не настроены
          </p>
        </div>
      )}

      {/* Connection Status */}
      <div className="fixed bottom-4 right-4">
        <Badge 
          variant={wsClient.connected ? "default" : "secondary"}
          className={wsClient.connected ? "bg-green-600" : "bg-gray-600"}
        >
          {wsClient.connected ? "🟢 Подключено" : "🔴 Отключено"}
        </Badge>
      </div>
    </div>
  );
};

export default Agents;
