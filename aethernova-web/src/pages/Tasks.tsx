import React from 'react';
import { CheckSquare, Clock, AlertTriangle, Plus } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

const Tasks: React.FC = () => {
  const mockTasks = [
    {
      id: '1',
      title: 'Анализ данных пользователей',
      description: 'Провести анализ поведения пользователей за последний месяц',
      status: 'in_progress',
      agent: 'Research Agent',
      priority: 'high',
      created: '2024-01-15',
      deadline: '2024-01-20'
    },
    {
      id: '2',
      title: 'Обновление безопасности',
      description: 'Проверить и обновить системы безопасности',
      status: 'completed',
      agent: 'Security Agent',
      priority: 'critical',
      created: '2024-01-14',
      deadline: '2024-01-16'
    },
    {
      id: '3',
      title: 'Планирование спринта',
      description: 'Составить план разработки на следующий спринт',
      status: 'pending',
      agent: 'Planning Agent',
      priority: 'medium',
      created: '2024-01-15',
      deadline: '2024-01-22'
    }
  ];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckSquare className="w-4 h-4 text-green-600" />;
      case 'in_progress':
        return <Clock className="w-4 h-4 text-blue-600" />;
      case 'pending':
        return <Clock className="w-4 h-4 text-yellow-600" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-red-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'in_progress':
        return 'bg-blue-100 text-blue-800';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-red-100 text-red-800';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical':
        return 'bg-red-100 text-red-800';
      case 'high':
        return 'bg-orange-100 text-orange-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'low':
        return 'bg-green-100 text-green-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Управление задачами
          </h1>
          <p className="text-gray-600">
            Отслеживание и управление задачами агентов
          </p>
        </div>
        <Button>
          <Plus className="w-4 h-4 mr-2" />
          Новая задача
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {mockTasks.map((task) => (
          <Card key={task.id} className="hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between">
                <CardTitle className="text-lg line-clamp-2">
                  {task.title}
                </CardTitle>
                <Badge 
                  variant="secondary" 
                  className={`${getStatusColor(task.status)} border-0 ml-2`}
                >
                  <div className="flex items-center space-x-1">
                    {getStatusIcon(task.status)}
                    <span className="capitalize">
                      {task.status === 'in_progress' ? 'В работе' :
                       task.status === 'completed' ? 'Завершена' :
                       task.status === 'pending' ? 'Ожидает' : task.status}
                    </span>
                  </div>
                </Badge>
              </div>
              <CardDescription>
                {task.description}
              </CardDescription>
            </CardHeader>
            
            <CardContent>
              <div className="space-y-4">
                {/* Task Details */}
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">Агент:</span>
                    <span className="font-medium">{task.agent}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">Приоритет:</span>
                    <Badge 
                      variant="secondary" 
                      className={`${getPriorityColor(task.priority)} text-xs`}
                    >
                      {task.priority === 'critical' ? 'Критический' :
                       task.priority === 'high' ? 'Высокий' :
                       task.priority === 'medium' ? 'Средний' :
                       task.priority === 'low' ? 'Низкий' : task.priority}
                    </Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">Создана:</span>
                    <span className="font-medium">{task.created}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">Дедлайн:</span>
                    <span className="font-medium">{task.deadline}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex space-x-2 pt-2">
                  <Button size="sm" variant="outline" className="flex-1">
                    Подробно
                  </Button>
                  <Button size="sm" variant="ghost">
                    Изменить
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Summary Stats */}
      <div className="mt-8 grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Всего задач</p>
                <p className="text-2xl font-bold text-gray-900">{mockTasks.length}</p>
              </div>
              <CheckSquare className="w-8 h-8 text-gray-400" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">В работе</p>
                <p className="text-2xl font-bold text-blue-600">
                  {mockTasks.filter(t => t.status === 'in_progress').length}
                </p>
              </div>
              <Clock className="w-8 h-8 text-blue-400" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Завершено</p>
                <p className="text-2xl font-bold text-green-600">
                  {mockTasks.filter(t => t.status === 'completed').length}
                </p>
              </div>
              <CheckSquare className="w-8 h-8 text-green-400" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Ожидает</p>
                <p className="text-2xl font-bold text-yellow-600">
                  {mockTasks.filter(t => t.status === 'pending').length}
                </p>
              </div>
              <Clock className="w-8 h-8 text-yellow-400" />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Tasks;
