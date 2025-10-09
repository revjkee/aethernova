import React from 'react';
import { Settings as SettingsIcon, User, Shield, Bell, Palette, Database, Cpu } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const Settings: React.FC = () => {
  const settingsCategories = [
    {
      title: 'Профиль пользователя',
      description: 'Управление аккаунтом и персональными настройками',
      icon: User,
      items: [
        'Информация о пользователе',
        'Смена пароля',
        'Уведомления по email',
        'Языковые настройки'
      ]
    },
    {
      title: 'Безопасность',
      description: 'Настройки безопасности и доступа',
      icon: Shield,
      items: [
        'Двухфакторная аутентификация',
        'API ключи',
        'Журнал активности',
        'Права доступа'
      ]
    },
    {
      title: 'Уведомления',
      description: 'Управление системными уведомлениями',
      icon: Bell,
      items: [
        'Push уведомления',
        'Email оповещения',
        'Уведомления агентов',
        'Критические события'
      ]
    },
    {
      title: 'Интерфейс',
      description: 'Настройка внешнего вида приложения',
      icon: Palette,
      items: [
        'Тема оформления',
        'Размер шрифта',
        'Компактный режим',
        'Цветовые схемы'
      ]
    },
    {
      title: 'Система',
      description: 'Общие системные настройки',
      icon: Cpu,
      items: [
        'Лимиты производительности',
        'Автосохранение',
        'Резервное копирование',
        'Логирование'
      ]
    },
    {
      title: 'База данных',
      description: 'Управление хранением данных',
      icon: Database,
      items: [
        'Подключения к БД',
        'Очистка логов',
        'Индексация',
        'Миграции'
      ]
    }
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Настройки системы
        </h1>
        <p className="text-gray-600">
          Конфигурация и персонализация AetherNova
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {settingsCategories.map((category) => {
          const Icon = category.icon;
          
          return (
            <Card key={category.title} className="hover:shadow-lg transition-shadow">
              <CardHeader className="pb-3">
                <div className="flex items-center space-x-3">
                  <div className="bg-blue-100 p-2 rounded-lg">
                    <Icon className="w-5 h-5 text-blue-600" />
                  </div>
                  <div>
                    <CardTitle className="text-lg">{category.title}</CardTitle>
                    <CardDescription className="text-sm">
                      {category.description}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              
              <CardContent>
                <div className="space-y-3">
                  <ul className="space-y-2">
                    {category.items.map((item, index) => (
                      <li key={index} className="flex items-center justify-between text-sm">
                        <span className="text-gray-700">{item}</span>
                        <Button size="sm" variant="ghost" className="h-6 px-2 text-xs">
                          Настроить
                        </Button>
                      </li>
                    ))}
                  </ul>
                  
                  <div className="pt-3 border-t border-gray-100">
                    <Button size="sm" variant="outline" className="w-full">
                      Открыть все настройки
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* System Status */}
      <div className="mt-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <SettingsIcon className="w-5 h-5" />
              <span>Статус системы</span>
            </CardTitle>
            <CardDescription>Текущая конфигурация и состояние</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <p className="text-2xl font-bold text-green-600">4</p>
                <p className="text-sm text-gray-500">Активных агента</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-blue-600">98%</p>
                <p className="text-sm text-gray-500">Время работы</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-purple-600">v1.2.0</p>
                <p className="text-sm text-gray-500">Версия системы</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <div className="mt-6 flex flex-wrap gap-4">
        <Button variant="outline">
          Экспорт настроек
        </Button>
        <Button variant="outline">
          Импорт конфигурации
        </Button>
        <Button variant="outline">
          Сброс к заводским
        </Button>
        <Button>
          Сохранить изменения
        </Button>
      </div>
    </div>
  );
};

export default Settings;
