import React from 'react';
import { clsx } from 'clsx';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  size?: 'sm' | 'md';
  dot?: boolean;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  size = 'md',
  dot = false,
  className
}) => {
  const baseClasses = 'inline-flex items-center font-medium rounded-full';
  
  const variantClasses = {
    default: 'bg-gray-100 text-gray-800',
    success: 'bg-green-100 text-green-800',
    warning: 'bg-yellow-100 text-yellow-800',
    danger: 'bg-red-100 text-red-800',
    info: 'bg-blue-100 text-blue-800'
  };

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-sm'
  };

  const dotClasses = {
    default: 'bg-gray-400',
    success: 'bg-green-500',
    warning: 'bg-yellow-500',
    danger: 'bg-red-500',
    info: 'bg-blue-500'
  };

  return (
    <span
      className={clsx(
        baseClasses,
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
    >
      {dot && (
        <span
          className={clsx(
            'w-1.5 h-1.5 rounded-full mr-1.5',
            dotClasses[variant]
          )}
        />
      )}
      {children}
    </span>
  );
};

interface StatusBadgeProps {
  status: 'connected' | 'disconnected' | 'error' | 'syncing' | 'running' | 'stopped' | 'paused' | 'healthy' | 'warning' | 'critical';
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  className
}) => {
  const statusConfig = {
    connected: { variant: 'success' as const, label: 'Connected', dot: true },
    disconnected: { variant: 'default' as const, label: 'Disconnected', dot: true },
    error: { variant: 'danger' as const, label: 'Error', dot: true },
    syncing: { variant: 'info' as const, label: 'Syncing', dot: true },
    running: { variant: 'success' as const, label: 'Running', dot: true },
    stopped: { variant: 'default' as const, label: 'Stopped', dot: true },
    paused: { variant: 'warning' as const, label: 'Paused', dot: true },
    healthy: { variant: 'success' as const, label: 'Healthy', dot: true },
    warning: { variant: 'warning' as const, label: 'Warning', dot: true },
    critical: { variant: 'danger' as const, label: 'Critical', dot: true }
  };

  const config = statusConfig[status];

  return (
    <Badge
      variant={config.variant}
      dot={config.dot}
      className={className}
    >
      {config.label}
    </Badge>
  );
};