// Date formatting utilities
export const formatDate = (date: string | Date, format: 'short' | 'medium' | 'long' | 'relative' = 'medium'): string => {
  const dateObj = new Date(date);
  
  if (isNaN(dateObj.getTime())) {
    return 'Invalid Date';
  }

  const now = new Date();
  const diffInMs = now.getTime() - dateObj.getTime();
  const diffInMinutes = Math.floor(diffInMs / (1000 * 60));
  const diffInHours = Math.floor(diffInMinutes / 60);
  const diffInDays = Math.floor(diffInHours / 24);

  switch (format) {
    case 'relative':
      if (diffInMinutes < 1) return 'just now';
      if (diffInMinutes < 60) return `${diffInMinutes} min ago`;
      if (diffInHours < 24) return `${diffInHours} hour${diffInHours > 1 ? 's' : ''} ago`;
      if (diffInDays < 7) return `${diffInDays} day${diffInDays > 1 ? 's' : ''} ago`;
      return dateObj.toLocaleDateString();
    
    case 'short':
      return dateObj.toLocaleDateString();
    
    case 'long':
      return dateObj.toLocaleDateString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    
    case 'medium':
    default:
      return dateObj.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
  }
};

// Duration formatting
export const formatDuration = (milliseconds: number): string => {
  const seconds = Math.floor(milliseconds / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) {
    return `${days}d ${hours % 24}h ${minutes % 60}m`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
};

// Parse duration string (e.g., "1h 30m", "45 min", "2 hours")
export const parseDuration = (durationStr: string): number => {
  const patterns = [
    { regex: /(\d+)d/i, multiplier: 24 * 60 * 60 * 1000 },
    { regex: /(\d+)h/i, multiplier: 60 * 60 * 1000 },
    { regex: /(\d+)m/i, multiplier: 60 * 1000 },
    { regex: /(\d+)s/i, multiplier: 1000 },
  ];

  let totalMs = 0;
  
  for (const pattern of patterns) {
    const match = durationStr.match(pattern.regex);
    if (match) {
      totalMs += parseInt(match[1]) * pattern.multiplier;
    }
  }

  return totalMs;
};

// Time zone utilities
export const formatInTimezone = (date: string | Date, timezone: string = 'UTC'): string => {
  const dateObj = new Date(date);
  return dateObj.toLocaleString('en-US', {
    timeZone: timezone,
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
};

// Get business days between two dates
export const getBusinessDaysBetween = (startDate: Date, endDate: Date): number => {
  let count = 0;
  const currentDate = new Date(startDate);
  
  while (currentDate <= endDate) {
    const dayOfWeek = currentDate.getDay();
    if (dayOfWeek !== 0 && dayOfWeek !== 6) { // Not Sunday (0) or Saturday (6)
      count++;
    }
    currentDate.setDate(currentDate.getDate() + 1);
  }
  
  return count;
};

// Check if date is within business hours
export const isBusinessHours = (date: Date, startHour: number = 9, endHour: number = 17): boolean => {
  const hour = date.getHours();
  const dayOfWeek = date.getDay();
  return dayOfWeek >= 1 && dayOfWeek <= 5 && hour >= startHour && hour < endHour;
};

// Get next business day
export const getNextBusinessDay = (date: Date = new Date()): Date => {
  const nextDay = new Date(date);
  nextDay.setDate(nextDay.getDate() + 1);
  
  while (nextDay.getDay() === 0 || nextDay.getDay() === 6) {
    nextDay.setDate(nextDay.getDate() + 1);
  }
  
  return nextDay;
};

// Date range utilities
export const getDateRange = (range: '1d' | '7d' | '30d' | '90d' | '1y'): { start: Date; end: Date } => {
  const end = new Date();
  const start = new Date();
  
  switch (range) {
    case '1d':
      start.setDate(start.getDate() - 1);
      break;
    case '7d':
      start.setDate(start.getDate() - 7);
      break;
    case '30d':
      start.setDate(start.getDate() - 30);
      break;
    case '90d':
      start.setDate(start.getDate() - 90);
      break;
    case '1y':
      start.setFullYear(start.getFullYear() - 1);
      break;
  }
  
  return { start, end };
};