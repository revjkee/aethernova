import React, { useRef } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  TimeScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler,
  ChartOptions,
  ChartData,
  ArcElement,
} from 'chart.js';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import { Download, Maximize2, MoreHorizontal } from 'lucide-react';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  TimeScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface InteractiveChartProps {
  title: string;
  type: 'line' | 'bar' | 'doughnut';
  data: ChartData<any>;
  options?: ChartOptions<any>;
  height?: number;
  width?: number;
  exportable?: boolean;
  fullscreenable?: boolean;
  className?: string;
}

const InteractiveChart: React.FC<InteractiveChartProps> = ({
  title,
  type,
  data,
  options = {},
  height = 300,
  width,
  exportable = true,
  fullscreenable = true,
  className = '',
}) => {
  const chartRef = useRef<ChartJS | null>(null);

  // Default chart options with dark mode support
  const defaultOptions: ChartOptions<any> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
        labels: {
          usePointStyle: true,
          padding: 20,
          color: 'rgb(156, 163, 175)', // gray-400
        },
      },
      title: {
        display: false, // We handle title separately
      },
      tooltip: {
        backgroundColor: 'rgba(17, 24, 39, 0.8)', // gray-900 with opacity
        titleColor: 'rgb(243, 244, 246)', // gray-100
        bodyColor: 'rgb(209, 213, 219)', // gray-300
        borderColor: 'rgb(75, 85, 99)', // gray-600
        borderWidth: 1,
        cornerRadius: 8,
        displayColors: true,
        padding: 12,
      },
    },
    scales: type !== 'doughnut' ? {
      x: {
        grid: {
          color: 'rgba(75, 85, 99, 0.3)', // gray-600 with opacity
        },
        ticks: {
          color: 'rgb(156, 163, 175)', // gray-400
        },
      },
      y: {
        grid: {
          color: 'rgba(75, 85, 99, 0.3)', // gray-600 with opacity
        },
        ticks: {
          color: 'rgb(156, 163, 175)', // gray-400
        },
      },
    } : undefined,
    animation: {
      duration: 1000,
      easing: 'easeInOutQuart',
    },
    interaction: {
      intersect: false,
      mode: 'index',
    },
  };

  // Merge default options with custom options
  const chartOptions = { ...defaultOptions, ...options };

  // Export chart as image
  const exportChart = () => {
    if (chartRef.current) {
      const url = chartRef.current.toBase64Image();
      const link = document.createElement('a');
      link.download = `${title.toLowerCase().replace(/\s+/g, '_')}_chart.png`;
      link.href = url;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  // Toggle fullscreen
  const toggleFullscreen = () => {
    // Implement fullscreen logic
    console.log('Toggle fullscreen for chart:', title);
  };

  const renderChart = () => {
    const commonProps = {
      data,
      options: chartOptions,
      height,
      width,
    };

    switch (type) {
      case 'line':
        return <Line {...commonProps} ref={chartRef as any} />;
      case 'bar':
        return <Bar {...commonProps} ref={chartRef as any} />;
      case 'doughnut':
        return <Doughnut {...commonProps} ref={chartRef as any} />;
      default:
        return <Line {...commonProps} ref={chartRef as any} />;
    }
  };

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg shadow-md border border-gray-200 dark:border-gray-700 ${className}`}>
      {/* Chart Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          {title}
        </h3>
        <div className="flex items-center space-x-2">
          {exportable && (
            <button
              onClick={exportChart}
              className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              title="Export Chart"
            >
              <Download className="h-4 w-4" />
            </button>
          )}
          {fullscreenable && (
            <button
              onClick={toggleFullscreen}
              className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              title="Fullscreen"
            >
              <Maximize2 className="h-4 w-4" />
            </button>
          )}
          <button className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
            <MoreHorizontal className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Chart Content */}
      <div className="p-4">
        <div style={{ height: `${height}px` }}>
          {renderChart()}
        </div>
      </div>
    </div>
  );
};

export default InteractiveChart;

// Predefined chart configurations for common metrics
export const MetricChartConfigs = {
  // CPU Usage over time
  cpuUsage: (data: number[], labels: string[]): ChartData<'line'> => ({
    labels,
    datasets: [
      {
        label: 'CPU Usage (%)',
        data,
        borderColor: 'rgb(239, 68, 68)', // red-500
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointBackgroundColor: 'rgb(239, 68, 68)',
        pointBorderColor: '#fff',
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
      },
    ],
  }),

  // Memory Usage over time
  memoryUsage: (data: number[], labels: string[]): ChartData<'line'> => ({
    labels,
    datasets: [
      {
        label: 'Memory Usage (%)',
        data,
        borderColor: 'rgb(59, 130, 246)', // blue-500
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointBackgroundColor: 'rgb(59, 130, 246)',
        pointBorderColor: '#fff',
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
      },
    ],
  }),

  // Response time distribution
  responseTime: (data: number[], labels: string[]): ChartData<'bar'> => ({
    labels,
    datasets: [
      {
        label: 'Response Time (ms)',
        data,
        backgroundColor: 'rgba(16, 185, 129, 0.8)', // emerald-500
        borderColor: 'rgb(16, 185, 129)',
        borderWidth: 1,
        borderRadius: 4,
        borderSkipped: false,
      },
    ],
  }),

  // System health distribution
  systemHealth: (healthy: number, warning: number, error: number): ChartData<'doughnut'> => ({
    labels: ['Healthy', 'Warning', 'Error'],
    datasets: [
      {
        data: [healthy, warning, error],
        backgroundColor: [
          'rgb(34, 197, 94)', // green-500
          'rgb(251, 191, 36)', // amber-400
          'rgb(239, 68, 68)', // red-500
        ],
        borderColor: [
          'rgb(21, 128, 61)', // green-700
          'rgb(217, 119, 6)', // amber-600
          'rgb(185, 28, 28)', // red-700
        ],
        borderWidth: 2,
        hoverOffset: 4,
      },
    ],
  }),

  // Agent activity over time
  agentActivity: (activeData: number[], restartData: number[], labels: string[]): ChartData<'line'> => ({
    labels,
    datasets: [
      {
        label: 'Active Agents',
        data: activeData,
        borderColor: 'rgb(34, 197, 94)', // green-500
        backgroundColor: 'rgba(34, 197, 94, 0.1)',
        borderWidth: 2,
        fill: false,
        tension: 0.1,
        yAxisID: 'y',
      },
      {
        label: 'Agent Restarts',
        data: restartData,
        borderColor: 'rgb(251, 191, 36)', // amber-400
        backgroundColor: 'rgba(251, 191, 36, 0.1)',
        borderWidth: 2,
        fill: false,
        tension: 0.1,
        yAxisID: 'y1',
      },
    ],
  }),
};

// Chart options presets
export const ChartOptionsPresets = {
  realTime: {
    animation: {
      duration: 300,
    },
    scales: {
      x: {
        type: 'time' as const,
        time: {
          displayFormats: {
            second: 'HH:mm:ss',
            minute: 'HH:mm',
          },
        },
      },
    },
  },

  zoomable: {
    interaction: {
      intersect: false,
      mode: 'index' as const,
    },
    responsive: true,
    maintainAspectRatio: false,
  },
};