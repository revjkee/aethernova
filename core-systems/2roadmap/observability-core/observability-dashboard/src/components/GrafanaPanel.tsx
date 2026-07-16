import React from 'react';

interface GrafanaPanelProps {
  dashboardUid: string;
  panelId: number;
  title?: string;
  width?: number;
  height?: number;
  theme?: 'light' | 'dark';
  timeRange?: {
    from: string;
    to: string;
  };
  className?: string;
}

const GrafanaPanel: React.FC<GrafanaPanelProps> = ({
  dashboardUid,
  panelId,
  title,
  width = 800,
  height = 400,
  theme = 'light',
  timeRange = { from: 'now-1h', to: 'now' },
  className = '',
}) => {
  const params = new URLSearchParams({
    orgId: '1',
    theme,
    width: width.toString(),
    height: height.toString(),
    from: timeRange.from,
    to: timeRange.to,
    panelId: panelId.toString(),
  });

  const embedUrl = `/api/grafana/d-solo/${dashboardUid}?${params.toString()}`;

  return (
    <div className={`grafana-panel-container ${className}`}>
      {title && (
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          {title}
        </h3>
      )}
      <div className="relative bg-gray-100 dark:bg-gray-700 rounded-lg overflow-hidden">
        <iframe
          src={embedUrl}
          width="100%"
          height={height}
          frameBorder="0"
          title={title || `Grafana Panel ${panelId}`}
          className="w-full"
          onError={(e) => {
            console.error('Failed to load Grafana panel:', e);
          }}
        />
        <div className="absolute top-2 right-2">
          <a
            href={`/api/grafana/d/${dashboardUid}?${params.toString()}`}
            target="_blank"
            rel="noopener noreferrer"
            className="bg-black bg-opacity-50 text-white px-2 py-1 rounded text-xs hover:bg-opacity-70 transition-opacity"
          >
            Open in Grafana
          </a>
        </div>
      </div>
    </div>
  );
};

export default GrafanaPanel;