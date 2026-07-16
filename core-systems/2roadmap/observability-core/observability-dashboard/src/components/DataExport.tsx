import React, { useState } from 'react';
import { Download, FileText, Table, Image } from 'lucide-react';

export type ExportFormat = 'csv' | 'json' | 'pdf' | 'png';

export interface ExportOptions {
  format: ExportFormat;
  dateRange: {
    from: Date;
    to: Date;
  };
  includeMetadata: boolean;
  fileName?: string;
}

interface DataExportProps {
  data: any[];
  type: 'metrics' | 'logs' | 'alerts';
  className?: string;
}

const DataExport: React.FC<DataExportProps> = ({ data, type, className = '' }) => {
  const [isExporting, setIsExporting] = useState(false);
  const [exportOptions, setExportOptions] = useState<ExportOptions>({
    format: 'csv',
    dateRange: {
      from: new Date(Date.now() - 24 * 60 * 60 * 1000), // 24 hours ago
      to: new Date(),
    },
    includeMetadata: true,
  });

  const formatOptions = [
    { value: 'csv', label: 'CSV', icon: Table, description: 'Comma-separated values' },
    { value: 'json', label: 'JSON', icon: FileText, description: 'JavaScript Object Notation' },
    { value: 'pdf', label: 'PDF', icon: FileText, description: 'Portable Document Format' },
    { value: 'png', label: 'PNG', icon: Image, description: 'Image format (charts only)' },
  ];

  // Export data to CSV
  const exportToCSV = (data: any[], filename: string) => {
    if (data.length === 0) return;

    const headers = Object.keys(data[0]);
    const csvContent = [
      headers.join(','),
      ...data.map(row =>
        headers.map(header => {
          const value = row[header];
          // Escape commas and quotes in CSV
          if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
            return `"${value.replace(/"/g, '""')}"`;
          }
          return value;
        }).join(',')
      )
    ].join('\n');

    downloadFile(csvContent, filename, 'text/csv');
  };

  // Export data to JSON
  const exportToJSON = (data: any[], filename: string) => {
    const jsonContent = JSON.stringify(data, null, 2);
    downloadFile(jsonContent, filename, 'application/json');
  };

  // Generate PDF report
  const exportToPDF = async (data: any[], filename: string) => {
    // Mock PDF generation
    const pdfContent = generatePDFContent(data);
    downloadFile(pdfContent, filename, 'application/pdf');
  };

  // Generate chart image
  const exportToPNG = async (filename: string) => {
    // Mock chart image generation
    const canvas = document.createElement('canvas');
    canvas.width = 800;
    canvas.height = 600;
    const ctx = canvas.getContext('2d');
    
    if (ctx) {
      // Draw mock chart
      ctx.fillStyle = '#f3f4f6';
      ctx.fillRect(0, 0, 800, 600);
      
      ctx.fillStyle = '#1f2937';
      ctx.font = '24px Arial';
      ctx.fillText(`${type.toUpperCase()} Export`, 50, 50);
      
      ctx.fillStyle = '#6b7280';
      ctx.font = '14px Arial';
      ctx.fillText(`Generated on ${new Date().toLocaleString()}`, 50, 80);
      ctx.fillText(`Total records: ${data.length}`, 50, 100);
    }
    
    canvas.toBlob(blob => {
      if (blob) {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
      }
    });
  };

  // Download file helper
  const downloadFile = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Generate PDF content (mock)
  const generatePDFContent = (_data: any[]) => {
    return `%PDF-1.4
1 0 obj
<<
  /Type /Catalog
  /Pages 2 0 R
>>
endobj

2 0 obj
<<
  /Type /Pages
  /Kids [3 0 R]
  /Count 1
>>
endobj

3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 612 792]
  /Contents 4 0 R
>>
endobj

4 0 obj
<<
  /Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(${type.toUpperCase()} Export Report) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000204 00000 n 
trailer
<<
  /Size 5
  /Root 1 0 R
>>
startxref
297
%%EOF`;
  };

  // Handle export
  const handleExport = async () => {
    if (data.length === 0) {
      alert('No data to export');
      return;
    }

    setIsExporting(true);

    try {
      const timestamp = new Date().toISOString().split('T')[0];
      const defaultFileName = `${type}_export_${timestamp}`;
      const fileName = exportOptions.fileName || defaultFileName;

      switch (exportOptions.format) {
        case 'csv':
          exportToCSV(data, `${fileName}.csv`);
          break;
        case 'json':
          exportToJSON(data, `${fileName}.json`);
          break;
        case 'pdf':
          await exportToPDF(data, `${fileName}.pdf`);
          break;
        case 'png':
          await exportToPNG(`${fileName}.png`);
          break;
      }
    } catch (error) {
      console.error('Export failed:', error);
      alert('Export failed. Please try again.');
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg shadow-md border border-gray-200 dark:border-gray-700 p-6 ${className}`}>
      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
        Export {type.charAt(0).toUpperCase() + type.slice(1)} Data
      </h3>

      {/* Format Selection */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
          Export Format
        </label>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {formatOptions.map(option => {
            const Icon = option.icon;
            return (
              <button
                key={option.value}
                onClick={() => setExportOptions(prev => ({ ...prev, format: option.value as ExportFormat }))}
                className={`p-3 border rounded-lg text-center transition-colors ${
                  exportOptions.format === option.value
                    ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                    : 'border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500'
                }`}
              >
                <Icon className="h-6 w-6 mx-auto mb-2" />
                <div className="text-sm font-medium">{option.label}</div>
                <div className="text-xs text-gray-500 dark:text-gray-400">{option.description}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Date Range */}
      <div className="mb-6 grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            From Date
          </label>
          <input
            type="datetime-local"
            value={exportOptions.dateRange.from.toISOString().slice(0, 16)}
            onChange={(e) =>
              setExportOptions(prev => ({
                ...prev,
                dateRange: { ...prev.dateRange, from: new Date(e.target.value) }
              }))
            }
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            To Date
          </label>
          <input
            type="datetime-local"
            value={exportOptions.dateRange.to.toISOString().slice(0, 16)}
            onChange={(e) =>
              setExportOptions(prev => ({
                ...prev,
                dateRange: { ...prev.dateRange, to: new Date(e.target.value) }
              }))
            }
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500"
          />
        </div>
      </div>

      {/* File Name */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          File Name (optional)
        </label>
        <input
          type="text"
          placeholder={`${type}_export_${new Date().toISOString().split('T')[0]}`}
          value={exportOptions.fileName || ''}
          onChange={(e) =>
            setExportOptions(prev => ({ ...prev, fileName: e.target.value }))
          }
          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-primary-500"
        />
      </div>

      {/* Options */}
      <div className="mb-6">
        <label className="flex items-center">
          <input
            type="checkbox"
            checked={exportOptions.includeMetadata}
            onChange={(e) =>
              setExportOptions(prev => ({ ...prev, includeMetadata: e.target.checked }))
            }
            className="mr-2 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
          />
          <span className="text-sm text-gray-700 dark:text-gray-300">
            Include metadata and additional fields
          </span>
        </label>
      </div>

      {/* Export Button */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-gray-600 dark:text-gray-400">
          {data.length} records available for export
        </div>
        <button
          onClick={handleExport}
          disabled={isExporting || data.length === 0}
          className="flex items-center space-x-2 px-6 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white font-medium rounded-lg transition-colors"
        >
          <Download className={`h-4 w-4 ${isExporting ? 'animate-pulse' : ''}`} />
          <span>{isExporting ? 'Exporting...' : 'Export Data'}</span>
        </button>
      </div>
    </div>
  );
};

export default DataExport;