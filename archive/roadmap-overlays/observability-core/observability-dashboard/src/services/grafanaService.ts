import axios from 'axios';

export interface GrafanaPanel {
  id: number;
  title: string;
  type: string;
  datasource: string;
  targets: any[];
  gridPos: {
    h: number;
    w: number;
    x: number;
    y: number;
  };
}

export interface GrafanaDashboard {
  id?: number;
  uid: string;
  title: string;
  tags: string[];
  panels: GrafanaPanel[];
  time: {
    from: string;
    to: string;
  };
  refresh: string;
}

class GrafanaService {
  private baseUrl: string;
  private apiKey?: string;

  constructor(baseUrl: string = '/api/grafana', apiKey?: string) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  private getHeaders() {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    
    return headers;
  }

  /**
   * Get dashboard by UID
   */
  async getDashboard(uid: string): Promise<GrafanaDashboard> {
    try {
      const response = await axios.get(`${this.baseUrl}/api/dashboards/uid/${uid}`, {
        headers: this.getHeaders(),
      });
      return response.data.dashboard;
    } catch (error) {
      console.error('Failed to fetch dashboard:', error);
      throw error;
    }
  }

  /**
   * Get panel data for embedding
   */
  async getPanelEmbedUrl(
    dashboardUid: string, 
    panelId: number, 
    options: {
      orgId?: number;
      theme?: 'light' | 'dark';
      width?: number;
      height?: number;
      from?: string;
      to?: string;
    } = {}
  ): Promise<string> {
    const {
      orgId = 1,
      theme = 'light',
      width = 800,
      height = 400,
      from = 'now-1h',
      to = 'now'
    } = options;

    const params = new URLSearchParams({
      orgId: orgId.toString(),
      theme,
      width: width.toString(),
      height: height.toString(),
      from,
      to,
      panelId: panelId.toString(),
    });

    return `${this.baseUrl}/d-solo/${dashboardUid}?${params.toString()}`;
  }

  /**
   * Search dashboards
   */
  async searchDashboards(query: string = '', tags: string[] = []): Promise<any[]> {
    try {
      const params = new URLSearchParams();
      if (query) params.append('query', query);
      if (tags.length > 0) params.append('tag', tags.join(','));

      const response = await axios.get(`${this.baseUrl}/api/search?${params.toString()}`, {
        headers: this.getHeaders(),
      });
      return response.data;
    } catch (error) {
      console.error('Failed to search dashboards:', error);
      throw error;
    }
  }

  /**
   * Get datasources
   */
  async getDatasources(): Promise<any[]> {
    try {
      const response = await axios.get(`${this.baseUrl}/api/datasources`, {
        headers: this.getHeaders(),
      });
      return response.data;
    } catch (error) {
      console.error('Failed to fetch datasources:', error);
      throw error;
    }
  }

  /**
   * Execute query against datasource
   */
  async queryDatasource(
    datasourceId: number,
    query: any,
    range: { from: string; to: string }
  ): Promise<any> {
    try {
      const response = await axios.post(
        `${this.baseUrl}/api/ds/query`,
        {
          queries: [
            {
              ...query,
              datasource: { uid: datasourceId },
            },
          ],
          from: range.from,
          to: range.to,
        },
        {
          headers: this.getHeaders(),
        }
      );
      return response.data;
    } catch (error) {
      console.error('Failed to query datasource:', error);
      throw error;
    }
  }
}

export default GrafanaService;