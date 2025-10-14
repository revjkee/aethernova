import React from 'react';

const App: React.FC = () => {
  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#f3f4f6', padding: '20px' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        <header style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', marginBottom: '20px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
          <h1 style={{ margin: 0, fontSize: '32px', fontWeight: 'bold', color: '#1f2937' }}>
            DataFabric Core
          </h1>
          <p style={{ margin: '8px 0 0', color: '#6b7280' }}>
            Enterprise Data Management Platform
          </p>
        </header>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px', marginBottom: '20px' }}>
          <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
            <h3 style={{ margin: '0 0 8px', fontSize: '18px', fontWeight: '600', color: '#1f2937' }}>Active Data Sources</h3>
            <p style={{ margin: 0, fontSize: '32px', fontWeight: 'bold', color: '#3b82f6' }}>24</p>
          </div>
          <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
            <h3 style={{ margin: '0 0 8px', fontSize: '18px', fontWeight: '600', color: '#1f2937' }}>Running Pipelines</h3>
            <p style={{ margin: 0, fontSize: '32px', fontWeight: 'bold', color: '#10b981' }}>12</p>
          </div>
          <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
            <h3 style={{ margin: '0 0 8px', fontSize: '18px', fontWeight: '600', color: '#1f2937' }}>Data Quality</h3>
            <p style={{ margin: 0, fontSize: '32px', fontWeight: 'bold', color: '#8b5cf6' }}>98.5%</p>
          </div>
          <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
            <h3 style={{ margin: '0 0 8px', fontSize: '18px', fontWeight: '600', color: '#1f2937' }}>Active Alerts</h3>
            <p style={{ margin: 0, fontSize: '32px', fontWeight: 'bold', color: '#ef4444' }}>3</p>
          </div>
        </div>

        <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
          <h2 style={{ margin: '0 0 16px', fontSize: '24px', fontWeight: '600', color: '#1f2937' }}>
            System Status
          </h2>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{ width: '12px', height: '12px', backgroundColor: '#10b981', borderRadius: '50%', margin: '0 8px 0 0' }}></div>
            <span style={{ color: '#10b981', fontWeight: '500' }}>All Systems Operational</span>
          </div>
          <p style={{ margin: 0, color: '#6b7280' }}>
            DataFabric Core is running smoothly. All data processing pipelines are active and monitoring systems are operational.
          </p>
        </div>
      </div>
    </div>
  );
};

export default App;