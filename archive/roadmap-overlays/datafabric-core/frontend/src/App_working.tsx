function App() {
  return (
    <div style={{ 
      minHeight: '100vh', 
      backgroundColor: '#f5f5f5', 
      fontFamily: 'Arial, sans-serif',
      padding: '20px'
    }}>
      <header style={{
        backgroundColor: 'white',
        padding: '20px',
        borderRadius: '8px',
        marginBottom: '20px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <h1 style={{ margin: 0, color: '#333' }}>DataFabric Core</h1>
        <p style={{ margin: '5px 0 0', color: '#666' }}>Enterprise Data Management Platform</p>
      </header>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
        gap: '20px',
        marginBottom: '20px'
      }}>
        <div style={{
          backgroundColor: 'white',
          padding: '20px',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h3 style={{ margin: '0 0 10px', color: '#333' }}>Active Data Sources</h3>
          <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#3b82f6' }}>24</div>
        </div>

        <div style={{
          backgroundColor: 'white',
          padding: '20px',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h3 style={{ margin: '0 0 10px', color: '#333' }}>Running Pipelines</h3>
          <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#10b981' }}>12</div>
        </div>

        <div style={{
          backgroundColor: 'white',
          padding: '20px',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h3 style={{ margin: '0 0 10px', color: '#333' }}>Data Quality</h3>
          <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#8b5cf6' }}>98.5%</div>
        </div>

        <div style={{
          backgroundColor: 'white',
          padding: '20px',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h3 style={{ margin: '0 0 10px', color: '#333' }}>Active Alerts</h3>
          <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#ef4444' }}>3</div>
        </div>
      </div>

      <div style={{
        backgroundColor: 'white',
        padding: '20px',
        borderRadius: '8px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <h2 style={{ margin: '0 0 15px', color: '#333' }}>System Status</h2>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
          <div style={{
            width: '12px',
            height: '12px',
            backgroundColor: '#10b981',
            borderRadius: '50%',
            marginRight: '8px'
          }}></div>
          <span style={{ color: '#10b981', fontWeight: 'bold' }}>All Systems Operational</span>
        </div>
        <p style={{ margin: 0, color: '#666' }}>
          DataFabric Core is running smoothly. All data processing pipelines are active.
        </p>
      </div>
    </div>
  );
}

export default App;