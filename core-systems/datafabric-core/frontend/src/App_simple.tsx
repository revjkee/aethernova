import React from 'react';

const App: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">
          DataFabric Core
        </h1>
        <p className="text-lg text-gray-600 mb-8">
          Enterprise Data Management Platform
        </p>
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md">
          <h2 className="text-2xl font-semibold text-gray-800 mb-4">
            System Status
          </h2>
          <div className="flex items-center justify-center mb-4">
            <div className="w-4 h-4 bg-green-500 rounded-full mr-2"></div>
            <span className="text-green-600 font-medium">Online</span>
          </div>
          <p className="text-gray-600">
            Ready for data operations
          </p>
        </div>
      </div>
    </div>
  );
};

export default App;