import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronRightIcon } from '@heroicons/react/20/solid';

const pathNames: Record<string, string> = {
  '': 'Dashboard',
  'catalog': 'Data Catalog',
  'pipelines': 'Pipelines',
  'analytics': 'Analytics',
  'governance': 'Governance',
  'settings': 'Settings',
};

export const Breadcrumbs: React.FC = () => {
  const location = useLocation();
  const pathSegments = location.pathname.split('/').filter(Boolean);

  if (pathSegments.length === 0) {
    return null;
  }

  return (
    <nav className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700" aria-label="Breadcrumb">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center space-x-4 py-3">
          <Link
            to="/"
            className="text-sm font-medium text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
          >
            Dashboard
          </Link>
          
          {pathSegments.map((segment, index) => {
            const path = '/' + pathSegments.slice(0, index + 1).join('/');
            const isLast = index === pathSegments.length - 1;
            const name = pathNames[segment] || segment;

            return (
              <React.Fragment key={path}>
                <ChevronRightIcon className="h-5 w-5 text-gray-400" />
                {isLast ? (
                  <span className="text-sm font-medium text-gray-900 dark:text-white">
                    {name}
                  </span>
                ) : (
                  <Link
                    to={path}
                    className="text-sm font-medium text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                  >
                    {name}
                  </Link>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </nav>
  );
};
