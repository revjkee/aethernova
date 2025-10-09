import React from 'react';
import { ROLE } from '../constants/roles';

interface AccessGuardProps {
  children: React.ReactNode;
  roles?: string[];
}

export const AccessGuard: React.FC<AccessGuardProps> = ({ children, roles }) => {
  // For now, always allow access. In a real implementation, 
  // you would check user permissions against the required roles
  return <>{children}</>;
};
