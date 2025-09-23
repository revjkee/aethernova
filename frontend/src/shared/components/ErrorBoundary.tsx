import React from 'react';
export class ErrorBoundary extends React.Component<{children: React.ReactNode}> {
  render() { return this.props.children; }
}
