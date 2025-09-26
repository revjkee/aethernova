import React from 'react';

export const ZKProofBadge: React.FC = () => {
  return (
    <span
      aria-hidden={false}
      style={{
        display: 'inline-block',
        padding: '0.125rem 0.5rem',
        background: 'linear-gradient(90deg,#eef2ff,#e6fffa)',
        color: '#0f172a',
        borderRadius: 6,
        fontSize: '0.75rem',
        fontWeight: 600,
      }}
    >
      ZK Proof
    </span>
  );
};

export default ZKProofBadge;
