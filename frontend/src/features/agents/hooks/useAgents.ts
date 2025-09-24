import { useState, useEffect } from 'react';

export function useAgents() {
  const [agents, setAgents] = useState<any[]>([]);
  useEffect(() => {
    setAgents([]);
  }, []);
  return { agents };
}

export default useAgents

