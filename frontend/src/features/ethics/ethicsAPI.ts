export function ethicsAPI() {
  // Заглушка API этики
  return {};
}

export function useEthicsScan() {
  // Простая заглушка хука — в реальном коде здесь будет обращение к API
  return {
    scan: async (text: string) => ({ score: 0, issues: [] }),
  };
}

export function useFlaggedActionsQuery() {
  return {
    data: [],
    loading: false,
  };
}
