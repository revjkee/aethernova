import { configureStore } from '@reduxjs/toolkit';

export const store = configureStore({
  reducer: {
    // Добавим слайсы позже
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST'],
      },
    }),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;