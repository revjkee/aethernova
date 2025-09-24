// UXContext.js
// TeslaAI Genesis — Промышленный уровень. Реактивный глобальный UX-контекст.
// Обеспечивает управление UI-состоянием, приоритетами и событиями в 3D-интерфейсах.

import React, {
  createContext,
  useContext,
  useReducer,
  useMemo,
  useCallback,
  useEffect
} from 'react';

// ==== UX События и Типы Состояний ====
const UXEvents = {
  OPEN_MENU: 'OPEN_MENU',
  CLOSE_MENU: 'CLOSE_MENU',
  TOGGLE_MENU: 'TOGGLE_MENU',
  SET_THEME: 'SET_THEME',
  SET_LANGUAGE: 'SET_LANGUAGE',
  SET_ACCESSIBILITY: 'SET_ACCESSIBILITY',
  SET_FOCUS_ELEMENT: 'SET_FOCUS_ELEMENT',
  LOG_INTERACTION: 'LOG_INTERACTION',
};

const initialState = {
  activeMenu: null,
  theme: 'dark',
  language: 'en',
  accessibility: {
    fontScale: 1.0,
    highContrast: false,
    screenReader: false,
  },
  focusElement: null,
  eventLog: [],
};

// ==== Редуктор: управление состоянием ====
function uxReducer(state, action) {
  switch (action.type) {
    case UXEvents.OPEN_MENU:
      return { ...state, activeMenu: action.payload };
    case UXEvents.CLOSE_MENU:
      return { ...state, activeMenu: null };
    case UXEvents.TOGGLE_MENU:
      return {
        ...state,
        activeMenu: state.activeMenu === action.payload ? null : action.payload,
      };
    case UXEvents.SET_THEME:
      return { ...state, theme: action.payload };
    case UXEvents.SET_LANGUAGE:
      return { ...state, language: action.payload };
    case UXEvents.SET_ACCESSIBILITY:
      return {
        ...state,
        accessibility: { ...state.accessibility, ...action.payload },
      };
    case UXEvents.SET_FOCUS_ELEMENT:
      return { ...state, focusElement: action.payload };
    case UXEvents.LOG_INTERACTION:
      return {
        ...state,
        eventLog: [...state.eventLog, { timestamp: Date.now(), ...action.payload }],
      };
    default:
      return state;
  }
}

// ==== Контекст и Провайдер ====
const UXContext = createContext();
export const useUX = () => useContext(UXContext);

// ==== UX Provider с метауправлением ====
export function UXProvider({ children }) {
  const [state, dispatch] = useReducer(uxReducer, initialState);

  const actions = useMemo(() => ({
    openMenu: menuId => dispatch({ type: UXEvents.OPEN_MENU, payload: menuId }),
    closeMenu: () => dispatch({ type: UXEvents.CLOSE_MENU }),
    toggleMenu: menuId => dispatch({ type: UXEvents.TOGGLE_MENU, payload: menuId }),
    setTheme: theme => dispatch({ type: UXEvents.SET_THEME, payload: theme }),
    setLanguage: lang => dispatch({ type: UXEvents.SET_LANGUAGE, payload: lang }),
    setAccessibility: data => dispatch({ type: UXEvents.SET_ACCESSIBILITY, payload: data }),
    setFocus: el => dispatch({ type: UXEvents.SET_FOCUS_ELEMENT, payload: el }),
    logInteraction: meta => dispatch({ type: UXEvents.LOG_INTERACTION, payload: meta }),
  }), []);

  const value = useMemo(() => ({ state, actions }), [state, actions]);

  // ==== DevTools / Аналитика / Мониторинг ====
  useEffect(() => {
    if (process.env.NODE_ENV === 'development') {
      console.debug('[UXContext] State updated:', state);
    }
  }, [state]);

  return (
    <UXContext.Provider value={value}>
      {children}
    </UXContext.Provider>
  );
}
