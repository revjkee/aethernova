// InputContext.js
// TeslaAI Genesis — Промышленный уровень. Контекст управления пользовательским вводом в 3D.

import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useReducer
} from 'react';

const InputEvents = {
  KEY_DOWN: 'KEY_DOWN',
  KEY_UP: 'KEY_UP',
  GAMEPAD_INPUT: 'GAMEPAD_INPUT',
  POINTER_MOVE: 'POINTER_MOVE',
  INPUT_DEVICE_CHANGE: 'INPUT_DEVICE_CHANGE',
  RESET_INPUT_STATE: 'RESET_INPUT_STATE',
};

const initialState = {
  keysPressed: new Set(),
  pointerPosition: { x: 0, y: 0 },
  lastGamepadState: null,
  inputDevice: 'keyboard', // keyboard | gamepad | vr-controller
  inputLog: [],
};

// ==== Редуктор: управление состоянием ====
function inputReducer(state, action) {
  switch (action.type) {
    case InputEvents.KEY_DOWN: {
      const updated = new Set(state.keysPressed);
      updated.add(action.payload.key);
      return {
        ...state,
        keysPressed: updated,
        inputDevice: 'keyboard',
      };
    }

    case InputEvents.KEY_UP: {
      const updated = new Set(state.keysPressed);
      updated.delete(action.payload.key);
      return {
        ...state,
        keysPressed: updated,
        inputDevice: 'keyboard',
      };
    }

    case InputEvents.POINTER_MOVE:
      return {
        ...state,
        pointerPosition: action.payload,
        inputDevice: 'mouse',
      };

    case InputEvents.GAMEPAD_INPUT:
      return {
        ...state,
        lastGamepadState: action.payload,
        inputDevice: 'gamepad',
      };

    case InputEvents.INPUT_DEVICE_CHANGE:
      return {
        ...state,
        inputDevice: action.payload,
      };

    case InputEvents.RESET_INPUT_STATE:
      return initialState;

    default:
      return state;
  }
}

// ==== Контекст и хук ====
const InputContext = createContext();
export const useInput = () => useContext(InputContext);

// ==== Провайдер: глобальный input listener ====
export function InputProvider({ children }) {
  const [state, dispatch] = useReducer(inputReducer, initialState);

  useEffect(() => {
    const handleKeyDown = (e) => {
      dispatch({ type: InputEvents.KEY_DOWN, payload: { key: e.key } });
    };

    const handleKeyUp = (e) => {
      dispatch({ type: InputEvents.KEY_UP, payload: { key: e.key } });
    };

    const handlePointerMove = (e) => {
      dispatch({
        type: InputEvents.POINTER_MOVE,
        payload: { x: e.clientX, y: e.clientY }
      });
    };

    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('keyup', handleKeyUp);
    window.addEventListener('pointermove', handlePointerMove);

    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('keyup', handleKeyUp);
      window.removeEventListener('pointermove', handlePointerMove);
    };
  }, []);

  useEffect(() => {
    const pollGamepad = () => {
      const gamepads = navigator.getGamepads?.() || [];
      if (gamepads[0]) {
        dispatch({
          type: InputEvents.GAMEPAD_INPUT,
          payload: {
            timestamp: Date.now(),
            axes: [...gamepads[0].axes],
            buttons: gamepads[0].buttons.map(btn => btn.pressed),
          }
        });
      }
      requestAnimationFrame(pollGamepad);
    };
    pollGamepad();
  }, []);

  const value = useMemo(() => ({
    state,
    dispatch,
    inputEvents: InputEvents,
  }), [state]);

  return (
    <InputContext.Provider value={value}>
      {children}
    </InputContext.Provider>
  );
}
