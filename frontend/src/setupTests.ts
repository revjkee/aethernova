import '@testing-library/jest-dom';

// ensure DOM is cleaned between tests
import { cleanup } from '@testing-library/react';

afterEach(() => {
  cleanup();
});
