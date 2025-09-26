import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'

import SecurityStatus from '../SecurityStatus'

beforeEach(() => {
  // @ts-ignore
  global.fetch = jest.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve({ id: 'security', overall: 'ok', incidents: [], lastChecked: new Date().toISOString() }) })
  )
})

test('renders security status widget', async () => {
  render(<SecurityStatus />)
  await waitFor(() => expect(screen.getByText(/Security Status/i)).toBeInTheDocument())
  expect(global.fetch).toHaveBeenCalled()
})
