import React from 'react'
import { APP_NAME, VERSION, REPO_URL } from '../utils/constants'
import GitCommitHash from '../../widgets/CI_CD/GitCommitHash'

export function VersionInfo() {
  return (
    <div style={{ display: 'flex', gap: 12, alignItems: 'center', fontSize: 12, color: 'var(--muted,#6b7280)' }}>
      <div>
        <strong>{APP_NAME}</strong>
        {VERSION ? <span style={{ marginLeft: 8 }}>v{VERSION}</span> : null}
      </div>
      <GitCommitHash />
      <a href={REPO_URL} target="_blank" rel="noopener noreferrer" style={{ marginLeft: 8 }}>
        repo
      </a>
    </div>
  )
}

export default VersionInfo
