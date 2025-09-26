import React from 'react'
import Footer from '@/shared/ui/Footer'

export const Layout: React.FC<React.PropsWithChildren<Record<string, unknown>>> = ({ children }) => {
	return (
		<div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
			<header style={{ padding: '12px 16px', borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
				<div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
					<div style={{ fontWeight: 700 }}>Aethernova</div>
					<nav aria-label="Main navigation">
						<a href="/" style={{ marginRight: 12 }}>Home</a>
						<a href="/docs">Docs</a>
					</nav>
				</div>
			</header>

			<main style={{ flex: 1, padding: '16px' }}>{children}</main>

			<Footer />
		</div>
	)
}

export default Layout
