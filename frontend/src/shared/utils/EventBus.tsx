import React from 'react'

type Handler = (payload?: any) => void

class _EventBus {
	private handlers: Map<string, Set<Handler>> = new Map()

	on(event: string, h: Handler) {
		const set = this.handlers.get(event) ?? new Set()
		set.add(h)
		this.handlers.set(event, set)
		return () => this.off(event, h)
	}

	off(event: string, h: Handler) {
		const set = this.handlers.get(event)
		if (!set) return
		set.delete(h)
		if (set.size === 0) this.handlers.delete(event)
	}

	emit(event: string, payload?: any) {
		const set = this.handlers.get(event)
		if (!set) return
		for (const h of Array.from(set)) {
			try {
				h(payload)
			} catch (e) {
				// swallow handlers errors to avoid crashing emitter
				// eslint-disable-next-line no-console
				console.error('EventBus handler error', e)
			}
		}
	}
}

export const EventBus = new _EventBus()

export const EventBusProvider = ({ children }: { children: React.ReactNode }) => <>{children}</>