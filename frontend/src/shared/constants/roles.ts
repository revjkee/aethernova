export const roles = [];

export const ROLE = {
	ADMIN: 'admin',
	MODERATOR: 'moderator',
	USER: 'user',
	SECURITY_OFFICER: 'security_officer',
	AI_GOVERNOR: 'ai_governor',
} as const;

export type ROLE = (typeof ROLE)[keyof typeof ROLE];
