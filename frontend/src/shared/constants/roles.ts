export const roles = [];

export const ROLE = {
	ADMIN: 'admin',
	MODERATOR: 'moderator',
	USER: 'user',
} as const;

export type ROLE = (typeof ROLE)[keyof typeof ROLE];
