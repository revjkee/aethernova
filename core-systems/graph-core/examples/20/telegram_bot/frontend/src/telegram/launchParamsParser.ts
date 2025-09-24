// src/telegram/launchParamsParser.ts
export interface LaunchParams {
  tgWebAppStartParam?: string;
  user?: string;
  chat?: string;
  auth_date: string;
  hash: string;
  [key: string]: string | undefined;
}

export function parseLaunchParams(): LaunchParams | null {
  const searchParams = new URLSearchParams(window.location.search);
  const entries = Object.fromEntries(searchParams.entries());

  if (!entries.hash || !entries.auth_date) return null;

  return {
    ...entries,
    tgWebAppStartParam: entries.tgWebAppStartParam,
    user: entries.user,
    chat: entries.chat,
    auth_date: entries.auth_date,
    hash: entries.hash,
  };
}
