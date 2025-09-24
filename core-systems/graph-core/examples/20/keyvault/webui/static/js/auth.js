// TeslaAI KeyVault – Secure Auth Module v2.1 (Industrial Grade)
// Разработано консиллиумом из 20 агентов и 3 метагенералов

import { getContextHash } from './utils.js'

const AUTH_CONFIG = {
    tokenEndpoint: '/api/auth/token',
    loginPage: '/login.html',
    clientId: 'teslaai-webui',
    storageKey: 'teslaai_token',
    contextFingerprint: getContextHash(),
};

export async function login(username, password) {
    const payload = {
        username,
        password,
        context_hash: AUTH_CONFIG.contextFingerprint
    };

    const response = await fetch(AUTH_CONFIG.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Ошибка авторизации');
    }

    const data = await response.json();
    storeToken(data.token);
    window.location.href = '/';
}

export function storeToken(token) {
    // Храним токен только в sessionStorage (или HttpOnly Cookie, если server-side)
    sessionStorage.setItem(AUTH_CONFIG.storageKey, token);
}

export function getToken() {
    return sessionStorage.getItem(AUTH_CONFIG.storageKey);
}

export function logout() {
    sessionStorage.removeItem(AUTH_CONFIG.storageKey);
    window.location.href = AUTH_CONFIG.loginPage;
}

export function isAuthenticated() {
    const token = getToken();
    if (!token) return false;

    try {
        const payload = parseJwt(token);
        const now = Math.floor(Date.now() / 1000);
        return payload.exp > now;
    } catch (e) {
        return false;
    }
}

function parseJwt(token) {
    const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
        atob(base64)
            .split('')
            .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
            .join('')
    );
    return JSON.parse(jsonPayload);
}

export function attachAuthHeader(requestOptions = {}) {
    const token = getToken();
    if (!token) return requestOptions;

    if (!requestOptions.headers) {
        requestOptions.headers = {};
    }

    requestOptions.headers['Authorization'] = `Bearer ${token}`;
    return requestOptions;
}
