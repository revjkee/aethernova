// TeslaAI WebUI Secure Utils v2.1
// Разработано: консиллиум из 20 агентов и 3 метагенералов

/**
 * Отображение alert-сообщения в UI
 * @param {string} message - Текст сообщения
 * @param {'success'|'error'|'info'} type - Тип сообщения
 */
export function showAlert(message, type = 'info') {
    const alertBox = document.createElement('div');
    alertBox.className = `alert-box alert-${type}`;
    alertBox.innerText = message;

    document.body.appendChild(alertBox);
    setTimeout(() => alertBox.remove(), 5000);
}

/**
 * Генерация и внедрение CSRF-токена
 * Используется при форменной авторизации
 * @returns {string} csrfToken
 */
export function generateCsrfToken() {
    const token = btoa(crypto.getRandomValues(new Uint8Array(32)).join(''));
    sessionStorage.setItem('csrf_token', token);
    return token;
}

/**
 * Получение текущего CSRF токена
 * @returns {string|null}
 */
export function getCsrfToken() {
    return sessionStorage.getItem('csrf_token');
}

/**
 * Проверка токена CSRF на стороне клиента
 * @param {string} token - полученный токен
 * @returns {boolean}
 */
export function validateCsrfToken(token) {
    const stored = getCsrfToken();
    return stored && stored === token;
}

/**
 * Валидатор email-адреса
 * @param {string} email
 * @returns {boolean}
 */
export function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Проверка на безопасный ввод (XSS-safe)
 * @param {string} input
 * @returns {boolean}
 */
export function isSafeInput(input) {
    return !/[<>]/.test(input);
}

/**
 * Получение хэша контекста среды (браузер + OS + часовой пояс)
 * Используется в RBAC/ABAC и сигнатурах контекста
 * @returns {string}
 */
export function getContextHash() {
    const agent = navigator.userAgent;
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const platform = navigator.platform;

    const raw = `${agent}|${timezone}|${platform}`;
    const hashBuffer = new TextEncoder().encode(raw);
    const hash = crypto.subtle.digest("SHA-256", hashBuffer);

    return hash.then(buffer => {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    });
}

/**
 * Генерация короткого идентификатора действия
 * @returns {string}
 */
export function generateActionId() {
    return Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
}
