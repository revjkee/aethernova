/**
 * Проверяет, валиден ли email
 */
export function isValidEmail(email: string): boolean {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

/**
 * Проверяет, валиден ли пароль (минимум 8 символов, с цифрами и буквами)
 */
export function isValidPassword(password: string): boolean {
  const re = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
  return re.test(password);
}
