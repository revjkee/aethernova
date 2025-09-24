/**
 * Форматирует число в строку с валютой и разделением тысяч
 * @param value - сумма в виде числа или строки, например 12345.67
 * @param currency - код валюты, например 'RUB', 'USD', 'EUR' (по умолчанию 'RUB')
 * @param locale - локаль для форматирования, по умолчанию 'ru-RU'
 * @returns Отформатированная строка, например "12 345,67 ₽"
 */
export function formatPrice(
  value: number | string,
  currency: string = 'RUB',
  locale: string = 'ru-RU'
): string {
  const numberValue = typeof value === 'string' ? parseFloat(value) : value

  if (isNaN(numberValue)) return ''

  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(numberValue)
}
