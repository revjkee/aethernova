/**
 * Парсит дату и возвращает строку в формате "ДД.ММ.ГГГГ" или "ДД ММ ГГГГ"
 * Принимает строки в ISO-формате или объекты Date.
 * Возвращает пустую строку при некорректных данных.
 *
 * @param input - дата в формате string (ISO) или Date
 * @param separator - разделитель даты, по умолчанию '.'
 * @returns строка с отформатированной датой, например "30.06.2025"
 */
export function parseDate(input: string | Date, separator: string = '.'): string {
  let date: Date

  if (typeof input === 'string') {
    date = new Date(input)
  } else if (input instanceof Date) {
    date = input
  } else {
    return ''
  }

  if (isNaN(date.getTime())) {
    return ''
  }

  const day = date.getDate().toString().padStart(2, '0')
  const month = (date.getMonth() + 1).toString().padStart(2, '0')
  const year = date.getFullYear()

  return [day, month, year].join(separator)
}
