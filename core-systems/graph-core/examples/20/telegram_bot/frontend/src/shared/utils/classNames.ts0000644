type ClassValue = string | undefined | null | false | ClassDictionary | ClassArray;
interface ClassDictionary {
  [key: string]: any;
}
interface ClassArray extends Array<ClassValue> {}

/**
 * classNames — функция для объединения классов с поддержкой условных выражений
 * Пример:
 *  classNames('btn', isActive && 'btn-active', ['extra', condition ? 'cond-true' : 'cond-false'])
 * Вернет строку с классами, фильтруя falsy значения
 */
export function classNames(...args: ClassValue[]): string {
  const classes: string[] = []

  args.forEach(arg => {
    if (!arg) return

    if (typeof arg === 'string') {
      classes.push(arg)
    } else if (Array.isArray(arg)) {
      classes.push(classNames(...arg))
    } else if (typeof arg === 'object') {
      Object.entries(arg).forEach(([key, value]) => {
        if (value) classes.push(key)
      })
    }
  })

  return classes.join(' ')
}
