# payload_example.ps1
#
# Пример простого PowerShell payload скрипта.
# Структура:
# - Объявление переменных
# - Основная логика
# - Обработка ошибок
#

$Target = "127.0.0.1"

Write-Host "Запуск PowerShell payload для цели: $Target"

try {
    $ping = Test-Connection -ComputerName $Target -Count 1 -ErrorAction Stop
    if ($ping) {
        Write-Host "Цель $Target доступна"
    }
} catch {
    Write-Error "Не удалось достучаться до цели $Target"
    exit 1
}

Write-Host "Payload выполнен успешно."
exit 0
