#!/bin/bash
set -e

echo "Обновление пакетов и установка системных зависимостей..."
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y python3 python3-pip python3-venv build-essential libssl-dev libffi-dev

echo "Создание виртуального окружения..."
python3 -m venv venv

echo "Активация виртуального окружения..."
source venv/bin/activate

echo "Обновление pip и установка зависимостей из requirements.txt..."
pip install --upgrade pip setuptools wheel
pip install -r ../requirements.txt

echo "Проверка установленных пакетов..."
pip check

echo "Установка завершена успешно."
