# Инструкция по применению патча ядра

## 1. Подготовка среды

- Убедитесь, что установлены необходимые инструменты:
  - gcc, make, bc, libncurses-dev
  - git
  - patch

- Получите исходники ядра:
  ```bash
  git clone https://kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
  cd linux-stable
