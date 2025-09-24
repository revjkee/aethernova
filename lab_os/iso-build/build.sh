#!/bin/bash
set -euo pipefail

# Переменные
WORKDIR=$(pwd)
ISO_NAME="custom-linux.iso"
BUILD_DIR="${WORKDIR}/build"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
ISO_DIR="${BUILD_DIR}/iso"
KERNEL_VERSION="5.15.0-custom"
ARCH="x86_64"

# Очистка предыдущих сборок
rm -rf "$BUILD_DIR"
mkdir -p "$ROOTFS_DIR" "$ISO_DIR/boot/grub"

echo "Скачиваем и распаковываем базовую систему (debootstrap для Debian/Ubuntu)"
debootstrap --arch=$ARCH stable "$ROOTFS_DIR" http://deb.debian.org/debian/

echo "Устанавливаем ядро Linux версии $KERNEL_VERSION"
chroot "$ROOTFS_DIR" /bin/bash -c "
  apt-get update
  apt-get install -y linux-image-$KERNEL_VERSION grub-pc
"

echo "Копируем ядро и initrd в ISO"
cp "$ROOTFS_DIR/boot/vmlinuz-$KERNEL_VERSION" "$ISO_DIR/boot/vmlinuz"
cp "$ROOTFS_DIR/boot/initrd.img-$KERNEL_VERSION" "$ISO_DIR/boot/initrd.img"

echo "Создаем grub.cfg"
cat > "$ISO_DIR/boot/grub/grub.cfg" <<EOF
set timeout=5
set default=0

menuentry "Custom Linux $KERNEL_VERSION" {
    linux /boot/vmlinuz root=/dev/sr0 ro quiet
    initrd /boot/initrd.img
}
EOF

echo "Создаем ISO образ"
grub-mkrescue -o "$WORKDIR/$ISO_NAME" "$ISO_DIR"

echo "Сборка ISO завершена: $ISO_NAME"
