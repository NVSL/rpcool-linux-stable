#!/bin/bash

# Exit immediately if a command exits with a non-zero status, and treat unset variables as an error.
set -eux

sudo make -j$(nproc)
sudo make modules_install -j$(nproc) > /tmp/kernel_modules_install.log
# sudo make headers_install ARCH=x86
sudo make install -j$(nproc)

if [ "$1" == "boot" ]; then
    sudo kexec -l /boot/vmlinuz-6.1.37+ --initrd=/boot/initrd.img-6.1.37+ --reuse-cmdline
    sudo kexec -f -e
fi