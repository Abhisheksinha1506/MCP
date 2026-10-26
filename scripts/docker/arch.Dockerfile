FROM archlinux:latest
RUN pacman -Syu --noconfirm python python-psutil python-pytest
