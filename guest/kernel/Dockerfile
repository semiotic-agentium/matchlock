# Multi-stage Dockerfile for building Matchlock guest kernels.
#
# Stages:
#   base          - Toolchain + kernel source (shared, heavily cached)
#   build-x86_64  - x86_64 kernel build (Firecracker)
#   build-arm64   - arm64 kernel build (Virtualization.framework)
#
# Usage:
#   docker build --build-arg KERNEL_VERSION=6.1.137 \
#     --target build-x86_64 --output type=local,dest=./out .

ARG KERNEL_VERSION=6.1.137

# ---------------------------------------------------------------------------
# Base: toolchain + kernel source
# ---------------------------------------------------------------------------
FROM ubuntu:22.04 AS base

ARG KERNEL_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential bc flex bison libelf-dev libssl-dev wget \
        gcc-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO /tmp/linux.tar.xz \
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz" \
    && mkdir /tmp/linux-src \
    && tar xf /tmp/linux.tar.xz -C /tmp/linux-src --strip-components=1 \
    && rm /tmp/linux.tar.xz

# ---------------------------------------------------------------------------
# x86_64 kernel (Firecracker)
# ---------------------------------------------------------------------------
FROM base AS build-x86_64

COPY x86_64.config /tmp/linux-src/.config

RUN cd /tmp/linux-src \
    && make olddefconfig \
    && make -j"$(nproc)" vmlinux

RUN mkdir /output && cp /tmp/linux-src/vmlinux /output/kernel

# ---------------------------------------------------------------------------
# arm64 kernel (Virtualization.framework)
# ---------------------------------------------------------------------------
FROM base AS build-arm64

COPY arm64.config /tmp/linux-src/.config

RUN cd /tmp/linux-src \
    && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig \
    && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j"$(nproc)" Image

RUN mkdir /output && cp /tmp/linux-src/arch/arm64/boot/Image /output/kernel-arm64
