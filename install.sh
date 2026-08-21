#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION="2.2.1"
REPOSITORY="Fausto-404/EFF-Monitoring"
case "$(uname -m)" in
  arm64|aarch64) ARCH_SUFFIX=arm ;;
  amd64|x86_64) ARCH_SUFFIX=amd ;;
  *) echo "不支持的 CPU 架构：$(uname -m)" >&2; exit 1 ;;
esac
IMAGE_TAR="$ROOT_DIR/eff-monitoring-v2.2.1-images-${ARCH_SUFFIX}.tar"
DOWNLOAD_URL=""
DEPLOY_ARGS=""

usage() {
  cat <<EOF
EFF-Monitoring v${VERSION} 一键安装

用法：
  ./install.sh                         按 CPU 架构下载 Release 离线镜像包并部署
  ./install.sh --offline images.tar   使用本地离线镜像包部署
  ./install.sh --api-port 8001 --web-port 8081  指定宿主机端口

脚本只下载 GitHub Release 离线镜像包，不会从 Docker 镜像仓库下载镜像。
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --offline)
      [ "$#" -ge 2 ] || { echo "--offline 需要镜像包路径" >&2; exit 2; }
      IMAGE_TAR=$2
      shift 2
      ;;
    --url)
      [ "$#" -ge 2 ] || { echo "--url 需要离线包下载地址" >&2; exit 2; }
      DOWNLOAD_URL=$2
      shift 2
      ;;
    --api-port|--web-port)
      [ "$#" -ge 2 ] || { echo "$1 需要端口号" >&2; exit 2; }
      DEPLOY_ARGS="$DEPLOY_ARGS $1 $2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "未知参数：$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ ! -f "$IMAGE_TAR" ] && [ -f "$ROOT_DIR/eff-monitoring-v2.2.1-images.tar" ]; then
  IMAGE_TAR="$ROOT_DIR/eff-monitoring-v2.2.1-images.tar"
fi

if [ ! -f "$IMAGE_TAR" ]; then
  if [ -z "$DOWNLOAD_URL" ]; then
    DOWNLOAD_URL="https://github.com/${REPOSITORY}/releases/download/v${VERSION}/eff-monitoring-v${VERSION}-images-${ARCH_SUFFIX}.tar"
  fi
  echo "检测到 CPU 架构：$(uname -m)，将下载 ${ARCH_SUFFIX} 镜像包：$DOWNLOAD_URL"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 15 -o "$IMAGE_TAR" "$DOWNLOAD_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$IMAGE_TAR" "$DOWNLOAD_URL"
  else
    echo "未找到 curl 或 wget，无法下载离线镜像包。" >&2
    exit 1
  fi
fi

set -- --offline "$IMAGE_TAR"
# shellcheck disable=SC2086
exec "$ROOT_DIR/deploy.sh" "$@" $DEPLOY_ARGS
