#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION="2.2.2"
REPOSITORY="Fausto-404/EFF-Monitoring"
case "$(uname -m)" in
  arm64|aarch64) ARCH_SUFFIX=arm ;;
  amd64|x86_64) ARCH_SUFFIX=amd ;;
  *) echo "不支持的 CPU 架构：$(uname -m)" >&2; exit 1 ;;
esac
IMAGE_TAR="$ROOT_DIR/eff-monitoring-v${VERSION}-images-${ARCH_SUFFIX}.tar"
DOWNLOAD_URL=""
API_PORT=""
WEB_PORT=""
OFFLINE_ONLY=0
VERIFY_RELEASE_CHECKSUM=1

usage() {
  cat <<EOF
EFF-Monitoring v${VERSION} 一键安装

用法：
  ./install.sh                         按 CPU 架构下载 Release 离线镜像包并部署
  ./install.sh --offline images.tar   使用本地离线镜像包部署
  ./install.sh --api-port 8001 --web-port 8081  指定端口

脚本只下载 GitHub Release 离线镜像包，不会从 Docker 镜像仓库下载镜像。
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --offline)
      [ "$#" -ge 2 ] || { echo "--offline 需要镜像包路径" >&2; exit 2; }
      IMAGE_TAR=$2
      OFFLINE_ONLY=1
      shift 2
      ;;
    --url)
      [ "$#" -ge 2 ] || { echo "--url 需要离线包下载地址" >&2; exit 2; }
      DOWNLOAD_URL=$2
      VERIFY_RELEASE_CHECKSUM=0
      shift 2
      ;;
    --api-port)
      [ "$#" -ge 2 ] || { echo "--api-port 需要端口号" >&2; exit 2; }
      API_PORT=$2
      shift 2
      ;;
    --web-port)
      [ "$#" -ge 2 ] || { echo "--web-port 需要端口号" >&2; exit 2; }
      WEB_PORT=$2
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

command -v docker >/dev/null 2>&1 || { echo "未找到 Docker，请先安装并启动 Docker。" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker 服务未运行。" >&2; exit 1; }
if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  echo "未找到 Docker Compose。" >&2
  exit 1
fi
free_kb=$(df -Pk "$ROOT_DIR" | awk 'NR==2 {print $4}')
if [ "${free_kb:-0}" -lt 2097152 ] 2>/dev/null; then
  echo "磁盘可用空间不足 2GB，暂不下载离线镜像包。" >&2
  exit 1
fi

if [ ! -f "$IMAGE_TAR" ]; then
  if [ "$OFFLINE_ONLY" -eq 1 ]; then
    echo "未找到指定的离线镜像包：$IMAGE_TAR" >&2
    exit 1
  fi
  if [ -z "$DOWNLOAD_URL" ]; then
    DOWNLOAD_URL="https://github.com/${REPOSITORY}/releases/download/v${VERSION}/eff-monitoring-v${VERSION}-images-${ARCH_SUFFIX}.tar"
  fi
  echo "检测到 CPU 架构：$(uname -m)，正在下载：$DOWNLOAD_URL"
  download_tmp=$(mktemp "${IMAGE_TAR}.part.XXXXXX")
  trap 'rm -f "$download_tmp"' EXIT HUP INT TERM
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 15 -o "$download_tmp" "$DOWNLOAD_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$download_tmp" "$DOWNLOAD_URL"
  else
    echo "未找到 curl 或 wget，无法下载离线镜像包。" >&2
    exit 1
  fi
  if [ "$VERIFY_RELEASE_CHECKSUM" -eq 1 ]; then
    command -v curl >/dev/null 2>&1 || { echo "校验 Release 包需要 curl。" >&2; exit 1; }
    expected_sha256=$(curl -fsSL --retry 3 --connect-timeout 15 "${DOWNLOAD_URL}.sha256")
    case "$expected_sha256" in
      ''|*[!0123456789abcdefABCDEF]*) echo "Release SHA-256 校验值无效。" >&2; exit 1 ;;
    esac
    [ "${#expected_sha256}" -eq 64 ] || { echo "Release SHA-256 校验值长度错误。" >&2; exit 1; }
    if command -v sha256sum >/dev/null 2>&1; then
      actual_sha256=$(sha256sum "$download_tmp" | cut -d ' ' -f 1)
    elif command -v shasum >/dev/null 2>&1; then
      actual_sha256=$(shasum -a 256 "$download_tmp" | cut -d ' ' -f 1)
    else
      echo "未找到 sha256sum 或 shasum，无法校验镜像包。" >&2
      exit 1
    fi
    [ "$actual_sha256" = "$expected_sha256" ] || { echo "离线镜像包 SHA-256 校验失败。" >&2; exit 1; }
  fi
  mv "$download_tmp" "$IMAGE_TAR"
  trap - EXIT HUP INT TERM
fi

set -- --offline "$IMAGE_TAR"
if [ -n "$API_PORT" ]; then set -- "$@" --api-port "$API_PORT"; fi
if [ -n "$WEB_PORT" ]; then set -- "$@" --web-port "$WEB_PORT"; fi
exec "$ROOT_DIR/deploy.sh" "$@"
