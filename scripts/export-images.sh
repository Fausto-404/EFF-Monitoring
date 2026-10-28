#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"
PLATFORM="${DOCKER_DEFAULT_PLATFORM:-linux/amd64}"
OUTPUT=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform)
      [ "$#" -ge 2 ] || { echo "--platform 需要平台值，例如 linux/amd64" >&2; exit 2; }
      PLATFORM=$2
      shift 2
      ;;
    --output)
      [ "$#" -ge 2 ] || { echo "--output 需要文件路径" >&2; exit 2; }
      OUTPUT=$2
      shift 2
      ;;
    -h|--help)
      echo "用法：$0 [--platform linux/amd64|linux/arm64] [--output images.tar]"
      exit 0
      ;;
    *)
      echo "未知参数：$1" >&2
      exit 2
      ;;
  esac
done

case "$PLATFORM" in
  linux/amd64) ARCH_SUFFIX=amd ;;
  linux/arm64) ARCH_SUFFIX=arm ;;
  *) echo "仅支持 linux/amd64 和 linux/arm64：$PLATFORM" >&2; exit 2 ;;
esac
[ -n "$OUTPUT" ] || OUTPUT="$ROOT_DIR/eff-monitoring-v2.2.2-images-${ARCH_SUFFIX}.tar"

command -v docker >/dev/null 2>&1 || { echo "未找到 Docker。" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker 服务未运行。" >&2; exit 1; }

# 某些 Docker Desktop/OrbStack 环境下，Compose BuildKit 会出现 gRPC
# session 错误；直接调用 buildx 更稳定，也能明确锁定目标架构。
BUILD_CONTEXT=$(docker context show)
docker_target() { docker --context "$BUILD_CONTEXT" "$@"; }
docker_target buildx version >/dev/null 2>&1 || {
  echo "当前 Docker 未提供 Buildx，无法构建跨架构镜像。" >&2
  exit 1
}

echo "拉取基础镜像并构建应用镜像（目标平台：${PLATFORM}）..."
target_arch=${PLATFORM#*/}
for image in postgres:17-alpine redis:7-alpine; do
  image_arch=$(docker_target image inspect "$image" --format '{{.Architecture}}' 2>/dev/null || true)
  if [ "$image_arch" != "$target_arch" ]; then
    docker_target pull --platform "$PLATFORM" "$image"
  fi
done
docker_target buildx build --platform "$PLATFORM" --load \
  -t eff-monitoring-api:v2.2.2 -f Dockerfile.backend .
docker_target tag eff-monitoring-api:v2.2.2 eff-monitoring-worker:v2.2.2
docker_target buildx build --platform "$PLATFORM" --load \
  -t eff-monitoring-web:v2.2.2 -f Dockerfile.frontend .

IMAGES="postgres:17-alpine redis:7-alpine eff-monitoring-api:v2.2.2 eff-monitoring-worker:v2.2.2 eff-monitoring-web:v2.2.2"

case "$target_arch" in
  amd64|x86_64) target_arch=amd64 ;;
  arm64|aarch64) target_arch=arm64 ;;
esac
for image in $IMAGES; do
  image_arch=$(docker_target image inspect "$image" --format '{{.Architecture}}')
  case "$image_arch" in
    x86_64) image_arch=amd64 ;;
    aarch64) image_arch=arm64 ;;
  esac
  [ "$image_arch" = "$target_arch" ] || {
    echo "镜像架构校验失败：${image} 是 ${image_arch}，目标是 ${target_arch}。" >&2
    exit 1
  }
done

set -- $IMAGES
temporary_output=$(mktemp "${OUTPUT}.part.XXXXXX")
trap 'rm -f "$temporary_output"' EXIT HUP INT TERM
docker_target save -o "$temporary_output" "$@"
mv "$temporary_output" "$OUTPUT"
trap - EXIT HUP INT TERM
echo "离线镜像包已生成：$OUTPUT"
echo "目标平台：$PLATFORM"
echo "目标机器执行：./deploy.sh --offline $OUTPUT"
