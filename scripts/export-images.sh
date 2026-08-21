#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"
PLATFORM="${DOCKER_DEFAULT_PLATFORM:-linux/amd64}"
OUTPUT="$ROOT_DIR/eff-monitoring-v2.2.1-images.tar"

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

command -v docker >/dev/null 2>&1 || { echo "未找到 Docker。" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker 服务未运行。" >&2; exit 1; }

if docker compose version >/dev/null 2>&1; then
  compose() { DOCKER_DEFAULT_PLATFORM="$PLATFORM" docker compose -p eff-monitoring-v2-2-1 "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { DOCKER_DEFAULT_PLATFORM="$PLATFORM" docker-compose -p eff-monitoring-v2-2-1 "$@"; }
else
  echo "未找到 Docker Compose。" >&2
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "已临时创建 .env；正式部署请使用 deploy.sh 自动生成安全密码。"
fi

echo "拉取基础镜像并构建应用镜像..."
compose pull eff-postgres eff-redis
compose build eff-api eff-worker eff-web

IMAGES=$(compose config --images | sort -u)
[ -n "$IMAGES" ] || { echo "未解析到待导出的镜像。" >&2; exit 1; }

target_arch=${PLATFORM#*/}
case "$target_arch" in
  amd64|x86_64) target_arch=amd64 ;;
  arm64|aarch64) target_arch=arm64 ;;
esac
for image in $IMAGES; do
  image_arch=$(docker image inspect "$image" --format '{{.Architecture}}')
  case "$image_arch" in
    x86_64) image_arch=amd64 ;;
    aarch64) image_arch=arm64 ;;
  esac
  [ "$image_arch" = "$target_arch" ] || {
    echo "镜像架构校验失败：$image 是 $image_arch，目标是 $target_arch。" >&2
    exit 1
  }
done

set -- $IMAGES
docker save -o "$OUTPUT" "$@"
echo "离线镜像包已生成：$OUTPUT"
echo "目标平台：$PLATFORM"
echo "目标机器执行：./deploy.sh --offline $OUTPUT"
