#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

OFFLINE_FILE=""
API_PORT=""
WEB_PORT=""

usage() {
  cat <<'EOF'
EFF-Monitoring 一键部署

用法：
  ./deploy.sh                         导入发布包内默认镜像包并启动
  ./deploy.sh --offline images.tar   导入指定离线镜像包并启动
  ./deploy.sh --api-port 8001 --web-port 8081  指定宿主机端口

部署只使用离线镜像包，不会从任何镜像仓库下载或构建依赖。
首次部署会自动生成数据库密码、JWT 密钥和管理员初始密码，并打印管理员密码。
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --offline)
      [ "$#" -ge 2 ] || { echo "--offline 需要镜像包路径" >&2; exit 2; }
      OFFLINE_FILE=$2
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

command -v docker >/dev/null 2>&1 || { echo "未找到 Docker，请先安装 Docker Desktop 或 Docker Engine。" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker 服务未运行，请先启动 Docker。" >&2; exit 1; }

if docker compose version >/dev/null 2>&1; then
  compose() { docker compose -p eff-monitoring-v2-2-1 "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose -p eff-monitoring-v2-2-1 "$@"; }
else
  echo "未找到 Docker Compose，请安装 Compose v2 或 docker-compose。" >&2
  exit 1
fi

if [ -z "$OFFLINE_FILE" ]; then
  if [ -f "$ROOT_DIR/eff-monitoring-v2.2.1-images.tar" ]; then
    OFFLINE_FILE="$ROOT_DIR/eff-monitoring-v2.2.1-images.tar"
  elif [ -f "$ROOT_DIR/../eff-monitoring-v2.2.1-images.tar" ]; then
    OFFLINE_FILE="$ROOT_DIR/../eff-monitoring-v2.2.1-images.tar"
  else
    OFFLINE_FILE="$ROOT_DIR/eff-monitoring-v2.2.1-images.tar"
  fi
fi
[ -f "$OFFLINE_FILE" ] || {
  echo "未找到离线镜像包：$OFFLINE_FILE" >&2
  echo "请将 eff-monitoring-v2.2.1-images.tar 放到源码目录或其上级版本目录，或使用 --offline 指定路径。" >&2
  exit 1
}

random_hex() {
  bytes=${1:-32}
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
  else
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
  fi
}

set_env_value() {
  key=$1
  value=$2
  if grep -q "^${key}=" .env 2>/dev/null; then
    sed -i.bak "s|^${key}=.*|${key}=${value}|" .env
    rm -f .env.bak
  else
    printf '\n%s=%s\n' "$key" "$value" >> .env
  fi
}

valid_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null
}

port_busy() {
  port=$1
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v nc >/dev/null 2>&1; then
    nc -z -w 1 127.0.0.1 "$port" >/dev/null 2>&1
  else
    return 1
  fi
}

next_free_port() {
  port=$1
  while port_busy "$port"; do
    port=$((port + 1))
    [ "$port" -le 65535 ] || { echo "没有可用端口。" >&2; exit 1; }
  done
  printf '%s' "$port"
}

normalize_arch() {
  case "$1" in
    aarch64|arm64) printf 'arm64' ;;
    x86_64|amd64) printf 'amd64' ;;
    armv7*|armhf) printf 'arm' ;;
    *) printf '%s' "$1" ;;
  esac
}

FIRST_INSTALL=0
if [ ! -f .env ]; then
  [ -f .env.example ] || { echo ".env.example 不存在。" >&2; exit 1; }
  cp .env.example .env
  DB_PASSWORD=${POSTGRES_PASSWORD:-$(random_hex 24)}
  JWT_SECRET_VALUE=${JWT_SECRET:-$(random_hex 32)}
  ADMIN_PASSWORD=${INITIAL_ADMIN_PASSWORD:-$(random_hex 16)}
  set_env_value POSTGRES_PASSWORD "$DB_PASSWORD"
  set_env_value DATABASE_URL "postgresql+psycopg://eff:${DB_PASSWORD}@eff-postgres:5432/eff_monitoring"
  set_env_value JWT_SECRET "$JWT_SECRET_VALUE"
  set_env_value INITIAL_ADMIN_PASSWORD "$ADMIN_PASSWORD"
  FIRST_INSTALL=1
fi

[ -n "$API_PORT" ] || API_PORT=$(sed -n 's/^EFF_API_PORT=//p' .env | tail -1)
[ -n "$WEB_PORT" ] || WEB_PORT=$(sed -n 's/^EFF_WEB_PORT=//p' .env | tail -1)
[ -n "$API_PORT" ] || API_PORT=8000
[ -n "$WEB_PORT" ] || WEB_PORT=8080
valid_port "$API_PORT" || { echo "API 端口无效：$API_PORT" >&2; exit 1; }
valid_port "$WEB_PORT" || { echo "前端端口无效：$WEB_PORT" >&2; exit 1; }

if ! compose ps --status running -q 2>/dev/null | grep -q .; then
  original_api_port=$API_PORT
  original_web_port=$WEB_PORT
  API_PORT=$(next_free_port "$API_PORT")
  WEB_PORT=$(next_free_port "$WEB_PORT")
  [ "$API_PORT" = "$original_api_port" ] || echo "API 端口 $original_api_port 已占用，自动改用 $API_PORT。"
  [ "$WEB_PORT" = "$original_web_port" ] || echo "前端端口 $original_web_port 已占用，自动改用 $WEB_PORT。"
  set_env_value EFF_API_PORT "$API_PORT"
  set_env_value EFF_WEB_PORT "$WEB_PORT"
fi

free_kb=$(df -Pk "$ROOT_DIR" | awk 'NR==2 {print $4}')
if [ "${free_kb:-0}" -lt 2097152 ] 2>/dev/null; then
  echo "磁盘可用空间不足 2GB，无法安全导入离线镜像包。" >&2
  exit 1
fi

echo "正在导入离线镜像包：$OFFLINE_FILE"
docker load -i "$OFFLINE_FILE"

host_arch=$(normalize_arch "$(docker info --format '{{.Architecture}}')")
api_image=$(sed -n 's/^EFF_API_IMAGE=//p' .env | tail -1)
[ -n "$api_image" ] || api_image=eff-monitoring-api:v2.2.1
image_arch=$(normalize_arch "$(docker image inspect "$api_image" --format '{{.Architecture}}' 2>/dev/null || true)")
if [ -z "$image_arch" ] || [ "$host_arch" != "$image_arch" ]; then
  echo "CPU 架构不兼容：当前 Docker=$host_arch，离线包=$image_arch。" >&2
  echo "请准备与目标机器架构匹配的离线镜像包。" >&2
  exit 1
fi

compose up -d --no-build

echo "等待服务健康检查..."
i=0
while [ "$i" -lt 30 ]; do
  if curl -fsS --max-time 3 "http://localhost:${API_PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 2
done

if ! curl -fsS --max-time 5 "http://localhost:${API_PORT}/healthz" >/dev/null 2>&1; then
  echo "服务未通过健康检查，请执行："
  echo "  $(printf '%s' "${PWD}")/scripts/logs.sh"
  exit 1
fi

echo
echo "EFF-Monitoring 已启动："
echo "  前端：http://localhost:${WEB_PORT}"
echo "  API：http://localhost:${API_PORT}"
echo "  文档：http://localhost:${API_PORT}/docs"
if [ "$FIRST_INSTALL" -eq 1 ]; then
  echo
  echo "首次管理员账号：$(sed -n 's/^INITIAL_ADMIN_USERNAME=//p' .env | tail -1)"
  echo "首次管理员密码：$(sed -n 's/^INITIAL_ADMIN_PASSWORD=//p' .env | tail -1)"
  echo "请立即保存该密码；密码也保存在当前目录 .env 中。"
else
  if grep -q '^INITIAL_ADMIN_PASSWORD=admin123$' .env 2>/dev/null; then
    echo
    echo "警告：当前 .env 仍使用默认管理员密码 admin123，请登录后修改。"
  fi
fi
