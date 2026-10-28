"""Dedicated, opt-in runner. It has no database credentials or host-mounted files."""

import ipaddress
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="EFF Block Script Runner", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz():
    if len(os.environ.get("BLOCK_RUNNER_TOKEN", "")) < 32:
        raise HTTPException(status_code=503, detail="联动执行器未配置")
    return {"status": "ok"}


class RunRequest(BaseModel):
    script: str = Field(min_length=1, max_length=32768)
    ip: str
    alert_id: int
    device_id: int


@app.post("/run")
def run_script(payload: RunRequest, x_block_runner_token: str = Header(default="")):
    token = os.environ.get("BLOCK_RUNNER_TOKEN", "")
    if len(token) < 32:
        raise HTTPException(status_code=503, detail="联动执行器未配置")
    if not secrets.compare_digest(x_block_runner_token, token):
        raise HTTPException(status_code=403, detail="无权调用联动执行器")
    try:
        ip = str(ipaddress.ip_address(payload.ip))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="封堵目标必须是单个有效 IP") from exc

    try:
        device_tokens = json.loads(os.environ.get("BLOCK_DEVICE_TOKENS_JSON") or "{}")
        if not isinstance(device_tokens, dict) or any(not isinstance(value, str) for value in device_tokens.values()):
            raise ValueError("invalid token mapping")
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=503, detail="设备令牌映射配置无效") from exc
    device_token = device_tokens.get(str(payload.device_id), os.environ.get("BLOCK_DEVICE_TOKEN", ""))

    with tempfile.TemporaryDirectory(prefix="eff-block-") as directory:
        script_path = Path(directory) / "block.py"
        script_path.write_text(payload.script, encoding="utf-8")
        script_path.chmod(0o600)
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                [sys.executable, "-I", str(script_path)],
                stdin=subprocess.PIPE,
                stdout=stdout, stderr=stderr, cwd=directory,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "HOME": directory,
                    "PYTHONIOENCODING": "utf-8",
                    "BLOCK_DEVICE_TOKEN": device_token,
                },
                start_new_session=True,
            )
            try:
                process.communicate(json.dumps({"ip": ip, "alert_id": payload.alert_id, "device_id": payload.device_id}).encode(), timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                return {"ok": False, "unknown": True, "message": "脚本执行超时，设备状态未知，请人工核查"}
            stdout.seek(0)
            output = stdout.read(8192).decode("utf-8", errors="replace").strip()
            if process.returncode != 0:
                return {"ok": False, "unknown": True, "message": f"脚本异常退出（代码 {process.returncode}），设备状态未知，请人工核查"}
            try:
                response = json.loads(output)
            except (json.JSONDecodeError, TypeError):
                return {"ok": False, "unknown": True, "message": "脚本未输出约定的 JSON 结果，设备状态未知，请人工核查"}
            if not isinstance(response, dict) or type(response.get("ok")) is not bool:
                return {"ok": False, "unknown": True, "message": "脚本结果必须包含布尔值 ok，设备状态未知，请人工核查"}
            return {"ok": response["ok"], "unknown": bool(response.get("unknown")) if not response["ok"] else False,
                    "message": str(response.get("message", ""))[:500]}
