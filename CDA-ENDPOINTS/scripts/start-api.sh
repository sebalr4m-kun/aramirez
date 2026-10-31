#!/bin/bash
set -e
cd /root/api/aramirez/CDA-ENDPOINTS
source .venv/bin/activate

export DB_HOST=127.0.0.1
export DB_PORT=3306
export DB_USER=onlineashes
export DB_PASSWORD='N5/Ro9!R/h&RRn'
export DB_NAME=onlineashes

if ss -tlnp 2>/dev/null | grep -q ':8001'; then
  echo "Ya hay algo escuchando en :8001"
  ss -tlnp | grep 8001
  exit 1
fi

echo "API OnlineAshes en 127.0.0.1:8001 (nginx /api/ → acá)"
exec uvicorn MainExample:app --host 127.0.0.1 --port 8001
