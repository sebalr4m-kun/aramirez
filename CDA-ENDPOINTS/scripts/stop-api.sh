#!/bin/bash
PID=$(ss -tlnp 2>/dev/null | grep ':8001' | grep -oP 'pid=\K[0-9]+' | head -1)
if [ -z "$PID" ]; then
  echo "No hay proceso en :8001"
  exit 0
fi
echo "Deteniendo PID $PID ..."
kill "$PID" 2>/dev/null || true
sleep 1
if ss -tlnp 2>/dev/null | grep -q ':8001'; then
  kill -9 "$PID" 2>/dev/null || true
fi
echo "API detenida"
