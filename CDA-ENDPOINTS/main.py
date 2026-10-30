from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Any

import bcrypt
import jwt
import mysql.connector
from mysql.connector import pooling, Error as MySQLError
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field


# =============================================================================
# CONFIGURACIÓN
# =============================================================================

class Settings:
    DB_HOST: str = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_USER: str = os.getenv("DB_USER", "root")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")
    DB_NAME: str = os.getenv("DB_NAME", "onlineashes")

    # FIJO: si cambia en cada restart, todos los tokens del launcher mueren
    JWT_SECRET: str = os.getenv(
        "JWT_SECRET",
        "cenizas-onlineashes-dev-secret-cambiar-en-produccion-2026",
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = int(os.getenv("JWT_EXPIRE_HOURS", "168"))  # 7 días

    POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", "10"))
    API_TITLE: str = "OnlineAshes API"
    API_VERSION: str = "1.0.3"


settings = Settings()
security = HTTPBearer(auto_error=False)

# =============================================================================
# POOL DE CONEXIONES
# =============================================================================

_pool: Optional[pooling.MySQLConnectionPool] = None


def init_pool() -> None:
    global _pool
    if _pool is not None:
        return
    _pool = pooling.MySQLConnectionPool(
        pool_name="onlineashes_pool",
        pool_size=settings.POOL_SIZE,
        pool_reset_session=True,
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        user=settings.DB_USER,
        password=settings.DB_PASSWORD,
        database=settings.DB_NAME,
        charset="utf8mb4",
        autocommit=True,
        connection_timeout=8,
    )


def get_conn():
    if _pool is None:
        init_pool()
    return _pool.get_connection()


# =============================================================================
# UTILIDADES DE SEGURIDAD (bcrypt + PHP $2y$)
# =============================================================================

def normalize_php_hash(hash_guardado: str) -> bytes:
    if not hash_guardado:
        return b""
    h = hash_guardado.strip()
    if h.startswith("$2y$"):
        h = "$2a$" + h[4:]
    return h.encode("utf-8")


def verificar_password(plain: str, hash_guardado: str) -> bool:
    if not plain or not hash_guardado:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), normalize_php_hash(hash_guardado))
    except Exception as e:
        print(f"[auth] bcrypt check error: {e}")
        return False


def hash_password(plain: str) -> str:
    raw = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=10))
    s = raw.decode("utf-8")
    if s.startswith("$2b$") or s.startswith("$2a$"):
        return "$2y$" + s[4:]
    return s


def crear_jwt(payload: dict) -> str:
    data = payload.copy()
    # sub como string: más portable entre implementaciones JWT
    if "sub" in data:
        data["sub"] = str(data["sub"])
    data["exp"] = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    data["iat"] = datetime.now(timezone.utc)
    return jwt.encode(data, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decodificar_jwt(token: str) -> dict:
    try:
        data = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if "sub" in data:
            try:
                data["sub"] = int(data["sub"])
            except (TypeError, ValueError):
                pass
        return data
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token expirado. Volvé a iniciar sesión.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido.")


def generar_llave_licencia() -> str:
    return secrets.token_hex(32)


def generar_clave_drm() -> str:
    return secrets.token_hex(16)


# =============================================================================
# SCHEMAS
# =============================================================================

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class LoginOut(BaseModel):
    status: str = "success"
    token: str
    id_usuario: int
    nombre: str
    email: str
    fecha_registro: Optional[str] = None
    clave_drm_maestra: str
    mensaje: str = "Acceso concedido."


class RegisterIn(BaseModel):
    nombre: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8)


class VersionOut(BaseModel):
    id: int
    titulo: str
    version: str
    fecha: Optional[str] = None
    precio: str = "$0.00"
    estado: str = "DISPONIBLE"
    url_descarga: Optional[str] = None


class LicenciaOut(BaseModel):
    id_licencia: int
    id_version: int
    titulo: str
    version: str
    fecha_adquisicion: Optional[str] = None
    llave_acceso: str
    url_descarga: Optional[str] = None
    precio: str = "$0.00"


class ComprarIn(BaseModel):
    id_version: int


class MsgOut(BaseModel):
    status: str
    message: str


# =============================================================================
# APP
# =============================================================================

app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_pool()
    print(
        f"[API] {settings.API_VERSION} · JWT fijo · "
        f"expire={settings.JWT_EXPIRE_HOURS}h · db={settings.DB_NAME}"
    )


def usuario_actual(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="Se requiere token Bearer.")
    data = decodificar_jwt(creds.credentials)
    if "sub" not in data:
        raise HTTPException(status_code=401, detail="Token incompleto.")
    return data


# =============================================================================
# HEALTH
# =============================================================================

@app.get("/health")
def health():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        conn.close()
        return {"status": "ok", "db": "up", "version": settings.API_VERSION}
    except Exception as e:
        return {"status": "degraded", "db": "down", "error": str(e)}


# =============================================================================
# AUTH — LOGIN
# =============================================================================

@app.post("/auth/login", response_model=LoginOut)
def login(body: LoginIn):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        # Un solo % en DATE_FORMAT (mysql-connector solo interpreta %s como param)
        cur.execute(
            """
            SELECT id_usuario, nombre, email, contraseña, clave_drm_maestra,
                   estado_cuenta,
                   DATE_FORMAT(fecha_registro, '%d/%m/%Y') AS fecha_registro
            FROM usuarios
            WHERE email = %s
            LIMIT 1
            """,
            (body.email.strip().lower(),),
        )
        user = cur.fetchone()
        cur.close()

        if not user or not verificar_password(body.password, user["contraseña"]):
            raise HTTPException(
                status_code=401,
                detail="Cuenta inexistente o credenciales incorrectas.",
            )

        if (user.get("estado_cuenta") or "").upper() != "ACTIVA":
            raise HTTPException(
                status_code=403,
                detail="La cuenta se encuentra suspendida o inactiva.",
            )

        token = crear_jwt({
            "sub": user["id_usuario"],
            "email": user["email"],
            "nombre": user["nombre"],
        })

        return LoginOut(
            token=token,
            id_usuario=user["id_usuario"],
            nombre=user["nombre"],
            email=user["email"],
            fecha_registro=user.get("fecha_registro"),
            clave_drm_maestra=user["clave_drm_maestra"],
        )
    finally:
        conn.close()


# =============================================================================
# AUTH — REGISTRO
# =============================================================================

@app.post("/auth/register", response_model=MsgOut)
def register(body: RegisterIn):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        email = body.email.strip().lower()

        cur.execute(
            "SELECT id_usuario FROM usuarios WHERE email = %s LIMIT 1",
            (email,),
        )
        if cur.fetchone():
            cur.close()
            raise HTTPException(
                status_code=409,
                detail="El correo ya está registrado.",
            )

        hash_pw = hash_password(body.password)
        drm = generar_clave_drm()

        cur.execute(
            """
            INSERT INTO usuarios (nombre, email, contraseña, clave_drm_maestra, estado_cuenta)
            VALUES (%s, %s, %s, %s, 'ACTIVA')
            """,
            (body.nombre.strip(), email, hash_pw, drm),
        )
        conn.commit()
        cur.close()
        return MsgOut(
            status="success",
            message="Cuenta creada. Ya podés iniciar sesión.",
        )
    except HTTPException:
        raise
    except MySQLError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error de base de datos: {e}",
        )
    finally:
        conn.close()


# =============================================================================
# PERFIL
# =============================================================================

@app.get("/auth/me")
def me(user: dict = Depends(usuario_actual)):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id_usuario, nombre, email, clave_drm_maestra, estado_cuenta,
                   DATE_FORMAT(fecha_registro, '%d/%m/%Y') AS fecha_registro
            FROM usuarios WHERE id_usuario = %s LIMIT 1
            """,
            (user["sub"],),
        )
        row = cur.fetchone()
        cur.close()
        if not row:
            raise HTTPException(status_code=404, detail="Usuario no encontrado.")
        return {"status": "success", "datos": row}
    finally:
        conn.close()


# =============================================================================
# VERSIONES PUBLICADAS
# =============================================================================

@app.get("/versiones", response_model=List[VersionOut])
def listar_versiones(user: dict = Depends(usuario_actual)):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id_version AS id, titulo, version,
                   DATE_FORMAT(fecha_salida, '%Y-%m-%d') AS fecha,
                   COALESCE(precio, '$0.00') AS precio,
                   COALESCE(estado, 'DISPONIBLE') AS estado,
                   url_descarga
            FROM versiones_publicadas
            WHERE COALESCE(estado, 'DISPONIBLE') IN ('DISPONIBLE', 'PUBLICADA', 'ACTIVA')
            ORDER BY id_version DESC
            """
        )
        rows = cur.fetchall() or []
        cur.close()
        return [VersionOut(**r) for r in rows]
    finally:
        conn.close()


# =============================================================================
# LICENCIAS
# =============================================================================

@app.get("/licencias", response_model=List[LicenciaOut])
def listar_licencias(user: dict = Depends(usuario_actual)):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT
                la.id_licencia,
                la.id_version,
                v.titulo,
                v.version,
                DATE_FORMAT(la.fecha_adquisicion, '%Y-%m-%d %H:%i') AS fecha_adquisicion,
                la.llave_acceso_aleatoria AS llave_acceso,
                v.url_descarga,
                COALESCE(v.precio, '$0.00') AS precio
            FROM licencias_adquiridas la
            INNER JOIN versiones_publicadas v ON v.id_version = la.id_version
            WHERE la.id_usuario = %s
            ORDER BY la.fecha_adquisicion DESC
            """,
            (user["sub"],),
        )
        rows = cur.fetchall() or []
        cur.close()
        return [LicenciaOut(**r) for r in rows]
    finally:
        conn.close()


# =============================================================================
# LAUNCHER SYNC (un round-trip)
# =============================================================================

@app.get("/launcher/sync")
def launcher_sync(user: dict = Depends(usuario_actual)):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT id_version AS id, titulo, version,
                   DATE_FORMAT(fecha_salida, '%Y-%m-%d') AS fecha,
                   COALESCE(precio, '$0.00') AS precio,
                   COALESCE(estado, 'DISPONIBLE') AS estado,
                   url_descarga
            FROM versiones_publicadas
            WHERE COALESCE(estado, 'DISPONIBLE') IN ('DISPONIBLE', 'PUBLICADA', 'ACTIVA')
            ORDER BY id_version DESC
            """
        )
        catalogo = cur.fetchall() or []

        cur.execute(
            """
            SELECT
                la.id_licencia,
                la.id_version,
                v.titulo,
                v.version,
                DATE_FORMAT(la.fecha_adquisicion, '%Y-%m-%d %H:%i') AS fecha_adquisicion,
                la.llave_acceso_aleatoria AS llave_acceso,
                v.url_descarga,
                COALESCE(v.precio, '$0.00') AS precio
            FROM licencias_adquiridas la
            INNER JOIN versiones_publicadas v ON v.id_version = la.id_version
            WHERE la.id_usuario = %s
            ORDER BY la.fecha_adquisicion DESC
            """,
            (user["sub"],),
        )
        licencias = cur.fetchall() or []

        ids_comprados = {int(l["id_version"]) for l in licencias}
        adquiribles = [c for c in catalogo if int(c["id"]) not in ids_comprados]

        cur.execute(
            "SELECT clave_drm_maestra FROM usuarios WHERE id_usuario = %s LIMIT 1",
            (user["sub"],),
        )
        u = cur.fetchone() or {}
        cur.close()

        return {
            "status": "success",
            "usuario": {
                "id_usuario": user["sub"],
                "email": user.get("email"),
                "nombre": user.get("nombre"),
                "clave_drm_maestra": u.get("clave_drm_maestra"),
            },
            "licencias": licencias,
            "adquiribles": adquiribles,
            "catalogo": catalogo,
        }
    finally:
        conn.close()


# =============================================================================
# COMPRA
# =============================================================================

@app.post("/licencias/comprar", response_model=MsgOut)
def comprar_version(body: ComprarIn, user: dict = Depends(usuario_actual)):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)

        cur.execute(
            "SELECT id_version, titulo FROM versiones_publicadas WHERE id_version = %s LIMIT 1",
            (body.id_version,),
        )
        ver = cur.fetchone()
        if not ver:
            raise HTTPException(status_code=404, detail="Versión no encontrada.")

        cur.execute(
            """
            SELECT id_licencia FROM licencias_adquiridas
            WHERE id_usuario = %s AND id_version = %s LIMIT 1
            """,
            (user["sub"], body.id_version),
        )
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Ya tenés esta versión.")

        llave = generar_llave_licencia()
        cur.execute(
            """
            INSERT INTO licencias_adquiridas (id_usuario, id_version, llave_acceso_aleatoria)
            VALUES (%s, %s, %s)
            """,
            (user["sub"], body.id_version, llave),
        )
        conn.commit()
        cur.close()
        return MsgOut(
            status="success",
            message=f"Licencia de «{ver['titulo']}» registrada.",
        )
    except HTTPException:
        raise
    except MySQLError as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# =============================================================================
# ENTRYPOINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=False,
        log_level="info",
    )