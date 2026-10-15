-- ════════════════════════════════════════════════════════════════════
--  Personal DMTH — Schema inicial (Neon / PostgreSQL)
--  Ejecutar desde Neon Dashboard → SQL Editor
-- ════════════════════════════════════════════════════════════════════

-- ── Config ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS config (
  clave TEXT PRIMARY KEY,
  valor TEXT DEFAULT '',
  descripcion TEXT DEFAULT '',
  fecha_actualizacion TIMESTAMPTZ DEFAULT NOW()
);

-- ── Usuarios ────────────────────────────────────────────────────────
-- roles: superadmin | admin | user | read
CREATE TABLE IF NOT EXISTS usuarios (
  id_usuario TEXT PRIMARY KEY,
  usuario TEXT UNIQUE NOT NULL,
  nombre TEXT DEFAULT '',
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT DEFAULT '',
  rol TEXT DEFAULT 'read' CHECK (rol IN ('superadmin','admin','user','read')),
  activo TEXT DEFAULT 'SI',
  ultimo_login TIMESTAMPTZ,
  fecha_alta TIMESTAMPTZ DEFAULT NOW(),
  fecha_actualizacion TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios (email);

-- ── Agentes ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agentes (
  id_agente TEXT PRIMARY KEY,
  cuil TEXT DEFAULT '',
  dni TEXT DEFAULT '',
  apellido TEXT DEFAULT '',
  nombre TEXT DEFAULT '',
  apellido_nombre TEXT DEFAULT '',
  telefono TEXT DEFAULT '',
  email TEXT DEFAULT '',
  fecha_nacimiento TEXT DEFAULT '',
  foto_url TEXT DEFAULT '',
  establecimiento TEXT DEFAULT '',
  localidad TEXT DEFAULT '',
  sector TEXT DEFAULT '',
  tarea_puesto TEXT DEFAULT '',
  categoria TEXT DEFAULT '',
  nivel_educativo TEXT DEFAULT '',
  tipo_contratacion TEXT DEFAULT '',
  fecha_ingreso TEXT DEFAULT '',
  fecha_baja TEXT DEFAULT '',
  motivo_baja TEXT DEFAULT '',
  codigo_1 TEXT DEFAULT '',
  codigo_2 TEXT DEFAULT '',
  codigo_3 TEXT DEFAULT '',
  codigo_4 TEXT DEFAULT '',
  codigo_5 TEXT DEFAULT '',
  activo TEXT DEFAULT 'SI',
  observaciones TEXT DEFAULT '',
  search_key TEXT DEFAULT '',
  fecha_alta TIMESTAMPTZ DEFAULT NOW(),
  fecha_actualizacion TIMESTAMPTZ DEFAULT NOW(),
  usuario_actualizacion TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agentes_search ON agentes USING gin(to_tsvector('simple', search_key));
CREATE INDEX IF NOT EXISTS idx_agentes_search_pat ON agentes (search_key text_pattern_ops);
CREATE INDEX IF NOT EXISTS idx_agentes_activo ON agentes (activo);
CREATE INDEX IF NOT EXISTS idx_agentes_cuil ON agentes (cuil);
CREATE INDEX IF NOT EXISTS idx_agentes_dni ON agentes (dni);
CREATE INDEX IF NOT EXISTS idx_agentes_establecimiento ON agentes (establecimiento);
CREATE INDEX IF NOT EXISTS idx_agentes_sector ON agentes (sector);

-- ── Historial del agente ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS historial_agente (
  id TEXT PRIMARY KEY,
  id_agente TEXT NOT NULL,
  fecha TIMESTAMPTZ DEFAULT NOW(),
  tipo_cambio TEXT DEFAULT '',  -- ALTA, BAJA, REINGRESO, CAMBIO_ESTABLECIMIENTO, CAMBIO_SECTOR, MODIFICACION, etc.
  campo_modificado TEXT DEFAULT '',
  valor_anterior TEXT DEFAULT '',
  valor_nuevo TEXT DEFAULT '',
  observaciones TEXT DEFAULT '',
  usuario TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hist_agente ON historial_agente (id_agente, fecha DESC);

-- ── Órdenes de Salida ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ordenes_salida (
  id TEXT PRIMARY KEY,
  numero_orden TEXT DEFAULT '',
  fecha TEXT DEFAULT '',
  hora_salida TEXT DEFAULT '',
  hora_retorno TEXT DEFAULT '',
  dni TEXT DEFAULT '',
  apellido_nombre TEXT DEFAULT '',
  sector TEXT DEFAULT '',
  destino TEXT DEFAULT '',
  motivo TEXT DEFAULT '',
  vehiculo TEXT DEFAULT '',
  tipo TEXT DEFAULT '',
  autorizado_por TEXT DEFAULT '',
  observaciones TEXT DEFAULT '',
  activo TEXT DEFAULT 'SI',
  fecha_carga TIMESTAMPTZ DEFAULT NOW(),
  usuario_carga TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_os_fecha ON ordenes_salida (fecha DESC);
CREATE INDEX IF NOT EXISTS idx_os_dni ON ordenes_salida (dni);

-- ── Órdenes de Trabajo ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ordenes_trabajo (
  id TEXT PRIMARY KEY,
  numero_orden TEXT DEFAULT '',
  fecha TEXT DEFAULT '',
  dni TEXT DEFAULT '',
  apellido_nombre TEXT DEFAULT '',
  sector TEXT DEFAULT '',
  cuadrilla TEXT DEFAULT '',
  tarea TEXT DEFAULT '',
  destino TEXT DEFAULT '',
  cantidad_horas TEXT DEFAULT '',
  observaciones TEXT DEFAULT '',
  activo TEXT DEFAULT 'SI',
  fecha_carga TIMESTAMPTZ DEFAULT NOW(),
  usuario_carga TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ot_fecha ON ordenes_trabajo (fecha DESC);
CREATE INDEX IF NOT EXISTS idx_ot_dni ON ordenes_trabajo (dni);

-- ── Logs ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS logs (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  usuario TEXT DEFAULT '',
  accion TEXT DEFAULT '',
  entidad TEXT DEFAULT '',
  id_entidad TEXT DEFAULT '',
  detalle TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (timestamp DESC);

-- ── Datos por defecto ────────────────────────────────────────────────
INSERT INTO config (clave, valor, descripcion) VALUES
  ('app_name', 'Personal DMTH', 'Nombre visible del sistema'),
  ('app_version', '1.0.0', 'Versión del sistema'),
  ('org_nombre', 'DMTH', 'Nombre de la organización'),
  ('org_logo_url', '', 'URL del logo de la organización')
ON CONFLICT (clave) DO NOTHING;
