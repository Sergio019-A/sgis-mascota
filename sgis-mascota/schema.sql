-- SGIS-Mascota: esquema de base de datos (SQLite, 3FN)
CREATE TABLE IF NOT EXISTS clientes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL, telefono TEXT NOT NULL, direccion TEXT NOT NULL, correo TEXT
);
CREATE TABLE IF NOT EXISTS mascotas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
  nombre TEXT NOT NULL, especie TEXT NOT NULL, raza TEXT, edad INTEGER NOT NULL CHECK (edad >= 0), observaciones TEXT
);
CREATE TABLE IF NOT EXISTS servicios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL,
  tipo TEXT NOT NULL CHECK (tipo IN ('Salud','Vacunación','Estética','Entrenamiento','Funerario')),
  precio REAL NOT NULL CHECK (precio >= 0)
);
CREATE TABLE IF NOT EXISTS planes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL, precio REAL NOT NULL CHECK (precio >= 0),
  periodicidad TEXT NOT NULL CHECK (periodicidad IN ('Único','Mensual','Trimestral','Anual'))
);
CREATE TABLE IF NOT EXISTS plan_servicios (
  plan_id INTEGER NOT NULL REFERENCES planes(id) ON DELETE CASCADE,
  servicio_id INTEGER NOT NULL REFERENCES servicios(id),
  PRIMARY KEY (plan_id, servicio_id)
);
CREATE TABLE IF NOT EXISTS contratos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
  plan_id INTEGER NOT NULL REFERENCES planes(id), fecha TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS personal (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL,
  cargo TEXT NOT NULL CHECK (cargo IN ('Veterinario','Estilista','Entrenador')),
  turno TEXT NOT NULL CHECK (turno IN ('Mañana','Tarde'))
);
CREATE TABLE IF NOT EXISTS citas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mascota_id INTEGER NOT NULL REFERENCES mascotas(id),
  servicio_id INTEGER NOT NULL REFERENCES servicios(id),
  personal_id INTEGER NOT NULL REFERENCES personal(id),
  fecha TEXT NOT NULL, hora TEXT NOT NULL,
  estado TEXT NOT NULL DEFAULT 'Programada' CHECK (estado IN ('Programada','Atendida','Cancelada'))
);
CREATE TABLE IF NOT EXISTS tratamientos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cita_id INTEGER NOT NULL REFERENCES citas(id) ON DELETE CASCADE,
  descripcion TEXT NOT NULL, fecha TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quejas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
  descripcion TEXT NOT NULL,
  estado TEXT NOT NULL DEFAULT 'Abierta' CHECK (estado IN ('Abierta','En proceso','Cerrada')),
  fecha TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notificaciones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cita_id INTEGER NOT NULL REFERENCES citas(id) ON DELETE CASCADE,
  tipo TEXT NOT NULL, mensaje TEXT NOT NULL, fecha TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  rol TEXT NOT NULL CHECK (rol IN ('administrador','personal','cliente')),
  cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE,
  personal_id INTEGER REFERENCES personal(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_citas_personal ON citas(personal_id, fecha, hora);
CREATE INDEX IF NOT EXISTS idx_mascotas_cliente ON mascotas(cliente_id);
