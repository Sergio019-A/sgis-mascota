// SGIS-Mascota - Servidor (Node.js + Express + SQLite)
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'cambiar-esta-clave-en-produccion';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'sgis.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('foreign_keys = ON');
db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));

// ---------- Definición de tablas, permisos y alcance por rol ----------
// cols: columnas editables. opt: columnas opcionales.
const T = {
  clientes:     { cols: ['nombre', 'telefono', 'direccion', 'correo'], opt: ['correo'] },
  mascotas:     { cols: ['cliente_id', 'nombre', 'especie', 'raza', 'edad', 'observaciones'], opt: ['raza', 'observaciones'] },
  servicios:    { cols: ['nombre', 'tipo', 'precio'], opt: [] },
  planes:       { cols: ['nombre', 'precio', 'periodicidad'], opt: [] },
  contratos:    { cols: ['cliente_id', 'plan_id', 'fecha'], opt: [] },
  personal:     { cols: ['nombre', 'cargo', 'turno'], opt: [] },
  citas:        { cols: ['mascota_id', 'servicio_id', 'personal_id', 'fecha', 'hora', 'estado'], opt: [] },
  tratamientos: { cols: ['cita_id', 'descripcion', 'fecha'], opt: [] },
  quejas:       { cols: ['cliente_id', 'descripcion', 'estado', 'fecha'], opt: [] },
  usuarios:     { cols: ['username', 'password_hash', 'rol', 'cliente_id', 'personal_id'], opt: ['cliente_id', 'personal_id'],
                  sel: 'id, username, rol, cliente_id, personal_id' },
};
// Permisos: r=leer, c=crear, u=actualizar, d=eliminar (RF-13: perfiles de acceso)
const P = {
  administrador: Object.fromEntries(Object.keys(T).map(t => [t, 'rcud'])),
  personal: { clientes: 'r', mascotas: 'r', servicios: 'r', planes: 'r', personal: 'r', citas: 'ru', tratamientos: 'rcud' },
  cliente: { clientes: 'ru', mascotas: 'rcud', servicios: 'r', planes: 'r', personal: 'r', citas: 'rcu', tratamientos: 'r', quejas: 'rc', contratos: 'rc' },
};
const SC = { // filtro de filas por rol (cada usuario solo ve lo suyo)
  cliente: {
    clientes: 'id=@cid', mascotas: 'cliente_id=@cid', quejas: 'cliente_id=@cid', contratos: 'cliente_id=@cid',
    citas: 'mascota_id IN (SELECT id FROM mascotas WHERE cliente_id=@cid)',
    tratamientos: 'cita_id IN (SELECT id FROM citas WHERE mascota_id IN (SELECT id FROM mascotas WHERE cliente_id=@cid))',
  },
  personal: {
    citas: 'personal_id=@pid',
    tratamientos: 'cita_id IN (SELECT id FROM citas WHERE personal_id=@pid)',
  },
};
const hoy = () => new Date().toISOString().slice(0, 10);
const num = v => (v === '' || v == null ? null : Number(v));

// ---------- App ----------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const fail = (res, code, msg) => res.status(code).json({ error: msg });

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  try {
    const d = jwt.verify(h.replace('Bearer ', ''), SECRET);
    req.u = { id: d.id, rol: d.rol, cid: d.cid ?? -1, pid: d.pid ?? -1 };
    next();
  } catch { fail(res, 401, 'Sesión no válida o expirada'); }
}
const can = (u, t, a) => (P[u.rol][t] || '').includes(a);
const scope = (u, t) => (SC[u.rol] && SC[u.rol][t]) || null;
const params = u => ({ cid: u.cid, pid: u.pid });

// ---------- Autenticación ----------
const tokenFor = u => jwt.sign({ id: u.id, rol: u.rol, cid: u.cliente_id, pid: u.personal_id }, SECRET, { expiresIn: '8h' });

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT * FROM usuarios WHERE username=?').get(String(username || '').trim());
  if (!u || !bcrypt.compareSync(String(password || ''), u.password_hash)) return fail(res, 401, 'Usuario o contraseña incorrectos');
  res.json({ token: tokenFor(u), rol: u.rol, username: u.username });
});

app.post('/api/register', (req, res) => { // autorregistro de clientes
  const { nombre, telefono, direccion, correo, username, password } = req.body || {};
  if (!nombre || !telefono || !direccion || !username || !password) return fail(res, 400, 'Complete todos los campos obligatorios');
  if (String(password).length < 6) return fail(res, 400, 'La contraseña debe tener al menos 6 caracteres');
  if (db.prepare('SELECT 1 FROM usuarios WHERE username=?').get(username)) return fail(res, 409, 'El usuario ya existe');
  db.transaction(() => {
    const c = db.prepare('INSERT INTO clientes(nombre,telefono,direccion,correo) VALUES(?,?,?,?)').run(nombre, telefono, direccion, correo || null);
    db.prepare("INSERT INTO usuarios(username,password_hash,rol,cliente_id) VALUES(?,?, 'cliente', ?)").run(username, bcrypt.hashSync(password, 10), c.lastInsertRowid);
  })();
  res.status(201).json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ rol: req.u.rol, perms: P[req.u.rol] }));

// ---------- Reportes (RF-11) y notificaciones (RF-07) ----------
app.get('/api/reportes', auth, (req, res) => {
  if (req.u.rol !== 'administrador') return fail(res, 403, 'Sin permiso');
  const q = s => db.prepare(s).all();
  res.json({
    totales: db.prepare(`SELECT (SELECT COUNT(*) FROM clientes) clientes, (SELECT COUNT(*) FROM mascotas) mascotas,
      (SELECT COUNT(*) FROM citas) citas, (SELECT COUNT(*) FROM tratamientos) tratamientos,
      (SELECT COUNT(*) FROM quejas WHERE estado!='Cerrada') quejas_abiertas`).get(),
    citas_por_estado: q('SELECT estado, COUNT(*) total FROM citas GROUP BY estado'),
    servicios_prestados: q("SELECT s.tipo, COUNT(*) total FROM citas c JOIN servicios s ON s.id=c.servicio_id WHERE c.estado!='Cancelada' GROUP BY s.tipo"),
    quejas_por_estado: q('SELECT estado, COUNT(*) total FROM quejas GROUP BY estado'),
    citas_por_personal: q("SELECT p.nombre, COUNT(*) total FROM citas c JOIN personal p ON p.id=c.personal_id WHERE c.estado!='Cancelada' GROUP BY p.nombre"),
  });
});

app.get('/api/notificaciones', auth, (req, res) => {
  const s = scope(req.u, 'citas');
  const rows = db.prepare(`SELECT * FROM notificaciones WHERE ${s ? `cita_id IN (SELECT id FROM citas WHERE ${s})` : '1=1'} ORDER BY id DESC LIMIT 50`).all(s ? params(req.u) : {});
  res.json(rows);
});

// ---------- CRUD genérico ----------
function normalize(t, body, u, isNew) {
  const o = {};
  for (const c of T[t].cols) if (c in body) o[c] = body[c] === '' ? null : body[c];
  for (const c of T[t].cols) if (c.endsWith('_id') || ['edad', 'precio'].includes(c)) if (c in o) o[c] = num(o[c]);
  if (t === 'usuarios' && body.password) {
    if (String(body.password).length < 6) throw { code: 400, msg: 'La contraseña debe tener al menos 6 caracteres' };
    o.password_hash = bcrypt.hashSync(String(body.password), 10);
  }
  if (['tratamientos', 'quejas', 'contratos'].includes(t) && isNew && !o.fecha) o.fecha = hoy();
  if (t === 'quejas' && isNew) o.estado = o.estado || 'Abierta';
  if (t === 'citas' && isNew) o.estado = o.estado || 'Programada';
  // Reglas por rol
  if (u.rol === 'cliente') {
    if (['mascotas', 'quejas', 'contratos'].includes(t)) o.cliente_id = u.cid;
    if (t === 'quejas') { if (isNew) o.estado = 'Abierta'; else delete o.estado; }
    if (t === 'citas' && isNew) o.estado = 'Programada';
    if (t === 'citas' && !db.prepare('SELECT 1 FROM mascotas WHERE id=? AND cliente_id=?').get(o.mascota_id, u.cid))
      if (isNew || 'mascota_id' in o) throw { code: 403, msg: 'La mascota no pertenece al cliente' };
  }
  if (u.rol === 'personal' && t === 'citas') { for (const k of Object.keys(o)) if (k !== 'estado') delete o[k]; }
  if (isNew) {
    const falta = T[t].cols.filter(c => !T[t].opt.includes(c) && (o[c] == null || o[c] === ''));
    if (falta.length) throw { code: 400, msg: 'Faltan campos obligatorios: ' + falta.join(', ') };
  }
  return o;
}

function conflictoCita(o, id) { // RF-06: validar disponibilidad del personal
  if (o.estado === 'Cancelada' || !o.personal_id || !o.fecha || !o.hora) return;
  const c = db.prepare("SELECT id FROM citas WHERE personal_id=? AND fecha=? AND hora=? AND estado!='Cancelada' AND id!=?").get(o.personal_id, o.fecha, o.hora, id || 0);
  if (c) throw { code: 409, msg: 'El personal no está disponible en esa fecha y hora. Elija otro horario o profesional.' };
}

const withExtras = (t, rows) => {
  if (t === 'planes') {
    const ps = db.prepare('SELECT plan_id, servicio_id FROM plan_servicios').all();
    rows.forEach(r => r.servicio_ids = ps.filter(x => x.plan_id === r.id).map(x => x.servicio_id));
  }
  return rows;
};
const setServicios = (planId, ids) => {
  db.prepare('DELETE FROM plan_servicios WHERE plan_id=?').run(planId);
  const ins = db.prepare('INSERT OR IGNORE INTO plan_servicios(plan_id,servicio_id) VALUES(?,?)');
  (ids || []).forEach(s => ins.run(planId, Number(s)));
};

function guard(t, a) {
  return (req, res, next) => {
    if (!T[t]) return fail(res, 404, 'Recurso no existe');
    if (!can(req.u, t, a)) return fail(res, 403, 'No tiene permiso para esta acción');
    next();
  };
}
const handle = fn => (req, res) => {
  try { fn(req, res); }
  catch (e) {
    if (e && e.code && e.msg) return fail(res, e.code, e.msg);
    if (e && String(e.code).startsWith('SQLITE_CONSTRAINT')) {
      return fail(res, 409, String(e.code).includes('FOREIGNKEY') ? 'No se puede completar: hay registros asociados o la referencia no existe' : 'Registro duplicado o dato inválido');
    }
    console.error(e); fail(res, 500, 'Error interno del servidor');
  }
};

for (const t of Object.keys(T)) {
  const r = `/api/${t}`;
  app.get(r, auth, guard(t, 'r'), handle((req, res) => {
    const s = scope(req.u, t);
    const sql = `SELECT ${T[t].sel || '*'} FROM ${t}${s ? ' WHERE ' + s : ''} ORDER BY id`;
    res.json(withExtras(t, db.prepare(sql).all(s ? params(req.u) : {})));
  }));

  app.post(r, auth, guard(t, 'c'), handle((req, res) => {
    const o = normalize(t, req.body || {}, req.u, true);
    if (t === 'citas') conflictoCita(o);
    const ks = Object.keys(o);
    const id = db.transaction(() => {
      const info = db.prepare(`INSERT INTO ${t}(${ks.join(',')}) VALUES(${ks.map(k => '@' + k).join(',')})`).run(o);
      const nid = info.lastInsertRowid;
      if (t === 'planes') setServicios(nid, req.body.servicio_ids);
      if (t === 'citas') {
        const m = db.prepare('SELECT nombre FROM mascotas WHERE id=?').get(o.mascota_id);
        const ins = db.prepare('INSERT INTO notificaciones(cita_id,tipo,mensaje,fecha) VALUES(?,?,?,?)');
        ins.run(nid, 'Confirmación', `Cita confirmada para ${m.nombre} el ${o.fecha} a las ${o.hora}.`, hoy());
        ins.run(nid, 'Recordatorio', `Recordatorio: ${m.nombre} tiene cita el ${o.fecha} a las ${o.hora}.`, hoy());
      }
      return nid;
    })();
    res.status(201).json({ id });
  }));

  app.put(`${r}/:id`, auth, guard(t, 'u'), handle((req, res) => {
    const id = Number(req.params.id);
    const s = scope(req.u, t);
    if (!db.prepare(`SELECT 1 FROM ${t} WHERE id=@id${s ? ' AND ' + s : ''}`).get({ id, ...params(req.u) })) return fail(res, 404, 'Registro no encontrado');
    const o = normalize(t, req.body || {}, req.u, false);
    if (t === 'citas') {
      const actual = db.prepare('SELECT * FROM citas WHERE id=?').get(id);
      conflictoCita({ ...actual, ...o }, id);
    }
    const ks = Object.keys(o);
    db.transaction(() => {
      if (ks.length) db.prepare(`UPDATE ${t} SET ${ks.map(k => k + '=@' + k).join(',')} WHERE id=@id`).run({ ...o, id });
      if (t === 'planes' && Array.isArray(req.body.servicio_ids)) setServicios(id, req.body.servicio_ids);
    })();
    res.json({ ok: true });
  }));

  app.delete(`${r}/:id`, auth, guard(t, 'd'), handle((req, res) => {
    const id = Number(req.params.id);
    const s = scope(req.u, t);
    if (!db.prepare(`SELECT 1 FROM ${t} WHERE id=@id${s ? ' AND ' + s : ''}`).get({ id, ...params(req.u) })) return fail(res, 404, 'Registro no encontrado');
    if (t === 'usuarios' && id === req.u.id) return fail(res, 400, 'No puede eliminar su propio usuario');
    db.prepare(`DELETE FROM ${t} WHERE id=?`).run(id);
    res.json({ ok: true });
  }));
}

app.use('/api', (req, res) => fail(res, 404, 'Ruta no encontrada'));

// ---------- Datos iniciales (solo si la base está vacía) ----------
function seed() {
  if (db.prepare('SELECT COUNT(*) n FROM usuarios').get().n) return;
  const h = p => bcrypt.hashSync(p, 10);
  db.transaction(() => {
    const sv = db.prepare('INSERT INTO servicios(nombre,tipo,precio) VALUES(?,?,?)');
    [['Consulta veterinaria a domicilio', 'Salud', 70000], ['Vacunación', 'Vacunación', 55000], ['Baño y corte', 'Estética', 45000],
     ['Sesión de entrenamiento', 'Entrenamiento', 60000], ['Servicio funerario', 'Funerario', 250000]].forEach(x => sv.run(...x));
    db.prepare("INSERT INTO planes(nombre,precio,periodicidad) VALUES('Plan Bienestar Mensual',120000,'Mensual')").run();
    db.prepare('INSERT INTO plan_servicios VALUES(1,1),(1,2),(1,3)').run();
    const pr = db.prepare('INSERT INTO personal(nombre,cargo,turno) VALUES(?,?,?)');
    pr.run('Dra. Camila Torres', 'Veterinario', 'Mañana'); pr.run('Andrés Ruiz', 'Estilista', 'Tarde'); pr.run('Paola Mejía', 'Entrenador', 'Mañana');
    db.prepare("INSERT INTO clientes(nombre,telefono,direccion,correo) VALUES('Laura Gómez','3001112233','Cra 15 # 80-20, Bogotá','laura@mail.com')").run();
    db.prepare("INSERT INTO mascotas(cliente_id,nombre,especie,raza,edad,observaciones) VALUES(1,'Max','Perro','Labrador',4,'Alérgico a la penicilina')").run();
    const us = db.prepare('INSERT INTO usuarios(username,password_hash,rol,cliente_id,personal_id) VALUES(?,?,?,?,?)');
    us.run('admin', h('Admin123*'), 'administrador', null, null);
    us.run('vet', h('Vet123*'), 'personal', null, 1);
    us.run('cliente', h('Cliente123*'), 'cliente', 1, null);
  })();
  console.log('Base de datos inicializada con datos de ejemplo.');
}
seed();

app.listen(PORT, () => console.log(`SGIS-Mascota en http://localhost:${PORT}`));
