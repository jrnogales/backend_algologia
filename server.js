require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware para verificar token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Token no proporcionado' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.usuario = decoded;
    next();
  });
};

// Rutas públicas
app.get('/api/usuarios/tipos-sangre', async (_, res) => {
  const result = await pool.query('SELECT * FROM tipos_sangre');
  res.json(result.rows);
});

app.get('/api/patologias', async (_, res) => {
  const result = await pool.query('SELECT * FROM patologias');
  res.json(result.rows);
});

app.get('/api/horarios', async (_, res) => {
  const result = await pool.query('SELECT * FROM horarios ORDER BY hora');
  res.json(result.rows);
});

app.get('/api/precio-cita', async (_, res) => {
  const result = await pool.query("SELECT valor FROM configuracion WHERE clave = 'precio_cita'");
  res.json({ precio: parseFloat(result.rows[0].valor) });
});

// Registro
app.post('/api/usuarios/registrar', async (req, res) => {
  const { nombres, apellidos, telefono, email, fecha_nacimiento, tipo_sangre_id, usuario, contrasena } = req.body;
  const hashed = await bcrypt.hash(contrasena, 10);
  await pool.query(
    'INSERT INTO usuarios (nombres, apellidos, telefono, email, fecha_nacimiento, tipo_sangre_id, usuario, contrasena) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
    [nombres, apellidos, telefono, email, fecha_nacimiento, tipo_sangre_id, usuario, hashed]
  );
  res.json({ message: 'Usuario registrado' });
});

// Login
app.post('/api/usuarios/login', async (req, res) => {
  const { usuario, contrasena } = req.body;
  const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
  if (result.rows.length === 0) return res.status(404).json({ message: 'Usuario no encontrado' });

  const user = result.rows[0];
  const valid = await bcrypt.compare(contrasena, user.contrasena);
  if (!valid) return res.status(401).json({ message: 'Contraseña incorrecta' });

  const token = jwt.sign({ id: user.id, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({
    token,
    usuario: {
      nombres: user.nombres
    }
  });
});

// Añadir cita al carrito (requiere login)
app.post('/api/carrito', verifyToken, async (req, res) => {
  const { patologia_id, fecha, hora_id } = req.body;
  const usuario_id = req.usuario.id;

  try {
    await pool.query(
      'INSERT INTO carrito (usuario_id, patologia_id, fecha, hora_id) VALUES ($1, $2, $3, $4)',
      [usuario_id, patologia_id, fecha, hora_id]
    );
    res.json({ message: 'Cita añadida al carrito correctamente.' });
  } catch (error) {
    console.error("Error al insertar en carrito:", error);
    res.status(500).json({ message: 'Error al añadir cita al carrito.' });
  }
});

// ✅ ELIMINAR cita del carrito (cuando ya ha iniciado sesión)
app.delete('/api/carrito/eliminar', verifyToken, async (req, res) => {
  const { fecha, hora } = req.body;
  const usuario_id = req.usuario.id;

  try {
    const result = await pool.query(
      `DELETE FROM carrito
       WHERE usuario_id = $1 AND fecha = $2 AND hora_id = (
         SELECT id FROM horarios WHERE hora = $3
       )`,
      [usuario_id, fecha, hora]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "Cita no encontrada en el carrito." });
    }

    res.json({ message: "Cita eliminada del carrito." });
  } catch (error) {
    console.error("Error eliminando cita del carrito:", error);
    res.status(500).json({ message: "Error al eliminar la cita." });
  }
});

// Obtener carrito del usuario
app.get('/api/carrito', verifyToken, async (req, res) => {
  const result = await pool.query(
    `SELECT c.id, p.nombre AS patologia, c.fecha, h.hora FROM carrito c
     JOIN patologias p ON p.id = c.patologia_id
     JOIN horarios h ON h.id = c.hora_id
     WHERE c.usuario_id = $1`,
    [req.usuario.id]
  );
  res.json(result.rows);
});

// Facturar: pasa las citas del carrito a citas confirmadas y genera factura
app.post('/api/facturar', verifyToken, async (req, res) => {
  const usuario_id = req.usuario.id;
  const citas = await pool.query('SELECT * FROM carrito WHERE usuario_id = $1', [usuario_id]);
  const precioRow = await pool.query("SELECT valor FROM configuracion WHERE clave = 'precio_cita'");
  const precio = parseFloat(precioRow.rows[0].valor);
  const subtotal = citas.rowCount * precio;
  const iva = subtotal * 0.15;
  const total = subtotal + iva;

  const factura = await pool.query(
    'INSERT INTO facturas (usuario_id, subtotal, iva, total) VALUES ($1,$2,$3,$4) RETURNING id',
    [usuario_id, subtotal, iva, total]
  );

  for (let cita of citas.rows) {
    const nueva = await pool.query(
      'INSERT INTO citas (usuario_id, patologia_id, fecha, hora_id, precio) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [usuario_id, cita.patologia_id, cita.fecha, cita.hora_id, precio]
    );
    await pool.query('INSERT INTO detalle_factura (factura_id, cita_id) VALUES ($1, $2)', [factura.rows[0].id, nueva.rows[0].id]);
  }

  await pool.query('DELETE FROM carrito WHERE usuario_id = $1', [usuario_id]);
  res.json({ message: 'Factura generada', total });
});

// Rutas administrativas
app.get('/api/admin/citas', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const result = await pool.query(
    `SELECT c.id, u.usuario, p.nombre AS patologia, c.fecha, h.hora, c.precio
     FROM citas c
     JOIN usuarios u ON u.id = c.usuario_id
     JOIN patologias p ON p.id = c.patologia_id
     JOIN horarios h ON h.id = c.hora_id
     ORDER BY c.fecha, h.hora`
  );
  res.json(result.rows);
});

app.delete('/api/admin/citas/:id', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  await pool.query('DELETE FROM citas WHERE id = $1', [req.params.id]);
  res.json({ message: 'Cita eliminada' });
});

app.put('/api/admin/precio', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const { nuevo_precio } = req.body;
  await pool.query("UPDATE configuracion SET valor = $1 WHERE clave = 'precio_cita'", [nuevo_precio]);
  res.json({ message: 'Precio actualizado' });
});

app.get('/api/admin/facturas', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const result = await pool.query(
    `SELECT f.id, u.usuario, f.fecha, f.subtotal, f.iva, f.total
     FROM facturas f
     JOIN usuarios u ON u.id = f.usuario_id
     ORDER BY f.fecha DESC`
  );
  res.json(result.rows);
});

app.get('/api/admin/soporte', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const result = await pool.query(
    `SELECT s.id, u.usuario, s.asunto, s.mensaje, s.fecha_envio
     FROM soporte s
     JOIN usuarios u ON u.id = s.usuario_id
     ORDER BY s.fecha_envio DESC`
  );
  res.json(result.rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Servidor corriendo en puerto ' + PORT));
