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

app.get('/api/configuracion/iva', async (_, res) => {
  try {
    const result = await pool.query("SELECT valor FROM configuracion WHERE clave = 'iva'");
    res.json({ valor: parseFloat(result.rows[0].valor) });
  } catch (error) {
    console.error("Error al obtener IVA:", error);
    res.status(500).json({ message: "Error al obtener el IVA" });
  }
});

// Obtener detalle completo de una factura
app.get('/api/admin/factura/:id', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const { id } = req.params;

  try {
    const result = await pool.query(`
      SELECT 
        CONCAT(u.nombres, ' ', u.apellidos) AS cliente,
        p.nombre AS patologia,
        c.fecha,
        h.hora,
        c.precio
      FROM detalle_factura df
      JOIN facturas f ON f.id = df.factura_id
      JOIN citas c ON c.id = df.cita_id
      JOIN usuarios u ON u.id = c.usuario_id
      JOIN patologias p ON p.id = c.patologia_id
      JOIN horarios h ON h.id = c.hora_id
      WHERE f.id = $1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Factura no encontrada o sin detalles." });
    }

    // Extraer info del encabezado desde la primera fila
    const encabezado = {
      id,
      cliente: result.rows[0].cliente,
      fecha: result.rows[0].fecha,
      subtotal: result.rows.reduce((sum, row) => sum + parseFloat(row.precio), 0),
    };

    // Consultar el IVA desde base de datos
    const ivaRes = await pool.query(`SELECT valor FROM configuracion WHERE clave = 'iva'`);
    const ivaPorcentaje = parseFloat(ivaRes.rows[0].valor);

    const iva = parseFloat((encabezado.subtotal * ivaPorcentaje).toFixed(2));
    const total = parseFloat((encabezado.subtotal + iva).toFixed(2));

    res.json({
      factura: {
        id,
        cliente: encabezado.cliente,
        fecha: encabezado.fecha,
        subtotal: encabezado.subtotal,
        iva,
        total
      },
      detalle: result.rows.map(row => ({
        patologia: row.patologia,
        fecha: row.fecha,
        hora: row.hora,
        precio: parseFloat(row.precio)
      }))
    });

  } catch (error) {
    console.error("Error al obtener detalle de factura:", error);
    res.status(500).json({ message: "Error al obtener detalle de factura" });
  }
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

app.post('/api/carrito', verifyToken, async (req, res) => {
  const { patologia_id, fecha, hora_id } = req.body;
  const usuario_id = req.usuario.id;

  try {
    // Validar si ya existe en carrito
    const existeEnCarrito = await pool.query(
      'SELECT * FROM carrito WHERE usuario_id = $1 AND fecha = $2 AND hora_id = $3',
      [usuario_id, fecha, hora_id]
    );

    if (existeEnCarrito.rowCount > 0) {
      return res.status(400).json({ message: 'Ya tienes esta cita en tu carrito.' });
    }

    // Validar si existe ya como cita confirmada
    const existeConfirmada = await pool.query(
      'SELECT * FROM citas WHERE fecha = $1 AND hora_id = $2',
      [fecha, hora_id]
    );

    if (existeConfirmada.rowCount > 0) {
      return res.status(400).json({ message: 'Esta hora ya fue reservada por otro usuario.' });
    }

    await pool.query(
      'INSERT INTO carrito (usuario_id, patologia_id, fecha, hora_id) VALUES ($1, $2, $3, $4)',
      [usuario_id, patologia_id, fecha, hora_id]
    );

    res.json({ message: 'Cita añadida al carrito correctamente.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al añadir cita al carrito.' });
  }
});


// Eliminar cita del carrito (requiere login)
app.delete('/api/carrito/eliminar', verifyToken, async (req, res) => {
  const { fecha, hora } = req.body;
  const usuario_id = req.usuario.id;

  try {
    const result = await pool.query(
      `DELETE FROM carrito WHERE usuario_id = $1 AND fecha = $2 AND hora_id = (SELECT id FROM horarios WHERE hora = $3)`,
      [usuario_id, fecha, hora]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: "Cita no encontrada en el carrito." });
    res.json({ message: "Cita eliminada del carrito." });
  } catch (error) {
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

// Generar factura (valores calculados en frontend)
app.post('/api/facturar', verifyToken, async (req, res) => {
  try {
    const usuario_id = req.usuario.id;
    const { subtotal, iva, total } = req.body;

    const citas = await pool.query('SELECT * FROM carrito WHERE usuario_id = $1', [usuario_id]);
    if (citas.rowCount === 0) return res.status(400).json({ message: 'No hay citas en el carrito.' });

    const factura = await pool.query(
      'INSERT INTO facturas (usuario_id, subtotal, iva, total) VALUES ($1,$2,$3,$4) RETURNING id',
      [usuario_id, subtotal, iva, total]
    );

    for (let cita of citas.rows) {
      const nueva = await pool.query(
        'INSERT INTO citas (usuario_id, patologia_id, fecha, hora_id, precio) VALUES ($1,$2,$3,$4,$5) RETURNING id',
        [usuario_id, cita.patologia_id, cita.fecha, cita.hora_id, subtotal / citas.rowCount]
      );
      await pool.query('INSERT INTO detalle_factura (factura_id, cita_id) VALUES ($1, $2)', [factura.rows[0].id, nueva.rows[0].id]);
    }

    await pool.query('DELETE FROM carrito WHERE usuario_id = $1', [usuario_id]);
    res.json({ message: 'Factura generada', total });
  } catch (err) {
    console.error("Error al facturar:", err);
    res.status(500).json({ message: 'Error inesperado al generar factura.' });
  }
});

// Ruta pública: citas confirmadas para bloqueo
app.get('/api/citas/ocupadas', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT fecha, h.hora
      FROM citas c
      JOIN horarios h ON c.hora_id = h.id
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("Error al obtener citas ocupadas:", err);
    res.status(500).json({ message: "Error al obtener citas ocupadas" });
  }
});

// Obtener citas del carrito del usuario (bloqueo temporal)
app.get('/api/carrito/usuario', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT fecha, h.hora
      FROM carrito c
      JOIN horarios h ON c.hora_id = h.id
      WHERE c.usuario_id = $1
    `, [req.usuario.id]);

    res.json(result.rows);
  } catch (error) {
    console.error("Error al obtener citas del carrito:", error);
    res.status(500).json({ message: "Error al obtener citas del carrito" });
  }
});
// Añadir mensaje de soporte del usuario logueado
app.post('/api/soporte', verifyToken, async (req, res) => {
  const { asunto, mensaje } = req.body;
  const usuario_id = req.usuario.id;

  try {
    await pool.query(
      'INSERT INTO soporte (usuario_id, asunto, mensaje) VALUES ($1, $2, $3)',
      [usuario_id, asunto, mensaje]
    );

    res.json({ message: 'Mensaje enviado con éxito.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al enviar mensaje.' });
  }
});

// Usuarios
app.get('/api/admin/usuarios', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const result = await pool.query('SELECT id, nombres, apellidos, email, usuario, rol FROM usuarios ORDER BY id');
  res.json(result.rows);
});

app.delete('/api/admin/usuarios/:id', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
  res.json({ message: 'Usuario eliminado' });
});

// Patologías
app.post('/api/admin/patologias', verifyToken, async (req, res) => {
  const { nombre } = req.body;
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  await pool.query('INSERT INTO patologias (nombre) VALUES ($1)', [nombre]);
  res.json({ message: 'Patología añadida' });
});

app.delete('/api/admin/patologias/:id', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  await pool.query('DELETE FROM patologias WHERE id = $1', [req.params.id]);
  res.json({ message: 'Patología eliminada' });
});

// Horarios
app.post('/api/admin/horarios', verifyToken, async (req, res) => {
  const { hora } = req.body;
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  await pool.query('INSERT INTO horarios (hora) VALUES ($1)', [hora]);
  res.json({ message: 'Horario añadido' });
});

app.delete('/api/admin/horarios/:id', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  await pool.query('DELETE FROM horarios WHERE id = $1', [req.params.id]);
  res.json({ message: 'Horario eliminado' });
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

app.put('/api/admin/iva', verifyToken, async (req, res) => {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const { nuevo_iva } = req.body;
  await pool.query("UPDATE configuracion SET valor = $1 WHERE clave = 'iva'", [nuevo_iva]);
  res.json({ message: 'IVA actualizado' });
});
// Validar existencia de usuario (para registro en tiempo real)
app.get('/api/usuarios/existe/:usuario', async (req, res) => {
  const { usuario } = req.params;
  try {
    const result = await pool.query('SELECT id FROM usuarios WHERE usuario = $1', [usuario]);
    res.json({ existe: result.rowCount > 0 });
  } catch (error) {
    console.error("Error al verificar existencia del usuario:", error);
    res.status(500).json({ message: "Error en la validación de usuario" });
  }
});


// Arranque del servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Servidor corriendo en puerto ' + PORT));
