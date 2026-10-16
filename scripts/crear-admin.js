'use strict';
// Ejecutar: node scripts/crear-admin.js
// Crea el primer superadmin en la base de datos.
// Requiere DATABASE_URL en .env.local

const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');
const readline = require('readline');
const sql = neon(process.env.DATABASE_URL);

function hashPassword(plain) {
  const salt = crypto.randomUUID().replace(/-/g, '');
  let v = salt + ':' + String(plain);
  for (let i = 0; i < 12000; i++) v = crypto.createHash('sha256').update(v, 'utf8').digest('hex');
  return salt + '$' + v;
}

function genId() {
  return 'usr_' + crypto.randomBytes(6).toString('hex');
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = q => new Promise(res => rl.question(q, res));

async function main() {
  console.log('\n── Crear primer SUPERADMIN ──────────────────────\n');

  const email = await ask('Email: ');
  const nombre = await ask('Nombre completo: ');
  const usuario = await ask('Usuario (login): ');
  const pwd = await ask('Contraseña (mín. 12 chars): ');

  if (pwd.length < 12) { console.error('Contraseña muy corta.'); process.exit(1); }

  const hash = hashPassword(pwd);
  const id = genId();

  await sql`
    INSERT INTO usuarios (id_usuario, usuario, nombre, email, password_hash, rol, activo)
    VALUES (${id}, ${usuario.toLowerCase()}, ${nombre}, ${email.toLowerCase()}, ${hash}, 'superadmin', 'SI')
    ON CONFLICT (email) DO UPDATE SET
      password_hash = EXCLUDED.password_hash,
      rol = 'superadmin',
      activo = 'SI'
  `;

  console.log('\n✓ SUPERADMIN creado:');
  console.log('  ID     :', id);
  console.log('  Usuario:', usuario.toLowerCase());
  console.log('  Email  :', email.toLowerCase());
  console.log('  Rol    : superadmin\n');

  rl.close();
  process.exit(0);
}

main().catch(e => { console.error('\nError:', e.message); process.exit(1); });
