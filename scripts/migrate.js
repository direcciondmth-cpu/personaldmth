'use strict';
// Ejecutar: node --env-file=.env.local scripts/migrate.js
// Aplica migrations/001_schema.sql a la base de datos Neon.

const { Pool } = require('@neondatabase/serverless');
const fs = require('fs');
const path = require('path');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function main() {
  const sqlFile = path.join(__dirname, '..', 'migrations', '001_schema.sql');
  const ddl = fs.readFileSync(sqlFile, 'utf8');

  // Remove single-line comments, then split on semicolons
  const cleaned = ddl.replace(/--[^\n]*/g, '');
  const statements = cleaned
    .split(';')
    .map(s => s.trim())
    .filter(s => s.length > 0);

  console.log(`\n── Ejecutando ${statements.length} sentencias ──────────────────\n`);

  for (const stmt of statements) {
    try {
      await pool.query(stmt + ';');
      const firstLine = stmt.split('\n')[0].substring(0, 60);
      console.log('  ✓', firstLine);
    } catch (e) {
      if (e.message?.includes('already exists')) {
        console.log('  ~ (ya existe)', stmt.split('\n')[0].substring(0, 50));
      } else {
        console.error('  ✗ Error:', e.message);
        console.error('    SQL:', stmt.substring(0, 100));
      }
    }
  }

  console.log('\n✓ Migración completada.\n');
  await pool.end();
  process.exit(0);
}

main().catch(e => { console.error('\nError:', e.message); process.exit(1); });
