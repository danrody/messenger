import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

async function checkAdmin() {
  try {
    const db = await open({ filename: 'data.sqlite', driver: sqlite3.Database });
    
    // Проверяем всех пользователей
    const users = await db.all('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at');
    console.log('Все пользователи в базе:');
    users.forEach(user => {
      console.log(`ID: ${user.id}, Username: ${user.username}, Admin: ${user.is_admin}, Created: ${user.created_at}`);
    });
    
    // Проверяем админа
    const admin = await db.get('SELECT * FROM users WHERE username = ?', 'admin');
    if (admin) {
      console.log('\nАдмин найден:', admin);
    } else {
      console.log('\nАдмин НЕ найден!');
    }
    
    await db.close();
  } catch (e) {
    console.error('Ошибка:', e);
  }
}

checkAdmin();
