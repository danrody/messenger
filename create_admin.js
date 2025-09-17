import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';

async function createAdmin() {
  try {
    const db = await open({ filename: 'data.sqlite', driver: sqlite3.Database });
    
    // Удаляем существующего админа если есть
    await db.run('DELETE FROM users WHERE username = ?', 'admin');
    
    // Создаем нового админа
    const adminPasswordHash = await bcrypt.hash('admin123', 10);
    const result = await db.run('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)', 'admin', adminPasswordHash, 1);
    
    console.log('Админ создан успешно!');
    console.log('Логин: admin');
    console.log('Пароль: admin123');
    console.log('ID:', result.lastID);
    
    await db.close();
  } catch (e) {
    console.error('Ошибка:', e);
  }
}

createAdmin();
