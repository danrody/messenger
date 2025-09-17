@echo off
title Создание пакета для CloudPab
cd /d "%~dp0"

echo ========================================
echo    СОЗДАНИЕ ПАКЕТА ДЛЯ CLOUDPAB
echo ========================================
echo.

echo Создаю архив cloudpab-deploy...
powershell -Command "Compress-Archive -Path 'cloudpab-deploy\*' -DestinationPath 'messenger-cloudpab-deploy.zip' -Force"

if exist "messenger-cloudpab-deploy.zip" (
    echo ✓ Архив создан: messenger-cloudpab-deploy.zip
    echo.
    echo 📁 Содержимое пакета:
    echo    - server.js (основной файл сервера)
    echo    - package.json (зависимости и скрипты)
    echo    - public/ (фронтенд с современным дизайном)
    echo    - README.md (подробная инструкция)
    echo.
    echo ========================================
    echo    ИНСТРУКЦИЯ ПО РАЗМЕЩЕНИЮ В CLOUDPAB:
    echo ========================================
    echo.
    echo 1. Зайдите в панель управления CloudPab
    echo 2. Создайте новый проект
    echo 3. Загрузите архив: messenger-cloudpab-deploy.zip
    echo 4. Распакуйте архив в корень проекта
    echo 5. Настройте переменные окружения:
    echo    - NODE_ENV=production
    echo    - JWT_SECRET=ваш-супер-секретный-ключ
    echo    - PORT=3000
    echo 6. Запустите проект
    echo.
    echo 🌟 Особенности для CloudPab:
    echo    - Автоматическое определение порта
    echo    - Оптимизированные настройки CORS
    echo    - Health check endpoint
    echo    - Современный градиентный дизайн
    echo    - Полная мобильная адаптация
    echo.
    echo 🔗 После размещения мессенджер будет доступен:
    echo    https://ваш-домен.cloudpab.com
    echo.
    echo 👤 Первый вход:
    echo    Логин: admin
    echo    Пароль: admin123
    echo    (ОБЯЗАТЕЛЬНО СМЕНИТЕ!)
    echo.
    echo 📋 Подробная инструкция в файле: cloudpab-deploy/README.md
    echo.
    echo 🚀 Готово к размещению на CloudPab!
    echo.
) else (
    echo ✗ Ошибка создания архива
)

echo.
pause
