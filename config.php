<?php
// ЗАЩИТА ОТ ПРЯМОГО ЗАПУСКА
// Если кто-то попытается открыть site.ru/config.php, скрипт остановится
if (!defined('SECURE_ACCESS')) {
    header('HTTP/1.0 403 Forbidden');
    die('Direct access not permitted');
}

// Настройки логирования (лучше держать их здесь или в index.php)
ini_set('log_errors', 1);
ini_set('display_errors', 0); // Скрываем ошибки от посетителей
ini_set('error_log', __DIR__ . '/error_log.log'); // Лог ошибок рядом с файлом
error_reporting(E_ALL);

return [
    // База данных (Вставьте СЮДА новый пароль)
    'db_host' => 'localhost',
    'db_user' => 'ivanal61_imagop',
    'db_pass' => 'dvQXZc1!QaLZ',
    'db_name' => 'ivanal61_imagop',
    
    // Настройки безопасности
    'session_name' => 'PHOTOHOST_SID',
    'session_lifetime' => 3600, // 1 час
    'max_login_attempts' => 5,
    'block_duration' => 900, // 15 минут
    
    // Настройки приложения
    'per_page' => 20,
    'upload_max_file_size' => 10 * 1024 * 1024, // 10 МБ
    'upload_max_total' => 100 * 1024 * 1024, // 100 МБ на пользователя
];