<?php
define('SECURE_ACCESS', true);

// 1. ПРИНУДИТЕЛЬНЫЙ HTTPS (REDIRECT)
// Если сертификат есть, мы обязаны перенаправлять всех на HTTPS.
// Google помечает формы входа без HTTPS как "Небезопасные".
$isHttps = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || 
           (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

if (!$isHttps) {
    $redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header('HTTP/1.1 301 Moved Permanently');
    header('Location: ' . $redirect);
    exit;
}

// Подключение конфига
if (file_exists('config.php')) {
    $config = require_once 'config.php';
} else {
    // Фолбэк для демонстрации, если конфига нет
    $config = [
        'session_name' => 'PH_SESS',
        'session_lifetime' => 86400,
        'db_host' => 'localhost',
        'db_user' => 'root',
        'db_pass' => '',
        'db_name' => 'photohost',
        'security_salt' => 'CHANGE_THIS_SALT'
    ];
}

// Настройки сессии для HTTPS
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1); // Строго 1, так как мы форсируем HTTPS
ini_set('session.use_strict_mode', 1);

session_name($config['session_name']);
session_set_cookie_params([
    'lifetime' => $config['session_lifetime'],
    'path' => '/',
    'secure' => true, // Строго true
    'httponly' => true,
    'samesite' => 'Lax'
]);

session_start();

// 2. УСИЛЕННЫЕ ЗАГОЛОВКИ БЕЗОПАСНОСТИ
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
// Content-Security-Policy (CSP) - ОЧЕНЬ ВАЖНО для Google. 
// Разрешаем загрузку только со своего домена + шрифты Google/FontAwesome.
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:;");

// Подключение к БД
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
try {
    $conn = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
    $conn->set_charset("utf8mb4");
} catch (Exception $e) {
    // Не выводим детали ошибки на экран, чтобы не "светить" пути
    error_log("DB Error: " . $e->getMessage());
    die("Service temporarily unavailable. Please try again later.");
}

// --- БЛОК ЗАЩИТЫ ОТ BRUTE FORCE (Оставлен без изменений логики) ---
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ipHash = hash('sha256', $ip . $userAgent . ($config['security_salt'] ?? 'salt'));
$attemptsFile = sys_get_temp_dir() . '/login_' . $ipHash . '.dat';
$blockFile = sys_get_temp_dir() . '/block_' . $ipHash . '.dat';

define('MAX_ATTEMPTS', 5);
define('BLOCK_DURATION', 900);
define('ATTEMPT_WINDOW', 3600);

function checkBruteForce() {
    global $attemptsFile, $blockFile;
    if (file_exists($blockFile)) {
        $blockTime = (int)file_get_contents($blockFile);
        if (time() - $blockTime < BLOCK_DURATION) return true;
        @unlink($blockFile);
    }
    if (file_exists($attemptsFile)) {
        $data = file_get_contents($attemptsFile);
        if ($data === false) return false;
        $parts = explode(':', $data);
        if (count($parts) !== 2) { @unlink($attemptsFile); return false; }
        list($count, $lastTime) = $parts;
        if (time() - (int)$lastTime > ATTEMPT_WINDOW) { @unlink($attemptsFile); return false; }
        if ((int)$count >= MAX_ATTEMPTS) {
            file_put_contents($blockFile, time());
            return true;
        }
    }
    return false;
}

function registerAttempt() {
    global $attemptsFile;
    $count = 1;
    if (file_exists($attemptsFile)) {
        $data = file_get_contents($attemptsFile);
        if ($data !== false) {
            $parts = explode(':', $data);
            if (count($parts) === 2) $count = (int)$parts[0] + 1;
        }
    }
    file_put_contents($attemptsFile, $count . ':' . time());
}

function clearAttempts() {
    global $attemptsFile, $blockFile;
    if (file_exists($attemptsFile)) @unlink($attemptsFile);
    if (file_exists($blockFile)) @unlink($blockFile);
}
// ------------------------------------------------------------------

// Логика выхода
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $_SESSION = [];
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 3600, '/');
    }
    session_destroy();
    header("Location: index.php"); // Редирект на чистый index
    exit;
}

// Если уже авторизован - пускаем внутрь
if (isset($_SESSION['user_id'])) {
    // Здесь должен быть ваш личный кабинет.
    // Для примера просто выведем сообщение.
    echo "<h1>Добро пожаловать, " . htmlspecialchars($_SESSION['username']) . "!</h1>";
    echo "<a href='?action=logout'>Выйти</a>";
    exit;
}

$error = '';
$success = '';
$activeForm = 'login';

// Обработка форм (Логин/Регистрация)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $activeForm = $_POST['type'] ?? 'login';
    
    if (!isset($_POST['token']) || !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['token'])) {
        $error = "Session expired. Please refresh.";
    } elseif (checkBruteForce()) {
        $remainingTime = ceil(BLOCK_DURATION / 60);
        $error = "Too many attempts. Blocked for $remainingTime minutes.";
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        // Валидация
        if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
            $error = "Invalid username format.";
            registerAttempt();
        } elseif (strlen($password) < 6 || strlen($password) > 255) {
            $error = "Invalid password length.";
            registerAttempt();
        } else {
            // ЛОГИКА РЕГИСТРАЦИИ
            if ($activeForm === 'register') {
                $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
                $stmt->bind_param("s", $username);
                $stmt->execute();
                if ($stmt->get_result()->num_rows > 0) {
                    $error = "Username already exists.";
                    registerAttempt();
                } else {
                    // Используем PASSWORD_DEFAULT для максимальной совместимости
                    // Если PHP свежий, он сам выберет лучший алгоритм (bcrypt или argon2)
                    $hash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                    $stmt->bind_param("ss", $username, $hash);
                    if ($stmt->execute()) {
                        $success = "Registration successful! Please login.";
                        $activeForm = 'login';
                        clearAttempts();
                    } else {
                        $error = "Registration failed.";
                    }
                }
                $stmt->close();
            
            // ЛОГИКА ВХОДА
            } else {
                $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
                $stmt->bind_param("s", $username);
                $stmt->execute();
                $res = $stmt->get_result();
                
                if ($row = $res->fetch_assoc()) {
                    if (password_verify($password, $row['password'])) {
                        // Rehash если нужно
                        if (password_needs_rehash($row['password'], PASSWORD_DEFAULT)) {
                            $newHash = password_hash($password, PASSWORD_DEFAULT);
                            $upd = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
                            $upd->bind_param("si", $newHash, $row['id']);
                            $upd->execute();
                        }
                        
                        clearAttempts();
                        session_regenerate_id(true);
                        $_SESSION['user_id'] = (int)$row['id'];
                        $_SESSION['username'] = $row['username'];
                        $_SESSION['login_time'] = time();
                        
                        // Редирект после успешного входа, чтобы сбросить POST данные
                        header("Location: index.php");
                        exit;
                    }
                }
                $error = "Invalid credentials.";
                registerAttempt();
                $stmt->close();
            }
        }
    }
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- NOINDEX: Говорим Google не индексировать страницу входа, это снижает риск попадания в базу фишинга -->
    <meta name="robots" content="noindex, nofollow">
    <meta name="description" content="Secure personal photo storage authentication.">
    <title>Вход в систему - PhotoHost</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg: #030712;
            --card: #0f1629;
            --card-hover: #161d33;
            --primary: #818cf8;
            --primary-hover: #6366f1;
            --primary-glow: rgba(129, 140, 248, 0.35);
            --accent: #c084fc;
            --accent-glow: rgba(192, 132, 252, 0.35);
            --cyan: #22d3ee;
            --cyan-glow: rgba(34, 211, 238, 0.3);
            --text: #f8fafc;
            --text-sec: #94a3b8;
            --text-muted: #64748b;
            --border: #1e293b;
            --error: #f87171;
            --error-glow: rgba(248, 113, 113, 0.35);
            --success: #34d399;
            --success-glow: rgba(52, 211, 153, 0.35);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            background-color: var(--bg);
            background-image:
                radial-gradient(ellipse at 0% 0%, rgba(129, 140, 248, 0.15) 0px, transparent 50%),
                radial-gradient(ellipse at 100% 100%, rgba(192, 132, 252, 0.12) 0px, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(34, 211, 238, 0.05) 0px, transparent 60%);
            background-attachment: fixed;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        .main-content {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }

        .auth-container { width: 100%; max-width: 460px; }

        .card {
            background: linear-gradient(145deg, rgba(15, 22, 41, 0.8), rgba(15, 22, 41, 0.95));
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 24px;
            padding: 2.75rem;
            box-shadow: 0 30px 60px -12px rgba(0, 0, 0, 0.5), 0 0 80px rgba(129, 140, 248, 0.08);
            backdrop-filter: blur(20px);
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--primary), var(--cyan), var(--accent), transparent);
            opacity: 0.6;
        }

        .logo {
            text-align: center;
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 2.25rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 14px;
        }

        .logo i {
            background: linear-gradient(135deg, var(--primary), var(--cyan), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: logoShimmer 3s ease-in-out infinite;
        }

        @keyframes logoShimmer {
            0%, 100% { filter: brightness(1); }
            50% { filter: brightness(1.3); }
        }

        .logo span {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .form-wrapper { transition: opacity 0.3s ease, transform 0.3s ease; }
        .form-wrapper.hidden { display: none; }

        .input-group { margin-bottom: 1.5rem; }
        .input-group label {
            display: block;
            color: var(--text-sec);
            font-size: 0.85rem;
            margin-bottom: 10px;
            font-weight: 500;
        }

        .input-wrapper {
            position: relative;
        }

        .input-wrapper i.icon {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            transition: color 0.3s ease;
            z-index: 1;
        }

        .input-wrapper:focus-within i.icon {
            color: var(--primary);
        }

        input {
            width: 100%;
            background: rgba(3, 7, 18, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 14px 18px 14px 48px;
            color: var(--text);
            font-size: 0.95rem;
            font-family: inherit;
            transition: all 0.3s ease;
        }

        input:focus {
            border-color: var(--primary);
            outline: none;
            box-shadow: 0 0 0 4px var(--primary-glow);
            background: rgba(3, 7, 18, 0.8);
        }

        input::placeholder {
            color: var(--text-muted);
        }

        .btn {
            width: 100%;
            padding: 15px;
            border-radius: 12px;
            border: none;
            color: white;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            margin-top: 14px;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            font-family: inherit;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 20px var(--primary-glow), inset 0 1px 0 rgba(255,255,255,0.2);
            position: relative;
            overflow: hidden;
        }

        .btn::before {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(255,255,255,0.2), transparent);
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 30px var(--primary-glow), inset 0 1px 0 rgba(255,255,255,0.3);
        }

        .btn:hover::before {
            opacity: 1;
        }

        .btn:active {
            transform: translateY(-1px);
        }

        .switch-text {
            text-align: center;
            margin-top: 1.75rem;
            color: var(--text-sec);
            font-size: 0.9rem;
        }

        .switch-text span {
            color: var(--cyan);
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            position: relative;
        }

        .switch-text span::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--cyan);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }

        .switch-text span:hover::after {
            transform: scaleX(1);
        }

        .msg-box {
            padding: 14px 18px;
            border-radius: 12px;
            margin-bottom: 1.75rem;
            text-align: center;
            font-size: 0.9rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .error {
            background: linear-gradient(135deg, rgba(248, 113, 113, 0.12), rgba(248, 113, 113, 0.08));
            color: #fca5a5;
            border: 1px solid rgba(248, 113, 113, 0.25);
        }

        .success {
            background: linear-gradient(135deg, rgba(52, 211, 153, 0.12), rgba(52, 211, 153, 0.08));
            color: #86efac;
            border: 1px solid rgba(52, 211, 153, 0.25);
        }

        footer {
            text-align: center;
            padding: 24px;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid rgba(255, 255, 255, 0.04);
            background: rgba(3, 7, 18, 0.5);
            backdrop-filter: blur(10px);
        }

        footer p {
            margin-bottom: 10px;
        }

        footer a {
            color: var(--text-sec);
            text-decoration: none;
            margin: 0 12px;
            transition: all 0.3s ease;
            position: relative;
        }

        footer a:hover {
            color: var(--cyan);
        }

        /* Анимации появления */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .card {
            animation: fadeInUp 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }

        /* Адаптивность */
        @media (max-width: 480px) {
            .main-content {
                padding: 16px;
            }

            .card {
                padding: 2rem;
                border-radius: 20px;
            }

            .logo {
                font-size: 1.6rem;
            }

            input {
                padding: 12px 14px 12px 44px;
            }

            .btn {
                padding: 13px;
            }
        }

        /* Улучшенный скроллбар */
        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg);
        }

        ::-webkit-scrollbar-thumb {
            background: linear-gradient(180deg, var(--primary), var(--accent));
            border-radius: 99px;
        }

        /* Выделение текста */
        ::selection {
            background: var(--primary);
            color: white;
        }
    </style>
</head>
<body>

<div class="main-content">
    <div class="auth-container">
        <div class="card">
            <div class="logo">
                <i class="fas fa-shield-alt" style="color:var(--primary)"></i> 
                Photo<span>Host</span>
            </div>

            <?php if ($error): ?>
                <div class="msg-box error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="msg-box success"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>

            <!-- LOGIN FORM -->
            <div id="loginForm" class="form-wrapper <?= $activeForm === 'register' ? 'hidden' : '' ?>">
                <form method="POST">
                    <input type="hidden" name="type" value="login">
                    <input type="hidden" name="token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                    <div class="input-group">
                        <label>Имя пользователя</label>
                        <div class="input-wrapper">
                            <i class="fas fa-user icon"></i>
                            <input type="text" name="username" required autocomplete="username" placeholder="Введите логин" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
                        </div>
                    </div>

                    <div class="input-group">
                        <label>Пароль</label>
                        <div class="input-wrapper">
                            <i class="fas fa-lock icon"></i>
                            <input type="password" name="password" required autocomplete="current-password" placeholder="Введите пароль">
                        </div>
                    </div>

                    <button type="submit" class="btn">
                        <i class="fas fa-sign-in-alt" style="margin-right: 8px;"></i>
                        Войти
                    </button>
                </form>
                <div class="switch-text">
                    Нет аккаунта? <span onclick="switchMode('register')">Регистрация</span>
                </div>
            </div>

            <!-- REGISTER FORM -->
            <div id="registerForm" class="form-wrapper <?= $activeForm === 'register' ? '' : 'hidden' ?>">
                <form method="POST">
                    <input type="hidden" name="type" value="register">
                    <input type="hidden" name="token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                    <div class="input-group">
                        <label>Придумайте логин</label>
                        <div class="input-wrapper">
                            <i class="fas fa-user-plus icon"></i>
                            <input type="text" name="username" required pattern="[a-zA-Z0-9_]{3,20}" placeholder="3-20 символов (a-z, 0-9, _)">
                        </div>
                    </div>

                    <div class="input-group">
                        <label>Придумайте пароль</label>
                        <div class="input-wrapper">
                            <i class="fas fa-key icon"></i>
                            <input type="password" name="password" required minlength="6" placeholder="Минимум 6 символов">
                        </div>
                    </div>

                    <button type="submit" class="btn">
                        <i class="fas fa-user-check" style="margin-right: 8px;"></i>
                        Создать аккаунт
                    </button>
                </form>
                <div class="switch-text">
                    Уже есть аккаунт? <span onclick="switchMode('login')">Войти</span>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Футер добавляет легитимности для роботов Google -->
<footer>
    <p>&copy; <?= date('Y') ?> PhotoHost Secure Storage.</p>
    <div style="margin-top: 10px;">
        <a href="#">Privacy Policy</a> | 
        <a href="#">Terms of Service</a> | 
        <a href="#">Support</a>
    </div>
</footer>

<script>
    'use strict';

    function switchMode(mode) {
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');

        // Анимация переключения
        const currentForm = mode === 'register' ? loginForm : registerForm;
        const nextForm = mode === 'register' ? registerForm : loginForm;

        currentForm.style.opacity = '0';
        currentForm.style.transform = 'translateX(-20px)';

        setTimeout(() => {
            currentForm.classList.add('hidden');
            nextForm.classList.remove('hidden');
            nextForm.style.opacity = '0';
            nextForm.style.transform = 'translateX(20px)';

            requestAnimationFrame(() => {
                nextForm.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
                nextForm.style.opacity = '1';
                nextForm.style.transform = 'translateX(0)';
            });
        }, 200);
    }

    // Ripple эффект для кнопок
    document.querySelectorAll('.btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;

            ripple.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                left: ${x}px;
                top: ${y}px;
                background: rgba(255, 255, 255, 0.4);
                border-radius: 50%;
                transform: scale(0);
                animation: rippleEffect 0.6s ease-out;
                pointer-events: none;
            `;

            this.style.position = 'relative';
            this.style.overflow = 'hidden';
            this.appendChild(ripple);

            setTimeout(() => ripple.remove(), 600);
        });
    });

    // CSS для ripple
    const style = document.createElement('style');
    style.textContent = `
        @keyframes rippleEffect {
            to { transform: scale(4); opacity: 0; }
        }
        .form-wrapper {
            transition: opacity 0.2s ease, transform 0.2s ease;
        }
    `;
    document.head.appendChild(style);

    // Автофокус на первое поле
    const visibleForm = document.querySelector('.form-wrapper:not(.hidden) input[name="username"]');
    if (visibleForm) {
        visibleForm.focus();
    }
</script>

</body>
</html>

