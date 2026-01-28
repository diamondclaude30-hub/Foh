<?php
define('SECURE_ACCESS', true);
$config = require_once 'config.php';

$isSecure = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') || 
            (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', $isSecure ? 1 : 0);
ini_set('session.use_strict_mode', 1);

session_name($config['session_name']);
session_set_cookie_params([
    'lifetime' => $config['session_lifetime'],
    'path' => '/',
    'secure' => $isSecure,
    'httponly' => true,
    'samesite' => 'Lax'
]);

session_start();

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src \'self\' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src \'self\' data:;');

if (!isset($_SESSION['user_id'])) {
    header("Location: auth.php");
    exit;
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
try {
    $conn = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
    $conn->set_charset("utf8mb4");
} catch (Exception $e) {
    error_log("DB Error: " . $e->getMessage());
    die("Ошибка подключения к базе данных");
}

$baseDir = __DIR__ . '/uploads/user_' . (int)$_SESSION['user_id'] . '/';
$thumbDir = $baseDir . 'thumbs/';
$webUserDir = 'uploads/user_' . (int)$_SESSION['user_id'] . '/';

if (!file_exists($baseDir)) mkdir($baseDir, 0755, true);
if (!file_exists($thumbDir)) mkdir($thumbDir, 0755, true);

$htaccessContent = "Options -Indexes\nphp_flag engine off\n<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phps|phar|pl|py|cgi|asp|aspx|jsp|sh|bash)$\">\n    Require all denied\n</FilesMatch>";
if (!file_exists($baseDir . '.htaccess')) {
    file_put_contents($baseDir . '.htaccess', $htaccessContent);
}

define('MAX_FILE_SIZE', 15 * 1024 * 1024);
define('MAX_STORAGE_PER_USER', 500 * 1024 * 1024);
define('THUMB_MAX_SIZE', 400);
define('ALLOWED_MIMES', ['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
define('MIME_TO_EXT', [
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'image/gif' => 'gif',
    'image/webp' => 'webp'
]);

function formatSize($bytes) {
    if ($bytes >= 1073741824) return round($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576) return round($bytes / 1048576, 1) . ' MB';
    if ($bytes >= 1024) return round($bytes / 1024, 0) . ' KB';
    return $bytes . ' B';
}

function calculateUserStorage($baseDir) {
    $total = 0;
    if (!is_dir($baseDir)) return 0;
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($baseDir, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    foreach ($iterator as $file) {
        if ($file->isFile() && !str_contains($file->getPathname(), '/thumbs/')) {
            $total += $file->getSize();
        }
    }
    return $total;
}

function sanitizeAndSaveImage($source, $dest, $mime) {
    $img = null;
    $memoryLimit = ini_get('memory_limit');
    ini_set('memory_limit', '256M');

    switch ($mime) {
        case 'image/jpeg': $img = @imagecreatefromjpeg($source); break;
        case 'image/png': $img = @imagecreatefrompng($source); break;
        case 'image/gif': $img = @imagecreatefromgif($source); break;
        case 'image/webp': $img = @imagecreatefromwebp($source); break;
    }

    if (!$img) {
        ini_set('memory_limit', $memoryLimit);
        return false;
    }

    if ($mime === 'image/jpeg' && function_exists('exif_read_data')) {
        $exif = @exif_read_data($source);
        if ($exif && isset($exif['Orientation'])) {
            $rotated = null;
            switch ($exif['Orientation']) {
                case 3: $rotated = @imagerotate($img, 180, 0); break;
                case 6: $rotated = @imagerotate($img, -90, 0); break;
                case 8: $rotated = @imagerotate($img, 90, 0); break;
            }
            if ($rotated) {
                imagedestroy($img);
                $img = $rotated;
            }
        }
    }

    if ($mime === 'image/png' || $mime === 'image/webp') {
        imagealphablending($img, false);
        imagesavealpha($img, true);
    }

    $result = false;
    switch ($mime) {
        case 'image/jpeg': $result = imagejpeg($img, $dest, 92); break;
        case 'image/png': $result = imagepng($img, $dest, 9); break;
        case 'image/gif': $result = imagegif($img, $dest); break;
        case 'image/webp': $result = imagewebp($img, $dest, 92); break;
    }

    imagedestroy($img);
    ini_set('memory_limit', $memoryLimit);
    return $result;
}

function createThumbnail($source, $dest, $mime) {
    $srcImg = null;
    $dstImg = null;
    
    try {
        $memoryLimit = ini_get('memory_limit');
        ini_set('memory_limit', '256M');
        
        $imageInfo = @getimagesize($source);
        if ($imageInfo === false) {
            ini_set('memory_limit', $memoryLimit);
            return false;
        }
        
        list($width, $height) = $imageInfo;
        
        if ($width <= 0 || $height <= 0) {
            ini_set('memory_limit', $memoryLimit);
            return false;
        }
        
        $maxWidth = THUMB_MAX_SIZE;
        $maxHeight = THUMB_MAX_SIZE;
        
        $ratio = $width / $height;
        if ($maxWidth / $maxHeight > $ratio) {
            $newWidth = (int)($maxHeight * $ratio);
            $newHeight = $maxHeight;
        } else {
            $newHeight = (int)($maxWidth / $ratio);
            $newWidth = $maxWidth;
        }
        
        if ($newWidth <= 0) $newWidth = 1;
        if ($newHeight <= 0) $newHeight = 1;

        switch ($mime) {
            case 'image/jpeg': $srcImg = @imagecreatefromjpeg($source); break;
            case 'image/png': $srcImg = @imagecreatefrompng($source); break;
            case 'image/gif': $srcImg = @imagecreatefromgif($source); break;
            case 'image/webp': $srcImg = @imagecreatefromwebp($source); break;
            default: 
                ini_set('memory_limit', $memoryLimit);
                return false;
        }

        if (!$srcImg) {
            ini_set('memory_limit', $memoryLimit);
            return false;
        }

        $dstImg = @imagecreatetruecolor($newWidth, $newHeight);
        if (!$dstImg) {
            if ($srcImg && (is_resource($srcImg) || $srcImg instanceof \GdImage)) {
                imagedestroy($srcImg);
            }
            ini_set('memory_limit', $memoryLimit);
            return false;
        }
        
        if ($mime === 'image/png' || $mime === 'image/webp') {
            imagealphablending($dstImg, false);
            imagesavealpha($dstImg, true);
            $transparent = imagecolorallocatealpha($dstImg, 0, 0, 0, 127);
            imagefill($dstImg, 0, 0, $transparent);
        }

        $srcWidth = imagesx($srcImg);
        $srcHeight = imagesy($srcImg);
        
        imagecopyresampled($dstImg, $srcImg, 0, 0, 0, 0, $newWidth, $newHeight, $srcWidth, $srcHeight);

        $result = false;
        switch ($mime) {
            case 'image/jpeg': $result = imagejpeg($dstImg, $dest, 85); break;
            case 'image/png': $result = imagepng($dstImg, $dest, 8); break;
            case 'image/gif': $result = imagegif($dstImg, $dest); break;
            case 'image/webp': $result = imagewebp($dstImg, $dest, 85); break;
        }

        ini_set('memory_limit', $memoryLimit);
        return $result;
        
    } catch (Exception $e) {
        error_log("Thumbnail error: " . $e->getMessage());
        return false;
    } finally {
        if ($srcImg && (is_resource($srcImg) || $srcImg instanceof \GdImage)) {
            imagedestroy($srcImg);
        }
        if ($dstImg && (is_resource($dstImg) || $dstImg instanceof \GdImage)) {
            imagedestroy($dstImg);
        }
    }
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['photos'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        echo json_encode(['success' => false, 'errors' => ['Ошибка безопасности CSRF']]);
        exit;
    }

    header('Content-Type: application/json');
    $uploaded = [];
    $errors = [];
    $files = $_FILES['photos'];
    $count = count($files['name']);
    
    $currentStorage = calculateUserStorage($baseDir);

    for ($i = 0; $i < $count; $i++) {
        $tmpName = $files['tmp_name'][$i];
        $origName = $files['name'][$i];
        $errorCode = $files['error'][$i];
        $size = $files['size'][$i];

        if ($errorCode !== UPLOAD_ERR_OK) {
            $errors[] = htmlspecialchars($origName) . ": Ошибка загрузки (код $errorCode)";
            continue;
        }

        if ($size > MAX_FILE_SIZE) {
            $errors[] = htmlspecialchars($origName) . ": Файл превышает 15MB";
            continue;
        }
        
        if ($currentStorage + $size > MAX_STORAGE_PER_USER) {
            $errors[] = htmlspecialchars($origName) . ": Превышен лимит хранилища (" . formatSize(MAX_STORAGE_PER_USER) . ")";
            continue;
        }

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($tmpName);

        if (!in_array($mimeType, ALLOWED_MIMES)) {
            $errors[] = htmlspecialchars($origName) . ": Недопустимый формат";
            continue;
        }
        
        $imageInfo = @getimagesize($tmpName);
        if ($imageInfo === false) {
            $errors[] = htmlspecialchars($origName) . ": Файл не является изображением";
            continue;
        }

        $ext = MIME_TO_EXT[$mimeType];
        $uniqueName = uniqid('img_', true) . '_' . bin2hex(random_bytes(8)) . '.' . $ext;
        
        $targetPath = $baseDir . $uniqueName;
        $thumbPath = $thumbDir . $uniqueName;
        
        if (sanitizeAndSaveImage($tmpName, $targetPath, $mimeType)) {
            createThumbnail($targetPath, $thumbPath, $mimeType);

            $stmt = $conn->prepare("INSERT INTO photos (user_id, file_name, original_name, file_size) VALUES (?, ?, ?, ?)");
            $sizeStr = formatSize($size);
            $stmt->bind_param("isss", $_SESSION['user_id'], $uniqueName, $origName, $sizeStr);
            
            if ($stmt->execute()) {
                $uploaded[] = $uniqueName;
                $currentStorage += $size;
            } else {
                @unlink($targetPath);
                @unlink($thumbPath);
                $errors[] = htmlspecialchars($origName) . ": Ошибка сохранения в БД";
            }
            $stmt->close();
        } else {
            $errors[] = htmlspecialchars($origName) . ": Ошибка обработки изображения";
        }
    }

    echo json_encode([
        'success' => count($uploaded) > 0,
        'count' => count($uploaded),
        'errors' => $errors
    ]);
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
    if (!isset($_GET['token']) || !hash_equals($_SESSION['csrf_token'], $_GET['token'])) {
        die("Ошибка безопасности");
    }

    $id = intval($_GET['id']);
    $stmt = $conn->prepare("SELECT file_name FROM photos WHERE id = ? AND user_id = ?");
    $stmt->bind_param("ii", $id, $_SESSION['user_id']);
    $stmt->execute();
    $res = $stmt->get_result();
    
    if ($row = $res->fetch_assoc()) {
        $fileName = basename($row['file_name']);
        $path = $baseDir . $fileName;
        $tPath = $thumbDir . $fileName;
        
        if (file_exists($path)) @unlink($path);
        if (file_exists($tPath)) @unlink($tPath);
                
        $del = $conn->prepare("DELETE FROM photos WHERE id = ? AND user_id = ?");
        $del->bind_param("ii", $id, $_SESSION['user_id']);
        $del->execute();
        $del->close();
    }
    $stmt->close();
    
    header("Location: " . strtok($_SERVER["REQUEST_URI"], '?') . "?page=" . (intval($_GET['page'] ?? 1)));
    exit;
}

$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$perPage = $config['per_page'] ?? 20;
$offset = ($page - 1) * $perPage;

$cntStmt = $conn->prepare("SELECT COUNT(*) as cnt FROM photos WHERE user_id = ?");
$cntStmt->bind_param("i", $_SESSION['user_id']);
$cntStmt->execute();
$totalPhotos = $cntStmt->get_result()->fetch_assoc()['cnt'];
$cntStmt->close();
$totalPages = ($totalPhotos > 0) ? ceil($totalPhotos / $perPage) : 1;

$stmt = $conn->prepare("SELECT * FROM photos WHERE user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?");
$stmt->bind_param("iii", $_SESSION['user_id'], $perPage, $offset);
$stmt->execute();
$photos = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

$totalSizeBytes = calculateUserStorage($baseDir);
$storagePercent = min(100, round(($totalSizeBytes / MAX_STORAGE_PER_USER) * 100));
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Моя Галерея - PhotoHost</title>
    <meta name="description" content="Личная фотогалерея с загрузкой изображений">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" crossorigin="anonymous" referrerpolicy="no-referrer">
    <style>
        :root {
            --bg-body: #030712;
            --bg-card: #0f1629;
            --bg-card-hover: #161d33;
            --bg-header: rgba(3, 7, 18, 0.85);
            --primary: #818cf8;
            --primary-hover: #6366f1;
            --primary-glow: rgba(129, 140, 248, 0.35);
            --accent: #c084fc;
            --accent-glow: rgba(192, 132, 252, 0.35);
            --cyan: #22d3ee;
            --cyan-glow: rgba(34, 211, 238, 0.3);
            --text-main: #f8fafc;
            --text-sec: #94a3b8;
            --text-muted: #64748b;
            --border: #1e293b;
            --border-light: #334155;
            --danger: #f87171;
            --danger-glow: rgba(248, 113, 113, 0.35);
            --success: #34d399;
            --success-glow: rgba(52, 211, 153, 0.35);
            --warning: #fbbf24;
            --radius: 20px;
            --radius-sm: 12px;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -1px rgba(0, 0, 0, 0.3);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            --shadow-glow: 0 0 40px var(--primary-glow);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-body);
            background-image:
                radial-gradient(ellipse at 0% 0%, rgba(129, 140, 248, 0.12) 0px, transparent 50%),
                radial-gradient(ellipse at 100% 0%, rgba(192, 132, 252, 0.1) 0px, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(34, 211, 238, 0.05) 0px, transparent 60%),
                radial-gradient(ellipse at 50% 100%, rgba(129, 140, 248, 0.08) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            padding-bottom: 4rem;
            min-height: 100vh;
            overflow-x: hidden;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        header {
            position: sticky;
            top: 0;
            width: 100%;
            z-index: 100;
            background: var(--bg-header);
            backdrop-filter: blur(24px) saturate(180%);
            -webkit-backdrop-filter: blur(24px) saturate(180%);
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            padding: 0.875rem 0;
            transition: all 0.3s ease;
        }

        header.scrolled {
            padding: 0.625rem 0;
            background: rgba(3, 7, 18, 0.95);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
        }

        .container {
            max-width: 1440px;
            margin: 0 auto;
            padding: 0 1.5rem;
        }

        .header-inner {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }

        .logo {
            font-size: 1.6rem;
            font-weight: 700;
            color: white;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            flex-shrink: 0;
        }

        .logo:hover {
            transform: scale(1.03);
            filter: drop-shadow(0 0 20px var(--primary-glow));
        }

        .logo i {
            font-size: 1.4rem;
            background: linear-gradient(135deg, var(--primary), var(--cyan), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: logoShimmer 3s ease-in-out infinite;
        }

        @keyframes logoShimmer {
            0%, 100% { filter: brightness(1); }
            50% { filter: brightness(1.2); }
        }

        .logo span {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header-controls {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-shrink: 0;
        }

        .user-pill {
            display: flex;
            align-items: center;
            gap: 10px;
            background: linear-gradient(135deg, rgba(129, 140, 248, 0.12), rgba(192, 132, 252, 0.12));
            padding: 10px 18px;
            border-radius: 99px;
            font-size: 0.9rem;
            color: var(--text-main);
            border: 1px solid rgba(255, 255, 255, 0.08);
            font-weight: 500;
            white-space: nowrap;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }

        .user-pill:hover {
            background: linear-gradient(135deg, rgba(129, 140, 248, 0.2), rgba(192, 132, 252, 0.2));
            border-color: rgba(255, 255, 255, 0.15);
        }

        .user-pill i {
            color: var(--primary);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 11px 22px;
            border-radius: var(--radius-sm);
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            border: none;
            text-decoration: none;
            white-space: nowrap;
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

        .btn:hover::before {
            opacity: 1;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            color: white;
            box-shadow: 0 4px 20px var(--primary-glow), inset 0 1px 0 rgba(255,255,255,0.2);
        }

        .btn-primary:hover {
            transform: translateY(-3px) scale(1.02);
            box-shadow: 0 8px 30px var(--primary-glow), inset 0 1px 0 rgba(255,255,255,0.3);
        }

        .btn-primary:active {
            transform: translateY(-1px) scale(1);
        }

        .btn-icon {
            background: rgba(15, 22, 41, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.08);
            color: var(--text-sec);
            width: 44px;
            height: 44px;
            padding: 0;
            border-radius: var(--radius-sm);
            backdrop-filter: blur(10px);
        }

        .btn-icon:hover {
            background: rgba(129, 140, 248, 0.15);
            color: white;
            border-color: var(--primary);
            transform: translateY(-2px);
            box-shadow: 0 4px 15px var(--primary-glow);
        }

        .btn-icon.logout:hover {
            color: var(--danger);
            border-color: var(--danger);
            background: rgba(248, 113, 113, 0.15);
            box-shadow: 0 4px 15px var(--danger-glow);
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 400px;
            gap: 1.75rem;
            margin: 2rem 0;
        }

        .upload-area {
            background: linear-gradient(145deg, rgba(15, 22, 41, 0.6), rgba(15, 22, 41, 0.9));
            border: 2px dashed rgba(129, 140, 248, 0.3);
            border-radius: var(--radius);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 3.5rem 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
            backdrop-filter: blur(10px);
        }

        .upload-area::before {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, var(--primary-glow), var(--cyan-glow), var(--accent-glow));
            opacity: 0;
            transition: opacity 0.4s ease;
        }

        .upload-area::after {
            content: '';
            position: absolute;
            inset: -50%;
            background: conic-gradient(from 0deg, transparent, var(--primary), var(--cyan), var(--accent), transparent);
            opacity: 0;
            animation: borderRotate 4s linear infinite;
            transition: opacity 0.4s ease;
        }

        @keyframes borderRotate {
            to { transform: rotate(360deg); }
        }

        .upload-area:hover,
        .upload-area.dragover {
            border-color: transparent;
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(129, 140, 248, 0.15);
        }

        .upload-area:hover::before,
        .upload-area.dragover::before {
            opacity: 1;
        }

        .upload-area:hover::after,
        .upload-area.dragover::after {
            opacity: 0.3;
        }

        .upload-area > * {
            position: relative;
            z-index: 2;
        }

        .upload-icon {
            width: 90px;
            height: 90px;
            background: linear-gradient(135deg, var(--primary), var(--cyan), var(--accent));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1.75rem;
            box-shadow: 0 15px 40px var(--primary-glow);
            animation: iconFloat 3s ease-in-out infinite;
        }

        @keyframes iconFloat {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-8px); }
        }

        .upload-icon i {
            font-size: 2.25rem;
            color: white;
        }

        .upload-area h3 {
            margin: 0 0 0.5rem 0;
            font-weight: 600;
            font-size: 1.35rem;
            background: linear-gradient(135deg, var(--text-main), var(--text-sec));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .upload-area p {
            margin: 0;
            color: var(--text-sec);
            font-size: 0.95rem;
        }

        .upload-hint {
            margin-top: 1.25rem;
            padding: 10px 20px;
            background: linear-gradient(135deg, rgba(129, 140, 248, 0.15), rgba(34, 211, 238, 0.1));
            border-radius: 99px;
            font-size: 0.85rem;
            color: var(--cyan);
            border: 1px solid rgba(34, 211, 238, 0.2);
        }

        .stats-panel {
            background: linear-gradient(145deg, rgba(15, 22, 41, 0.8), rgba(15, 22, 41, 0.95));
            border-radius: var(--radius);
            padding: 1.75rem;
            border: 1px solid rgba(255, 255, 255, 0.06);
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
        }

        .stats-panel::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--primary), var(--accent), transparent);
            opacity: 0.5;
        }

        .stats-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }

        .stats-header i {
            color: var(--cyan);
            font-size: 1.1rem;
        }

        .stats-header h3 {
            margin: 0;
            font-size: 1.05rem;
            font-weight: 600;
        }

        .stat-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            transition: all 0.3s ease;
        }

        .stat-row:hover {
            padding-left: 8px;
            background: linear-gradient(90deg, rgba(129, 140, 248, 0.05), transparent);
        }

        .stat-row:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }

        .stat-label {
            display: flex;
            align-items: center;
            gap: 12px;
            color: var(--text-sec);
            font-size: 0.9rem;
        }

        .stat-label i {
            width: 20px;
            text-align: center;
            color: var(--text-muted);
            transition: color 0.3s ease;
        }

        .stat-row:hover .stat-label i {
            color: var(--primary);
        }

        .stat-val {
            color: white;
            font-weight: 600;
            font-size: 0.95rem;
            font-variant-numeric: tabular-nums;
        }

        .storage-bar {
            margin-top: 1.5rem;
            padding-top: 1.25rem;
            border-top: 1px solid rgba(255, 255, 255, 0.06);
        }

        .storage-info {
            display: flex;
            justify-content: space-between;
            margin-bottom: 12px;
            font-size: 0.85rem;
        }

        .storage-info span:first-child {
            color: var(--text-sec);
        }

        .storage-info span:last-child {
            color: var(--text-main);
            font-weight: 600;
        }

        .storage-track {
            height: 10px;
            background: rgba(255, 255, 255, 0.06);
            border-radius: 99px;
            overflow: hidden;
            position: relative;
        }

        .storage-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--cyan), var(--accent));
            border-radius: 99px;
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            box-shadow: 0 0 20px var(--primary-glow);
        }

        .storage-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            animation: storageShine 2s ease-in-out infinite;
        }

        @keyframes storageShine {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        .storage-fill.warning {
            background: linear-gradient(90deg, var(--warning), var(--danger));
            box-shadow: 0 0 20px var(--danger-glow);
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 3rem 0 1.75rem;
        }

        .section-title {
            display: flex;
            align-items: center;
            gap: 14px;
            font-size: 1.35rem;
            font-weight: 700;
        }

        .section-title i {
            color: var(--cyan);
            font-size: 1.2rem;
        }

        .photo-count {
            background: linear-gradient(135deg, rgba(129, 140, 248, 0.1), rgba(34, 211, 238, 0.1));
            padding: 8px 18px;
            border-radius: 99px;
            font-size: 0.85rem;
            color: var(--text-sec);
            border: 1px solid rgba(255, 255, 255, 0.08);
            font-weight: 500;
        }

        .gallery-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
            gap: 1.75rem;
        }

        .card {
            background: var(--bg-card);
            border-radius: var(--radius);
            overflow: hidden;
            position: relative;
            aspect-ratio: 1;
            box-shadow: var(--shadow);
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .card::before {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: var(--radius);
            padding: 1px;
            background: linear-gradient(135deg, var(--primary), var(--cyan), var(--accent));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            opacity: 0;
            transition: opacity 0.4s ease;
            z-index: 1;
            pointer-events: none;
        }

        .card:hover {
            transform: translateY(-10px) scale(1.02);
            box-shadow: var(--shadow-lg), 0 0 50px rgba(129, 140, 248, 0.2);
        }

        .card:hover::before {
            opacity: 1;
        }

        .card img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            transition: transform 0.6s cubic-bezier(0.4, 0, 0.2, 1), filter 0.4s ease;
        }

        .card:hover img {
            transform: scale(1.12);
            filter: brightness(0.85);
        }

        .card-overlay {
            position: absolute;
            inset: 0;
            background: linear-gradient(to top, rgba(3, 7, 18, 0.98) 0%, rgba(3, 7, 18, 0.6) 35%, transparent 100%);
            opacity: 0;
            transition: opacity 0.4s ease;
            display: flex;
            flex-direction: column;
            justify-content: flex-end;
            padding: 1.5rem;
            cursor: pointer;
            z-index: 2;
        }

        .card:hover .card-overlay {
            opacity: 1;
        }

        .card-actions {
            display: flex;
            gap: 12px;
            justify-content: center;
            margin-bottom: 14px;
            transform: translateY(25px);
            transition: transform 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .card:hover .card-actions {
            transform: translateY(0);
        }

        .action-btn {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.15);
            color: white;
            width: 44px;
            height: 44px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            text-decoration: none;
        }

        .action-btn:hover {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border-color: transparent;
            transform: scale(1.2) translateY(-3px);
            box-shadow: 0 8px 25px var(--primary-glow);
        }

        .action-btn.del:hover {
            background: linear-gradient(135deg, var(--danger), #dc2626);
            box-shadow: 0 8px 25px var(--danger-glow);
        }

        .file-meta {
            font-size: 0.8rem;
            color: var(--text-sec);
            text-align: center;
            opacity: 0;
            transform: translateY(15px);
            transition: all 0.4s ease;
            font-weight: 500;
        }

        .card:hover .file-meta {
            opacity: 1;
            transform: translateY(0);
        }

        .empty-state {
            grid-column: 1 / -1;
            text-align: center;
            padding: 6rem 2rem;
            background: linear-gradient(145deg, rgba(15, 22, 41, 0.6), rgba(15, 22, 41, 0.9));
            border: 2px dashed rgba(129, 140, 248, 0.2);
            border-radius: var(--radius);
            backdrop-filter: blur(10px);
        }

        .empty-icon {
            width: 120px;
            height: 120px;
            background: linear-gradient(135deg, rgba(129, 140, 248, 0.15), rgba(34, 211, 238, 0.1), rgba(192, 132, 252, 0.15));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 2rem;
            animation: emptyPulse 3s ease-in-out infinite;
        }

        @keyframes emptyPulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.05); opacity: 0.8; }
        }

        .empty-icon i {
            font-size: 3rem;
            background: linear-gradient(135deg, var(--primary), var(--cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .empty-state h3 {
            margin: 0 0 0.75rem;
            color: var(--text-main);
            font-size: 1.5rem;
            font-weight: 600;
        }

        .empty-state p {
            color: var(--text-sec);
            margin: 0;
            font-size: 1rem;
        }

        .pagination {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 3.5rem;
            flex-wrap: wrap;
        }

        .page-link {
            min-width: 46px;
            height: 46px;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0 14px;
            border-radius: var(--radius-sm);
            background: rgba(15, 22, 41, 0.8);
            color: var(--text-sec);
            text-decoration: none;
            border: 1px solid rgba(255, 255, 255, 0.08);
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
        }

        .page-link:hover {
            background: rgba(129, 140, 248, 0.15);
            color: white;
            border-color: var(--primary);
            transform: translateY(-2px);
        }

        .page-link.active {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            color: white;
            border-color: transparent;
            box-shadow: 0 6px 20px var(--primary-glow);
            transform: translateY(-2px);
        }

        #lightbox {
            position: fixed;
            inset: 0;
            background: rgba(3, 7, 18, 0.97);
            z-index: 1000;
            display: none;
            justify-content: center;
            align-items: center;
            opacity: 0;
            transition: opacity 0.4s ease;
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
        }

        #lightbox.visible {
            opacity: 1;
        }

        #lightbox img {
            max-width: 92vw;
            max-height: 88vh;
            border-radius: var(--radius);
            box-shadow: 0 30px 60px rgba(0, 0, 0, 0.7), 0 0 100px rgba(129, 140, 248, 0.1);
            transition: transform 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }

        #lightbox.visible img {
            animation: lbZoomIn 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }

        @keyframes lbZoomIn {
            from { transform: scale(0.9); opacity: 0; }
            to { transform: scale(1); opacity: 1; }
        }

        .lb-controls {
            position: absolute;
            top: 24px;
            right: 24px;
            display: flex;
            gap: 12px;
            z-index: 10;
        }

        .lb-nav {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            z-index: 10;
        }

        .lb-nav.prev { left: 24px; }
        .lb-nav.next { right: 24px; }

        .lb-btn {
            width: 52px;
            height: 52px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.25rem;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
        }

        .lb-btn:hover {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border-color: transparent;
            transform: scale(1.1);
            box-shadow: 0 8px 25px var(--primary-glow);
        }

        .lb-counter {
            position: absolute;
            bottom: 24px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(10px);
            padding: 10px 20px;
            border-radius: 99px;
            font-size: 0.9rem;
            color: var(--text-sec);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(3, 7, 18, 0.92);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            z-index: 2000;
            display: none;
            justify-content: center;
            align-items: center;
            opacity: 0;
            transition: opacity 0.4s ease;
        }

        .modal-overlay.active {
            display: flex;
            opacity: 1;
        }

        .share-modal {
            background: linear-gradient(145deg, rgba(15, 22, 41, 0.95), rgba(15, 22, 41, 0.98));
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: var(--radius);
            width: 90%;
            max-width: 540px;
            padding: 0;
            box-shadow: var(--shadow-lg), 0 0 80px rgba(129, 140, 248, 0.1);
            transform: scale(0.92) translateY(30px);
            transition: transform 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            overflow: hidden;
            position: relative;
        }

        .share-modal::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--primary), var(--cyan), var(--accent), transparent);
        }

        .modal-overlay.active .share-modal {
            transform: scale(1) translateY(0);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem 1.75rem;
            background: linear-gradient(135deg, rgba(129, 140, 248, 0.1), rgba(34, 211, 238, 0.05), rgba(192, 132, 252, 0.1));
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }

        .modal-header h3 {
            margin: 0;
            font-size: 1.15rem;
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 600;
        }

        .modal-header h3 i {
            color: var(--cyan);
        }

        .close-modal-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-sec);
            font-size: 1.25rem;
            cursor: pointer;
            padding: 8px;
            line-height: 1;
            border-radius: 50%;
            width: 36px;
            height: 36px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
        }

        .close-modal-btn:hover {
            color: white;
            background: rgba(248, 113, 113, 0.2);
            border-color: var(--danger);
        }

        .modal-body {
            padding: 1.75rem;
        }

        .share-group {
            margin-bottom: 1.5rem;
        }

        .share-group:last-child {
            margin-bottom: 0;
        }

        .share-group label {
            display: block;
            color: var(--text-sec);
            font-size: 0.85rem;
            margin-bottom: 10px;
            font-weight: 500;
        }

        .input-with-btn {
            display: flex;
            gap: 10px;
        }

        .input-with-btn input {
            flex: 1;
            background: rgba(3, 7, 18, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: var(--radius-sm);
            padding: 14px 16px;
            color: var(--text-main);
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            font-size: 0.85rem;
            transition: all 0.3s ease;
        }

        .input-with-btn input:focus {
            border-color: var(--primary);
            outline: none;
            box-shadow: 0 0 0 4px var(--primary-glow);
            background: rgba(3, 7, 18, 0.8);
        }

        .input-with-btn .copy-btn {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border: none;
            color: white;
            border-radius: var(--radius-sm);
            width: 52px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .input-with-btn .copy-btn:hover {
            transform: scale(1.08);
            box-shadow: 0 6px 20px var(--primary-glow);
        }

        .input-with-btn .copy-btn.copied {
            background: linear-gradient(135deg, var(--success), #059669);
        }

        .loader-overlay {
            position: fixed;
            inset: 0;
            background: rgba(3, 7, 18, 0.97);
            z-index: 3000;
            display: none;
            justify-content: center;
            align-items: center;
            flex-direction: column;
            backdrop-filter: blur(10px);
        }

        .loader-content {
            text-align: center;
        }

        .loader-spinner {
            width: 70px;
            height: 70px;
            border: 3px solid rgba(255, 255, 255, 0.1);
            border-top-color: var(--primary);
            border-right-color: var(--cyan);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 2rem;
            box-shadow: 0 0 30px var(--primary-glow);
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .loader-content h3 {
            margin: 0 0 0.75rem;
            font-size: 1.35rem;
            font-weight: 600;
            background: linear-gradient(135deg, var(--text-main), var(--text-sec));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .loader-content p {
            color: var(--text-sec);
            margin: 0 0 2rem;
            font-size: 0.95rem;
        }

        .progress-container {
            width: 360px;
            height: 10px;
            background: rgba(255, 255, 255, 0.06);
            border-radius: 99px;
            overflow: hidden;
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.2);
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--cyan), var(--accent));
            width: 0%;
            transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            border-radius: 99px;
            position: relative;
            box-shadow: 0 0 20px var(--primary-glow);
        }

        .progress-bar::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            animation: progressShine 1.5s ease-in-out infinite;
        }

        @keyframes progressShine {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        .progress-text {
            margin-top: 14px;
            font-size: 0.9rem;
            color: var(--cyan);
            font-weight: 600;
        }

        #toast {
            position: fixed;
            bottom: 32px;
            left: 50%;
            transform: translateX(-50%) translateY(120px);
            background: linear-gradient(145deg, rgba(15, 22, 41, 0.95), rgba(15, 22, 41, 0.98));
            color: white;
            padding: 16px 28px;
            border-radius: var(--radius-sm);
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: var(--shadow-lg);
            display: flex;
            align-items: center;
            gap: 14px;
            z-index: 4000;
            transition: transform 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            font-weight: 500;
            backdrop-filter: blur(20px);
        }

        #toast.show {
            transform: translateX(-50%) translateY(0);
        }

        #toast.success {
            border-color: var(--success);
            box-shadow: var(--shadow-lg), 0 0 30px var(--success-glow);
        }

        #toast.success i {
            color: var(--success);
            font-size: 1.1rem;
        }

        #toast.error {
            border-color: var(--danger);
            box-shadow: var(--shadow-lg), 0 0 30px var(--danger-glow);
        }

        #toast.error i {
            color: var(--danger);
            font-size: 1.1rem;
        }

        @media (max-width: 1024px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }

            .stats-panel {
                order: 2;
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: 0 1rem;
            }

            .gallery-grid {
                grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
                gap: 1.25rem;
            }

            .section-title {
                font-size: 1.15rem;
            }

            .lb-nav {
                display: none;
            }
        }

        @media (max-width: 640px) {
            .header-inner {
                gap: 10px;
            }

            .user-pill {
                display: none;
            }

            .btn-primary span {
                display: none;
            }

            .btn-primary {
                padding: 11px 16px;
            }

            .gallery-grid {
                grid-template-columns: repeat(auto-fill, minmax(145px, 1fr));
                gap: 0.875rem;
            }

            .card {
                border-radius: var(--radius-sm);
            }

            .upload-area {
                padding: 2.5rem 1.5rem;
            }

            .upload-icon {
                width: 70px;
                height: 70px;
            }

            .upload-icon i {
                font-size: 1.75rem;
            }

            .upload-area h3 {
                font-size: 1.1rem;
            }

            .section-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
            }

            .progress-container {
                width: 280px;
            }

            #toast {
                left: 16px;
                right: 16px;
                transform: translateX(0) translateY(120px);
                width: auto;
            }

            #toast.show {
                transform: translateX(0) translateY(0);
            }
        }

        @media (max-width: 400px) {
            .gallery-grid {
                grid-template-columns: repeat(2, 1fr);
                gap: 0.75rem;
            }
        }

        @media (hover: none) {
            .card-overlay {
                opacity: 1;
                background: linear-gradient(to top, rgba(3, 7, 18, 0.95) 0%, transparent 50%);
            }

            .card-actions {
                transform: translateY(0);
            }

            .file-meta {
                opacity: 1;
                transform: translateY(0);
            }

            .card:hover {
                transform: none;
            }

            .card:hover img {
                transform: none;
                filter: none;
            }
        }

        /* Улучшенный скроллбар */
        ::-webkit-scrollbar {
            width: 10px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-body);
        }

        ::-webkit-scrollbar-thumb {
            background: linear-gradient(180deg, var(--primary), var(--accent));
            border-radius: 99px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(180deg, var(--primary-hover), var(--primary));
        }

        /* Плавная прокрутка */
        html {
            scroll-behavior: smooth;
        }

        /* Выделение текста */
        ::selection {
            background: var(--primary);
            color: white;
        }
    </style>
</head>
<body>

    <header>
        <div class="container header-inner">
            <a href="index.php" class="logo">
                <i class="fas fa-bolt"></i>
                Photo<span>Host</span>
            </a>
            <div class="header-controls">
                <div class="user-pill">
                    <i class="fas fa-user-astronaut"></i>
                    <?= htmlspecialchars($_SESSION['username'] ?? 'User') ?>
                </div>
                <button class="btn btn-primary" onclick="document.getElementById('fileInput').click()">
                    <i class="fas fa-cloud-upload-alt"></i>
                    <span>Загрузить</span>
                </button>
                <a href="auth.php?action=logout" class="btn btn-icon logout" title="Выход">
                    <i class="fas fa-power-off"></i>
                </a>
            </div>
        </div>
    </header>

    <main class="container">
        <div class="dashboard-grid">
            <input type="file" id="fileInput" multiple accept="image/jpeg,image/png,image/gif,image/webp" style="display: none;">
            <div class="upload-area" id="dropZone">
                <div class="upload-icon">
                    <i class="fas fa-cloud-upload-alt"></i>
                </div>
                <h3>Перетащите файлы сюда</h3>
                <p>или нажмите для выбора</p>
                <div class="upload-hint">
                    <i class="fas fa-info-circle"></i>
                    JPG, PNG, GIF, WEBP до 15 МБ
                </div>
            </div>
            <div class="stats-panel">
                <div class="stats-header">
                    <i class="fas fa-chart-pie"></i>
                    <h3>Статистика</h3>
                </div>
                <div class="stat-row">
                    <span class="stat-label"><i class="fas fa-images"></i> Всего фото</span>
                    <span class="stat-val"><?= $totalPhotos ?></span>
                </div>
                <div class="stat-row">
                    <span class="stat-label"><i class="fas fa-hdd"></i> Использовано</span>
                    <span class="stat-val"><?= formatSize($totalSizeBytes) ?></span>
                </div>
                <div class="stat-row">
                    <span class="stat-label"><i class="fas fa-file-alt"></i> Страница</span>
                    <span class="stat-val"><?= $page ?> из <?= $totalPages ?></span>
                </div>
                <div class="storage-bar">
                    <div class="storage-info">
                        <span>Хранилище</span>
                        <span><?= formatSize($totalSizeBytes) ?> / <?= formatSize(MAX_STORAGE_PER_USER) ?></span>
                    </div>
                    <div class="storage-track">
                        <div class="storage-fill <?= $storagePercent > 80 ? 'warning' : '' ?>" style="width: <?= $storagePercent ?>%"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="section-header">
            <h2 class="section-title">
                <i class="fas fa-th"></i>
                Галерея
            </h2>
            <?php if ($totalPhotos > 0): ?>
            <span class="photo-count"><?= $totalPhotos ?> фото</span>
            <?php endif; ?>
        </div>

        <div class="gallery-grid">
            <?php if (empty($photos)): ?>
                <div class="empty-state">
                    <div class="empty-icon">
                        <i class="far fa-images"></i>
                    </div>
                    <h3>Галерея пуста</h3>
                    <p>Загрузите свои первые фотографии</p>
                </div>
            <?php else: ?>
                <?php foreach ($photos as $photo): 
                    $fileName = htmlspecialchars($photo['file_name'], ENT_QUOTES, 'UTF-8');
                    $webThumb = $webUserDir . 'thumbs/' . $fileName;
                    $webFull = $webUserDir . $fileName;
                    
                    if (!file_exists($thumbDir . $photo['file_name'])) {
                        $webThumb = $webFull;
                    }

                    $protocol = $isSecure ? "https" : "http";
                    $fullUrl = $protocol . "://" . $_SERVER['HTTP_HOST'] . rtrim(dirname($_SERVER['PHP_SELF']), '/') . '/' . $webFull;
                ?>
                    <div class="card">
                        <img src="<?= $webThumb ?>" loading="lazy" alt="<?= htmlspecialchars($photo['original_name'], ENT_QUOTES, 'UTF-8') ?>">
                        <div class="card-overlay" onclick="openLightbox('<?= addslashes($webFull) ?>')">
                            <div class="card-actions" onclick="event.stopPropagation()">
                                <button class="action-btn" onclick="openShareModal('<?= addslashes($fullUrl) ?>', '<?= htmlspecialchars($photo['original_name'], ENT_QUOTES, 'UTF-8') ?>')" title="Поделиться">
                                    <i class="fas fa-link"></i>
                                </button>
                                <a href="<?= $webFull ?>" download class="action-btn" title="Скачать">
                                    <i class="fas fa-download"></i>
                                </a>
                                <a href="?action=delete&id=<?= $photo['id'] ?>&token=<?= $_SESSION['csrf_token'] ?>&page=<?= $page ?>" class="action-btn del" onclick="return confirm('Удалить изображение?')" title="Удалить">
                                    <i class="fas fa-trash-alt"></i>
                                </a>
                            </div>
                            <div class="file-meta"><?= htmlspecialchars($photo['file_size'], ENT_QUOTES, 'UTF-8') ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <?php if ($totalPages > 1): ?>
        <div class="pagination">
            <?php if ($page > 1): ?>
                <a href="?page=<?= $page - 1 ?>" class="page-link"><i class="fas fa-chevron-left"></i></a>
            <?php endif; ?>
            
            <?php
            $start = max(1, $page - 2);
            $end = min($totalPages, $page + 2);
            
            if ($start > 1): ?>
                <a href="?page=1" class="page-link">1</a>
                <?php if ($start > 2): ?>
                    <span class="page-link" style="border: none; background: none;">...</span>
                <?php endif; ?>
            <?php endif; ?>
            
            <?php for ($i = $start; $i <= $end; $i++): ?>
                <a href="?page=<?= $i ?>" class="page-link <?= $i == $page ? 'active' : '' ?>"><?= $i ?></a>
            <?php endfor; ?>
            
            <?php if ($end < $totalPages): ?>
                <?php if ($end < $totalPages - 1): ?>
                    <span class="page-link" style="border: none; background: none;">...</span>
                <?php endif; ?>
                <a href="?page=<?= $totalPages ?>" class="page-link"><?= $totalPages ?></a>
            <?php endif; ?>
            
            <?php if ($page < $totalPages): ?>
                <a href="?page=<?= $page + 1 ?>" class="page-link"><i class="fas fa-chevron-right"></i></a>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </main>

    <div id="lightbox" onclick="closeLightbox()">
        <div class="lb-controls" onclick="event.stopPropagation()">
            <a id="lb-download" href="#" download class="lb-btn" title="Скачать">
                <i class="fas fa-download"></i>
            </a>
            <button class="lb-btn" onclick="closeLightbox()" title="Закрыть (Esc)">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <button class="lb-btn lb-nav prev" onclick="event.stopPropagation(); navigateLightbox(-1)" title="Предыдущее (←)">
            <i class="fas fa-chevron-left"></i>
        </button>
        <img id="lb-img" src="" onclick="event.stopPropagation()" alt="Просмотр изображения">
        <button class="lb-btn lb-nav next" onclick="event.stopPropagation(); navigateLightbox(1)" title="Следующее (→)">
            <i class="fas fa-chevron-right"></i>
        </button>
        <div class="lb-counter" id="lb-counter" onclick="event.stopPropagation()"></div>
    </div>

    <div id="shareModalOverlay" class="modal-overlay" onclick="closeShareModal(event)">
        <div class="share-modal" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h3><i class="fas fa-share-alt"></i> Поделиться</h3>
                <button class="close-modal-btn" onclick="closeShareModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="share-group">
                    <label>Прямая ссылка</label>
                    <div class="input-with-btn">
                        <input type="text" id="share-direct" readonly>
                        <button class="copy-btn" onclick="copyInput('share-direct', this)">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="share-group">
                    <label>HTML код</label>
                    <div class="input-with-btn">
                        <input type="text" id="share-html" readonly>
                        <button class="copy-btn" onclick="copyInput('share-html', this)">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="share-group">
                    <label>BBCode для форумов</label>
                    <div class="input-with-btn">
                        <input type="text" id="share-bb" readonly>
                        <button class="copy-btn" onclick="copyInput('share-bb', this)">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="share-group">
                    <label>Markdown</label>
                    <div class="input-with-btn">
                        <input type="text" id="share-md" readonly>
                        <button class="copy-btn" onclick="copyInput('share-md', this)">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="loader-overlay" id="loader">
        <div class="loader-content">
            <div class="loader-spinner"></div>
            <h3>Загрузка файлов</h3>
            <p>Пожалуйста, подождите...</p>
            <div class="progress-container">
                <div class="progress-bar" id="progressFill"></div>
            </div>
            <div class="progress-text" id="progressText">0%</div>
        </div>
    </div>

    <div id="toast">
        <i class="fas"></i>
        <span id="toast-msg"></span>
    </div>

    <script>
        'use strict';

        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const loader = document.getElementById('loader');
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');

        // Массив изображений для навигации
        let galleryImages = [];
        let currentImageIndex = 0;

        // Инициализация галереи
        document.querySelectorAll('.card').forEach((card, index) => {
            const overlay = card.querySelector('.card-overlay');
            if (overlay) {
                const imgSrc = overlay.getAttribute('onclick')?.match(/'([^']+)'/)?.[1];
                if (imgSrc) {
                    galleryImages.push(imgSrc);
                }
            }
        });

        // Эффект скролла для хедера
        const header = document.querySelector('header');
        let lastScroll = 0;
        window.addEventListener('scroll', () => {
            const currentScroll = window.pageYOffset;
            if (currentScroll > 50) {
                header.classList.add('scrolled');
            } else {
                header.classList.remove('scrolled');
            }
            lastScroll = currentScroll;
        }, { passive: true });

        dropZone.onclick = () => fileInput.click();

        dropZone.ondragover = (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        };

        dropZone.ondragleave = (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
        };

        dropZone.ondrop = (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            handleUpload(e.dataTransfer.files);
        };

        fileInput.onchange = () => handleUpload(fileInput.files);

        function handleUpload(files) {
            if (!files.length) return;

            const fd = new FormData();
            for (let i = 0; i < files.length; i++) {
                fd.append('photos[]', files[i]);
            }
            fd.append('csrf_token', '<?= $_SESSION['csrf_token'] ?>');

            loader.style.display = 'flex';
            progressFill.style.width = '0%';
            progressText.textContent = '0%';

            const xhr = new XMLHttpRequest();
            xhr.open('POST', 'index.php', true);

            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    progressFill.style.width = percent + '%';
                    progressText.textContent = percent + '%';
                }
            };

            xhr.onload = () => {
                loader.style.display = 'none';
                if (xhr.status === 200) {
                    try {
                        const res = JSON.parse(xhr.responseText);
                        if (res.success) {
                            showToast('Загружено: ' + res.count + ' файл(ов)', 'success');
                            setTimeout(() => window.location.reload(), 1000);
                        } else {
                            showToast(res.errors.join('\n'), 'error');
                        }
                    } catch (e) {
                        showToast('Ошибка обработки ответа', 'error');
                    }
                } else {
                    showToast('Ошибка сети', 'error');
                }
            };

            xhr.onerror = () => {
                loader.style.display = 'none';
                showToast('Ошибка соединения', 'error');
            };

            xhr.send(fd);
        }

        function openLightbox(src) {
            const lb = document.getElementById('lightbox');
            const img = document.getElementById('lb-img');
            const download = document.getElementById('lb-download');
            const counter = document.getElementById('lb-counter');

            // Найти индекс изображения
            currentImageIndex = galleryImages.indexOf(src);
            if (currentImageIndex === -1) currentImageIndex = 0;

            img.src = src;
            download.href = src;

            // Обновить счётчик
            if (galleryImages.length > 0) {
                counter.textContent = `${currentImageIndex + 1} / ${galleryImages.length}`;
                counter.style.display = 'block';
            } else {
                counter.style.display = 'none';
            }

            lb.style.display = 'flex';
            requestAnimationFrame(() => lb.classList.add('visible'));
            document.body.style.overflow = 'hidden';
        }

        function closeLightbox() {
            const lb = document.getElementById('lightbox');
            lb.classList.remove('visible');
            setTimeout(() => {
                lb.style.display = 'none';
                document.getElementById('lb-img').src = '';
                document.body.style.overflow = '';
            }, 400);
        }

        function navigateLightbox(direction) {
            if (galleryImages.length === 0) return;

            currentImageIndex += direction;
            if (currentImageIndex < 0) currentImageIndex = galleryImages.length - 1;
            if (currentImageIndex >= galleryImages.length) currentImageIndex = 0;

            const img = document.getElementById('lb-img');
            const download = document.getElementById('lb-download');
            const counter = document.getElementById('lb-counter');

            // Анимация смены изображения
            img.style.opacity = '0';
            img.style.transform = direction > 0 ? 'translateX(30px)' : 'translateX(-30px)';

            setTimeout(() => {
                img.src = galleryImages[currentImageIndex];
                download.href = galleryImages[currentImageIndex];
                counter.textContent = `${currentImageIndex + 1} / ${galleryImages.length}`;

                img.style.transform = direction > 0 ? 'translateX(-30px)' : 'translateX(30px)';
                requestAnimationFrame(() => {
                    img.style.transition = 'all 0.3s ease';
                    img.style.opacity = '1';
                    img.style.transform = 'translateX(0)';
                });
            }, 200);

            setTimeout(() => {
                img.style.transition = '';
            }, 500);
        }

        function openShareModal(url, name) {
            const escapeHtml = (text) => text.replace(/[&<>"']/g, (m) => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            })[m]);
            
            document.getElementById('share-direct').value = url;
            document.getElementById('share-html').value = '<a href="' + escapeHtml(url) + '" target="_blank"><img src="' + escapeHtml(url) + '" alt="' + escapeHtml(name) + '"></a>';
            document.getElementById('share-bb').value = '[url=' + url + '][img]' + url + '[/img][/url]';
            document.getElementById('share-md').value = '![' + name.replace(/[\[\]]/g, '') + '](' + url + ')';
            document.getElementById('shareModalOverlay').classList.add('active');
        }

        function closeShareModal(e) {
            if (!e || e.target.id === 'shareModalOverlay') {
                document.getElementById('shareModalOverlay').classList.remove('active');
            }
        }

        function copyInput(id, btn) {
            const el = document.getElementById(id);
            el.select();
            el.setSelectionRange(0, 99999);

            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(el.value).then(() => {
                    showCopySuccess(btn);
                    showToast('Скопировано!', 'success');
                }).catch(() => {
                    fallbackCopy(el, btn);
                });
            } else {
                fallbackCopy(el, btn);
            }
        }

        function fallbackCopy(el, btn) {
            try {
                document.execCommand('copy');
                showCopySuccess(btn);
                showToast('Скопировано!', 'success');
            } catch (e) {
                showToast('Ошибка копирования', 'error');
            }
        }

        function showCopySuccess(btn) {
            const icon = btn.querySelector('i');
            btn.classList.add('copied');
            icon.className = 'fas fa-check';
            setTimeout(() => {
                btn.classList.remove('copied');
                icon.className = 'fas fa-copy';
            }, 1500);
        }

        function showToast(msg, type) {
            const t = document.getElementById('toast');
            const icon = t.querySelector('i');
            t.className = type;
            icon.className = type === 'success' ? 'fas fa-check-circle' : 'fas fa-exclamation-circle';
            document.getElementById('toast-msg').innerText = msg;
            t.classList.add('show');
            if (window.toastTimeout) clearTimeout(window.toastTimeout);
            window.toastTimeout = setTimeout(() => t.classList.remove('show'), 3500);
        }

        // Улучшенная обработка клавиш
        document.onkeydown = (e) => {
            const lb = document.getElementById('lightbox');
            const isLightboxOpen = lb.style.display === 'flex';

            if (e.key === 'Escape') {
                closeLightbox();
                closeShareModal();
            }

            if (isLightboxOpen) {
                if (e.key === 'ArrowLeft') {
                    e.preventDefault();
                    navigateLightbox(-1);
                } else if (e.key === 'ArrowRight') {
                    e.preventDefault();
                    navigateLightbox(1);
                } else if (e.key === ' ') {
                    e.preventDefault();
                    navigateLightbox(1);
                }
            }
        };

        // Поддержка свайпов для lightbox
        let touchStartX = 0;
        let touchStartY = 0;
        let touchEndX = 0;
        let touchEndY = 0;

        const lightbox = document.getElementById('lightbox');

        lightbox.addEventListener('touchstart', (e) => {
            touchStartX = e.changedTouches[0].screenX;
            touchStartY = e.changedTouches[0].screenY;
        }, { passive: true });

        lightbox.addEventListener('touchend', (e) => {
            touchEndX = e.changedTouches[0].screenX;
            touchEndY = e.changedTouches[0].screenY;
            handleSwipe();
        }, { passive: true });

        function handleSwipe() {
            const diffX = touchEndX - touchStartX;
            const diffY = touchEndY - touchStartY;
            const minSwipeDistance = 50;

            // Проверяем что это горизонтальный свайп
            if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > minSwipeDistance) {
                if (diffX > 0) {
                    navigateLightbox(-1); // Свайп вправо - предыдущее
                } else {
                    navigateLightbox(1); // Свайп влево - следующее
                }
            } else if (Math.abs(diffY) > minSwipeDistance && diffY > 0) {
                // Свайп вниз - закрыть
                closeLightbox();
            }
        }

        // Вставка из буфера обмена
        document.addEventListener('paste', (e) => {
            const items = e.clipboardData.items;
            const files = [];
            for (let i = 0; i < items.length; i++) {
                if (items[i].type.indexOf('image') !== -1) {
                    files.push(items[i].getAsFile());
                }
            }
            if (files.length > 0) {
                handleUpload(files);
            }
        });

        // Ленивая загрузка изображений с Intersection Observer
        if ('IntersectionObserver' in window) {
            const imageObserver = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const img = entry.target;
                        if (img.dataset.src) {
                            img.src = img.dataset.src;
                            img.removeAttribute('data-src');
                        }
                        imageObserver.unobserve(img);
                    }
                });
            }, { rootMargin: '50px' });

            document.querySelectorAll('.card img[loading="lazy"]').forEach(img => {
                imageObserver.observe(img);
            });
        }

        // Добавляем эффект ripple для кнопок
        document.querySelectorAll('.btn, .action-btn').forEach(btn => {
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
                    background: rgba(255, 255, 255, 0.3);
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

        // Добавляем CSS для ripple эффекта
        const style = document.createElement('style');
        style.textContent = `
            @keyframes rippleEffect {
                to { transform: scale(4); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>