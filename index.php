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
            --bg-body: #0a0e17;
            --bg-card: #151c2c;
            --bg-card-hover: #1a2436;
            --bg-header: rgba(10, 14, 23, 0.95);
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --primary-glow: rgba(99, 102, 241, 0.3);
            --accent: #a855f7;
            --accent-glow: rgba(168, 85, 247, 0.3);
            --text-main: #f1f5f9;
            --text-sec: #8892a8;
            --text-muted: #5c6578;
            --border: #252d3d;
            --border-light: #2d3748;
            --danger: #ef4444;
            --danger-glow: rgba(239, 68, 68, 0.3);
            --success: #10b981;
            --success-glow: rgba(16, 185, 129, 0.3);
            --warning: #f59e0b;
            --radius: 16px;
            --radius-sm: 10px;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
            --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.4), 0 10px 10px -5px rgba(0, 0, 0, 0.2);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-body);
            background-image: 
                radial-gradient(ellipse at 0% 0%, rgba(99, 102, 241, 0.08) 0px, transparent 50%),
                radial-gradient(ellipse at 100% 0%, rgba(168, 85, 247, 0.06) 0px, transparent 50%),
                radial-gradient(ellipse at 50% 100%, rgba(99, 102, 241, 0.04) 0px, transparent 50%);
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
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border);
            padding: 1rem 0;
        }

        .container {
            max-width: 1400px;
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
            font-size: 1.5rem;
            font-weight: 700;
            color: white;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: transform 0.2s ease;
            flex-shrink: 0;
        }

        .logo:hover {
            transform: scale(1.02);
        }

        .logo i {
            font-size: 1.3rem;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
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
            gap: 10px;
            flex-shrink: 0;
        }

        .user-pill {
            display: flex;
            align-items: center;
            gap: 10px;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(168, 85, 247, 0.1));
            padding: 8px 16px;
            border-radius: 99px;
            font-size: 0.9rem;
            color: var(--text-main);
            border: 1px solid var(--border);
            font-weight: 500;
            white-space: nowrap;
        }

        .user-pill i {
            color: var(--primary);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 10px 20px;
            border-radius: var(--radius-sm);
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            border: none;
            text-decoration: none;
            white-space: nowrap;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            color: white;
            box-shadow: 0 4px 15px var(--primary-glow);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px var(--primary-glow);
        }

        .btn-primary:active {
            transform: translateY(0);
        }

        .btn-icon {
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-sec);
            width: 42px;
            height: 42px;
            padding: 0;
            border-radius: var(--radius-sm);
        }

        .btn-icon:hover {
            background: var(--bg-card-hover);
            color: white;
            border-color: var(--primary);
        }

        .btn-icon.logout:hover {
            color: var(--danger);
            border-color: var(--danger);
            background: rgba(239, 68, 68, 0.1);
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 380px;
            gap: 1.5rem;
            margin: 2rem 0;
        }

        .upload-area {
            background: var(--bg-card);
            border: 2px dashed var(--border);
            border-radius: var(--radius);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 3rem 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .upload-area::before {
            content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, var(--primary-glow), var(--accent-glow));
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .upload-area:hover,
        .upload-area.dragover {
            border-color: var(--primary);
            transform: translateY(-3px);
        }

        .upload-area:hover::before,
        .upload-area.dragover::before {
            opacity: 1;
        }

        .upload-area > * {
            position: relative;
            z-index: 1;
        }

        .upload-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1.5rem;
            box-shadow: 0 10px 30px var(--primary-glow);
        }

        .upload-icon i {
            font-size: 2rem;
            color: white;
        }

        .upload-area h3 {
            margin: 0 0 0.5rem 0;
            font-weight: 600;
            font-size: 1.25rem;
        }

        .upload-area p {
            margin: 0;
            color: var(--text-sec);
            font-size: 0.9rem;
        }

        .upload-hint {
            margin-top: 1rem;
            padding: 8px 16px;
            background: rgba(99, 102, 241, 0.1);
            border-radius: 99px;
            font-size: 0.8rem;
            color: var(--primary);
        }

        .stats-panel {
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 1.5rem;
            border: 1px solid var(--border);
        }

        .stats-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }

        .stats-header i {
            color: var(--primary);
        }

        .stats-header h3 {
            margin: 0;
            font-size: 1rem;
            font-weight: 600;
        }

        .stat-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }

        .stat-row:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }

        .stat-label {
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--text-sec);
            font-size: 0.9rem;
        }

        .stat-label i {
            width: 18px;
            text-align: center;
            color: var(--text-muted);
        }

        .stat-val {
            color: white;
            font-weight: 600;
            font-size: 0.95rem;
        }

        .storage-bar {
            margin-top: 1.5rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }

        .storage-info {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 0.85rem;
        }

        .storage-info span:first-child {
            color: var(--text-sec);
        }

        .storage-info span:last-child {
            color: var(--text-main);
            font-weight: 500;
        }

        .storage-track {
            height: 8px;
            background: var(--border);
            border-radius: 99px;
            overflow: hidden;
        }

        .storage-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--accent));
            border-radius: 99px;
            transition: width 0.5s ease;
        }

        .storage-fill.warning {
            background: linear-gradient(90deg, var(--warning), var(--danger));
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 2.5rem 0 1.5rem;
        }

        .section-title {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.25rem;
            font-weight: 600;
        }

        .section-title i {
            color: var(--primary);
        }

        .photo-count {
            background: var(--bg-card);
            padding: 6px 14px;
            border-radius: 99px;
            font-size: 0.85rem;
            color: var(--text-sec);
            border: 1px solid var(--border);
        }

        .gallery-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 1.5rem;
        }

        .card {
            background: var(--bg-card);
            border-radius: var(--radius);
            overflow: hidden;
            position: relative;
            aspect-ratio: 1;
            box-shadow: var(--shadow);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            border: 1px solid var(--border);
        }

        .card:hover {
            transform: translateY(-8px) scale(1.02);
            box-shadow: var(--shadow-lg), 0 0 30px var(--primary-glow);
            border-color: var(--primary);
        }

        .card img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            transition: transform 0.5s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .card:hover img {
            transform: scale(1.1);
        }

        .card-overlay {
            position: absolute;
            inset: 0;
            background: linear-gradient(to top, rgba(10, 14, 23, 0.95) 0%, rgba(10, 14, 23, 0.5) 40%, transparent 100%);
            opacity: 0;
            transition: opacity 0.3s ease;
            display: flex;
            flex-direction: column;
            justify-content: flex-end;
            padding: 1.25rem;
            cursor: pointer;
        }

        .card:hover .card-overlay {
            opacity: 1;
        }

        .card-actions {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin-bottom: 12px;
            transform: translateY(20px);
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .card:hover .card-actions {
            transform: translateY(0);
        }

        .action-btn {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
        }

        .action-btn:hover {
            background: var(--primary);
            border-color: var(--primary);
            transform: scale(1.15);
            box-shadow: 0 5px 15px var(--primary-glow);
        }

        .action-btn.del:hover {
            background: var(--danger);
            border-color: var(--danger);
            box-shadow: 0 5px 15px var(--danger-glow);
        }

        .file-meta {
            font-size: 0.8rem;
            color: var(--text-sec);
            text-align: center;
            opacity: 0;
            transform: translateY(10px);
            transition: all 0.3s ease;
        }

        .card:hover .file-meta {
            opacity: 1;
            transform: translateY(0);
        }

        .empty-state {
            grid-column: 1 / -1;
            text-align: center;
            padding: 5rem 2rem;
            background: var(--bg-card);
            border: 2px dashed var(--border);
            border-radius: var(--radius);
        }

        .empty-icon {
            width: 100px;
            height: 100px;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(168, 85, 247, 0.1));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
        }

        .empty-icon i {
            font-size: 2.5rem;
            color: var(--text-muted);
        }

        .empty-state h3 {
            margin: 0 0 0.5rem;
            color: var(--text-main);
        }

        .empty-state p {
            color: var(--text-sec);
            margin: 0;
        }

        .pagination {
            display: flex;
            justify-content: center;
            gap: 8px;
            margin-top: 3rem;
            flex-wrap: wrap;
        }

        .page-link {
            min-width: 42px;
            height: 42px;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0 12px;
            border-radius: var(--radius-sm);
            background: var(--bg-card);
            color: var(--text-sec);
            text-decoration: none;
            border: 1px solid var(--border);
            font-weight: 500;
            transition: all 0.2s ease;
        }

        .page-link:hover {
            background: var(--bg-card-hover);
            color: white;
            border-color: var(--primary);
        }

        .page-link.active {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            color: white;
            border-color: transparent;
            box-shadow: 0 4px 15px var(--primary-glow);
        }

        #lightbox {
            position: fixed;
            inset: 0;
            background: rgba(5, 7, 12, 0.98);
            z-index: 1000;
            display: none;
            justify-content: center;
            align-items: center;
            opacity: 0;
            transition: opacity 0.3s ease;
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
        }

        #lightbox.visible {
            opacity: 1;
        }

        #lightbox img {
            max-width: 92vw;
            max-height: 88vh;
            border-radius: var(--radius-sm);
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.8);
        }

        .lb-controls {
            position: absolute;
            top: 20px;
            right: 20px;
            display: flex;
            gap: 10px;
        }

        .lb-btn {
            width: 48px;
            height: 48px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.25rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .lb-btn:hover {
            background: var(--primary);
            border-color: var(--primary);
        }

        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(10, 14, 23, 0.9);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            z-index: 2000;
            display: none;
            justify-content: center;
            align-items: center;
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .modal-overlay.active {
            display: flex;
            opacity: 1;
        }

        .share-modal {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            width: 90%;
            max-width: 520px;
            padding: 0;
            box-shadow: var(--shadow-lg);
            transform: scale(0.95) translateY(20px);
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            overflow: hidden;
        }

        .modal-overlay.active .share-modal {
            transform: scale(1) translateY(0);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.25rem 1.5rem;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(168, 85, 247, 0.1));
            border-bottom: 1px solid var(--border);
        }

        .modal-header h3 {
            margin: 0;
            font-size: 1.1rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .modal-header h3 i {
            color: var(--primary);
        }

        .close-modal-btn {
            background: none;
            border: none;
            color: var(--text-sec);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0;
            line-height: 1;
            transition: color 0.2s ease;
        }

        .close-modal-btn:hover {
            color: white;
        }

        .modal-body {
            padding: 1.5rem;
        }

        .share-group {
            margin-bottom: 1.25rem;
        }

        .share-group:last-child {
            margin-bottom: 0;
        }

        .share-group label {
            display: block;
            color: var(--text-sec);
            font-size: 0.85rem;
            margin-bottom: 8px;
            font-weight: 500;
        }

        .input-with-btn {
            display: flex;
            gap: 8px;
        }

        .input-with-btn input {
            flex: 1;
            background: var(--bg-body);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            padding: 12px 14px;
            color: var(--text-main);
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
        }

        .input-with-btn input:focus {
            border-color: var(--primary);
            outline: none;
            box-shadow: 0 0 0 3px var(--primary-glow);
        }

        .input-with-btn .copy-btn {
            background: var(--primary);
            border: none;
            color: white;
            border-radius: var(--radius-sm);
            width: 48px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .input-with-btn .copy-btn:hover {
            background: var(--primary-hover);
            transform: scale(1.05);
        }

        .input-with-btn .copy-btn.copied {
            background: var(--success);
        }

        .loader-overlay {
            position: fixed;
            inset: 0;
            background: rgba(10, 14, 23, 0.98);
            z-index: 3000;
            display: none;
            justify-content: center;
            align-items: center;
            flex-direction: column;
        }

        .loader-content {
            text-align: center;
        }

        .loader-spinner {
            width: 60px;
            height: 60px;
            border: 3px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 1.5rem;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .loader-content h3 {
            margin: 0 0 0.5rem;
            font-size: 1.25rem;
        }

        .loader-content p {
            color: var(--text-sec);
            margin: 0 0 1.5rem;
            font-size: 0.9rem;
        }

        .progress-container {
            width: 320px;
            height: 8px;
            background: var(--border);
            border-radius: 99px;
            overflow: hidden;
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--accent));
            width: 0%;
            transition: width 0.2s ease;
            border-radius: 99px;
        }

        .progress-text {
            margin-top: 10px;
            font-size: 0.85rem;
            color: var(--text-sec);
        }

        #toast {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: var(--bg-card);
            color: white;
            padding: 14px 24px;
            border-radius: var(--radius-sm);
            border: 1px solid var(--border);
            box-shadow: var(--shadow-lg);
            display: flex;
            align-items: center;
            gap: 12px;
            z-index: 4000;
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            font-weight: 500;
        }

        #toast.show {
            transform: translateX(-50%) translateY(0);
        }

        #toast.success {
            border-color: var(--success);
            box-shadow: var(--shadow-lg), 0 0 20px var(--success-glow);
        }

        #toast.success i {
            color: var(--success);
        }

        #toast.error {
            border-color: var(--danger);
            box-shadow: var(--shadow-lg), 0 0 20px var(--danger-glow);
        }

        #toast.error i {
            color: var(--danger);
        }

        @media (max-width: 900px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
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
                padding: 10px 14px;
            }

            .gallery-grid {
                grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
                gap: 1rem;
            }

            .upload-area {
                padding: 2rem 1.5rem;
            }

            .upload-icon {
                width: 60px;
                height: 60px;
            }

            .upload-icon i {
                font-size: 1.5rem;
            }
        }

        @media (hover: none) {
            .card-overlay {
                opacity: 1;
                background: linear-gradient(to top, rgba(10, 14, 23, 0.9) 0%, transparent 60%);
            }

            .card-actions {
                transform: translateY(0);
            }

            .file-meta {
                opacity: 1;
                transform: translateY(0);
            }
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
            <button class="lb-btn" onclick="closeLightbox()" title="Закрыть">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <img id="lb-img" src="" onclick="event.stopPropagation()" alt="Просмотр изображения">
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
            img.src = src;
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
            }, 300);
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

        document.onkeydown = (e) => {
            if (e.key === 'Escape') {
                closeLightbox();
                closeShareModal();
            }
        };

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
    </script>
</body>
</html>