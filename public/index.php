<?php
/**
 * Mani Trip — server-side gate.
 *
 * The private page (../private/content.php) is never sent to the browser
 * until a valid shared password has been verified on the server and a
 * session established. The password itself never leaves the server.
 */

declare(strict_types=1);

require __DIR__ . '/../private/config.php';

// --- Secure session ----------------------------------------------------------
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

session_name('mani_session');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => $https,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

$authed = !empty($_SESSION['mani_auth']);
$error  = '';

// --- Logout ------------------------------------------------------------------
if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// --- Throttle helpers (file-based, per IP) -----------------------------------
function mani_client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function mani_throttle_state(): array
{
    if (!is_readable(MANI_THROTTLE_FILE)) {
        return [];
    }
    $data = json_decode((string) file_get_contents(MANI_THROTTLE_FILE), true);
    return is_array($data) ? $data : [];
}

function mani_is_locked(): bool
{
    $state = mani_throttle_state();
    $rec = $state[mani_client_ip()] ?? null;
    if (!$rec) {
        return false;
    }
    if (($rec['first'] ?? 0) + MANI_WINDOW_SECONDS < time()) {
        return false; // window expired
    }
    return ($rec['count'] ?? 0) >= MANI_MAX_ATTEMPTS;
}

function mani_record_failure(): void
{
    $state = mani_throttle_state();
    $ip = mani_client_ip();
    $now = time();
    $rec = $state[$ip] ?? null;
    if (!$rec || ($rec['first'] ?? 0) + MANI_WINDOW_SECONDS < $now) {
        $rec = ['first' => $now, 'count' => 0];
    }
    $rec['count'] = ($rec['count'] ?? 0) + 1;
    $state[$ip] = $rec;
    // prune stale entries
    foreach ($state as $k => $v) {
        if (($v['first'] ?? 0) + MANI_WINDOW_SECONDS < $now) {
            unset($state[$k]);
        }
    }
    @file_put_contents(MANI_THROTTLE_FILE, json_encode($state), LOCK_EX);
}

function mani_clear_failures(): void
{
    $state = mani_throttle_state();
    unset($state[mani_client_ip()]);
    @file_put_contents(MANI_THROTTLE_FILE, json_encode($state), LOCK_EX);
}

// --- Handle login POST -------------------------------------------------------
if (!$authed && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (mani_is_locked()) {
        $error = 'יותר מדי ניסיונות, נסה שוב מאוחר יותר';
    } else {
        $pw = (string) ($_POST['pw'] ?? '');
        if ($pw !== '' && mani_password_ok($pw)) {
            session_regenerate_id(true);
            $_SESSION['mani_auth'] = true;
            mani_clear_failures();
            // Post/Redirect/Get so a refresh doesn't re-submit
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        }
        mani_record_failure();
        $error = 'קוד שגוי, נסה שוב';
    }
}

// --- Serve the private content if authenticated ------------------------------
if ($authed) {
    define('MANI_OK', true);
    require __DIR__ . '/../private/content.php';
    exit;
}

// --- Otherwise: login page ---------------------------------------------------
http_response_code(401);
?>
<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>משפחת מני 🇺🇸 ניו יורק 2026 · אזור פרטי</title>
<link href="https://fonts.googleapis.com/css2?family=Heebo:wght@300;400;500;700;900&family=Oswald:wght@700&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Heebo',sans-serif}
</style>
</head>
<body>
<div style="position:fixed;inset:0;background:linear-gradient(135deg,#002868 0%,#001a4d 50%,#003080 100%);display:flex;align-items:center;justify-content:center">
  <form method="post" style="text-align:center;padding:40px 32px;background:rgba(255,255,255,.07);border-radius:24px;border:1px solid rgba(255,215,0,.25);max-width:340px;width:90%">
    <div style="font-size:52px;margin-bottom:8px">🇺🇸</div>
    <div style="font-family:'Oswald',sans-serif;font-size:28px;font-weight:700;color:white;margin-bottom:4px">משפחת מני</div>
    <div style="font-size:13px;color:rgba(255,255,255,.6);margin-bottom:28px">ניו יורק 2026 · אזור פרטי</div>
    <input name="pw" type="password" placeholder="הכנס קוד גישה" dir="ltr" autofocus autocomplete="current-password"
      style="width:100%;padding:13px 16px;border-radius:12px;border:2px solid <?= $error ? '#FF6B6B' : 'rgba(255,255,255,.2)' ?>;background:rgba(255,255,255,.1);color:white;font-size:16px;text-align:center;outline:none;font-family:inherit;letter-spacing:3px;margin-bottom:12px">
    <button type="submit"
      style="width:100%;padding:13px;background:#BF0A30;color:white;border:none;border-radius:12px;font-size:15px;font-weight:700;cursor:pointer;font-family:inherit">
      כניסה ✈️
    </button>
    <?php if ($error): ?>
      <div style="color:#FF6B6B;font-size:13px;margin-top:10px"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>
  </form>
</div>
</body>
</html>
