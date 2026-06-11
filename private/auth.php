<?php
/**
 * Shared session + auth helpers, used by both public/index.php and public/api.php
 * so they share one session and one definition of "authenticated".
 */

declare(strict_types=1);

require_once __DIR__ . '/config.php';

function mani_session_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
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
}

function mani_is_authed(): bool
{
    return !empty($_SESSION['mani_auth']);
}

/** For API endpoints: bail out with 401 JSON if not logged in. */
function mani_require_auth(): void
{
    if (!mani_is_authed()) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'unauthorized']);
        exit;
    }
}
