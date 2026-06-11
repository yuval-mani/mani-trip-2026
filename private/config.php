<?php
/**
 * Mani Trip — auth config.
 *
 * The shared family password is resolved in this order:
 *   1. MANI_PW_HASH  — a bcrypt/argon hash (preferred). Generate with:
 *        php -r "echo password_hash('YOUR_PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"
 *   2. MANI_PW       — a plaintext password (simpler, slightly less safe at rest).
 *
 * Each can come from a real environment variable (RunCloud → Web App → Env Variables,
 * or an Nginx `fastcgi_param`) OR from a .env file placed next to this config.
 * Env variables take precedence over the .env file.
 *
 * Never commit the real value. config.php and .env are gitignored.
 */

// --- Minimal .env loader (only fills vars that aren't already set) -----------
(function () {
    $envFile = __DIR__ . '/.env';
    if (!is_readable($envFile)) {
        return;
    }
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) {
            continue;
        }
        [$key, $val] = explode('=', $line, 2);
        $key = trim($key);
        $val = trim($val);
        // strip optional surrounding quotes
        if (strlen($val) >= 2 && ($val[0] === '"' || $val[0] === "'") && substr($val, -1) === $val[0]) {
            $val = substr($val, 1, -1);
        }
        if ($key !== '' && getenv($key) === false && !isset($_ENV[$key]) && !isset($_SERVER[$key])) {
            putenv("$key=$val");
            $_ENV[$key] = $val;
        }
    }
})();

function mani_env(string $key): ?string
{
    $v = getenv($key);
    if ($v === false || $v === '') {
        $v = $_SERVER[$key] ?? $_ENV[$key] ?? null;
    }
    return ($v === false || $v === '' || $v === null) ? null : $v;
}

/**
 * Verify a submitted password against the configured hash or plaintext.
 */
function mani_password_ok(string $submitted): bool
{
    $hash = mani_env('MANI_PW_HASH');
    if ($hash !== null) {
        return password_verify($submitted, $hash);
    }
    $plain = mani_env('MANI_PW');
    if ($plain !== null) {
        // constant-time compare to avoid timing leaks
        return hash_equals($plain, $submitted);
    }
    // No password configured — fail closed.
    error_log('mani-trip: no MANI_PW_HASH or MANI_PW configured');
    return false;
}

// --- Brute-force throttle ----------------------------------------------------
const MANI_MAX_ATTEMPTS    = 8;     // attempts allowed per window, per IP
const MANI_WINDOW_SECONDS  = 600;   // 10 minutes
const MANI_THROTTLE_FILE   = __DIR__ . '/.throttle.json';
