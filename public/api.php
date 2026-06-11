<?php
/**
 * Document API — shared, server-side document storage for the trip page.
 *
 * Every action requires a valid session (same login as the page). Files are
 * stored OUTSIDE the web root (private/uploads/) and can only be read back
 * through the auth-gated `download` action below — they are never directly
 * reachable or executable over HTTP.
 */

declare(strict_types=1);

require __DIR__ . '/../private/auth.php';

mani_session_start();
mani_require_auth();

const UPLOAD_DIR    = __DIR__ . '/../private/uploads';
const MANIFEST_FILE = UPLOAD_DIR . '/manifest.json';
const STATE_FILE    = __DIR__ . '/../private/state.json';
const MAX_BYTES     = 25 * 1024 * 1024; // 25 MB per file

// Checkbox lists that may be synced (packing categories + the to-do list).
const STATE_KEYS = ['baby', 'kids', 'clothes', 'medical', 'tech', 'docs', 'todos'];

// Inline-viewable types; everything else is forced to download as an attachment.
const INLINE_MIME = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'application/pdf'];

function json_out($data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data);
    exit;
}

function ensure_dir(): void
{
    if (!is_dir(UPLOAD_DIR)) {
        @mkdir(UPLOAD_DIR, 0775, true);
    }
}

function load_manifest(): array
{
    if (!is_readable(MANIFEST_FILE)) {
        return [];
    }
    $data = json_decode((string) file_get_contents(MANIFEST_FILE), true);
    return is_array($data) ? $data : [];
}

function save_manifest(array $items): void
{
    ensure_dir();
    file_put_contents(MANIFEST_FILE, json_encode(array_values($items)), LOCK_EX);
}

/** Public view of a manifest item (no internal storage path). */
function public_item(array $it): array
{
    return [
        'id'   => $it['id'],
        'name' => $it['name'],
        'mime' => $it['mime'],
        'size' => $it['size'],
        'date' => $it['date'],
    ];
}

function load_state(): array
{
    if (!is_readable(STATE_FILE)) {
        return [];
    }
    $data = json_decode((string) file_get_contents(STATE_FILE), true);
    return is_array($data) ? $data : [];
}

$action = $_GET['action'] ?? '';

switch ($action) {

    case 'state':
        json_out(['checks' => load_state()]);
        // no break

    case 'savecheck':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            json_out(['error' => 'method'], 405);
        }
        $key = (string) ($_POST['key'] ?? '');
        if (!in_array($key, STATE_KEYS, true)) {
            json_out(['error' => 'bad_key'], 400);
        }
        $arr = json_decode((string) ($_POST['data'] ?? ''), true);
        if (!is_array($arr)) {
            json_out(['error' => 'bad_data'], 400);
        }
        // Normalize to a plain list of booleans, capped in length.
        $clean = array_map(fn($v) => (bool) $v, array_slice(array_values($arr), 0, 300));
        $state = load_state();
        $state[$key] = $clean;
        file_put_contents(STATE_FILE, json_encode($state), LOCK_EX);
        json_out(['ok' => true]);
        // no break

    case 'list':
        json_out(['docs' => array_map('public_item', load_manifest())]);
        // no break (json_out exits)

    case 'upload':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            json_out(['error' => 'method'], 405);
        }
        if (empty($_FILES['file']) || !is_array($_FILES['file']['name'])) {
            json_out(['error' => 'no_files'], 400);
        }
        ensure_dir();
        $manifest = load_manifest();
        $names  = $_FILES['file']['name'];
        $tmps   = $_FILES['file']['tmp_name'];
        $errs   = $_FILES['file']['error'];
        $sizes  = $_FILES['file']['size'];
        $types  = $_FILES['file']['type'];

        for ($i = 0; $i < count($names); $i++) {
            if (($errs[$i] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                continue;
            }
            if (!is_uploaded_file($tmps[$i])) {
                continue;
            }
            if (($sizes[$i] ?? 0) > MAX_BYTES) {
                json_out(['error' => 'too_large', 'name' => $names[$i], 'max' => MAX_BYTES], 413);
            }
            $id = bin2hex(random_bytes(16));
            // Stored without any extension so it can never be executed/served as code.
            $dest = UPLOAD_DIR . '/' . $id . '.bin';
            if (!move_uploaded_file($tmps[$i], $dest)) {
                json_out(['error' => 'store_failed', 'name' => $names[$i]], 500);
            }
            // Trust the browser-reported mime only loosely; sniff for images/pdf.
            $mime = (string) ($types[$i] ?? 'application/octet-stream');
            if (function_exists('finfo_open')) {
                $f = finfo_open(FILEINFO_MIME_TYPE);
                $sniffed = finfo_file($f, $dest);
                finfo_close($f);
                if ($sniffed) {
                    $mime = $sniffed;
                }
            }
            $manifest[] = [
                'id'    => $id,
                'name'  => mb_substr((string) $names[$i], 0, 200),
                'mime'  => $mime,
                'size'  => (int) ($sizes[$i] ?? filesize($dest)),
                'date'  => date('d/m/Y'),
                'store' => $id . '.bin',
            ];
        }
        save_manifest($manifest);
        json_out(['docs' => array_map('public_item', $manifest)]);
        // no break

    case 'download':
        $id = (string) ($_GET['id'] ?? '');
        if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
            json_out(['error' => 'bad_id'], 400);
        }
        $item = null;
        foreach (load_manifest() as $it) {
            if ($it['id'] === $id) {
                $item = $it;
                break;
            }
        }
        $path = $item ? UPLOAD_DIR . '/' . $item['store'] : null;
        if (!$item || !is_readable($path)) {
            json_out(['error' => 'not_found'], 404);
        }
        $mime = in_array($item['mime'], INLINE_MIME, true) ? $item['mime'] : 'application/octet-stream';
        $disp = in_array($item['mime'], INLINE_MIME, true) ? 'inline' : 'attachment';
        // Harden against any stored-content being treated as executable in-origin.
        header('Content-Type: ' . $mime);
        header('X-Content-Type-Options: nosniff');
        header("Content-Security-Policy: default-src 'none'; sandbox");
        header('Content-Length: ' . filesize($path));
        $fname = preg_replace('/["\r\n]/', '', $item['name']);
        header("Content-Disposition: $disp; filename=\"$fname\"");
        readfile($path);
        exit;

    case 'delete':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            json_out(['error' => 'method'], 405);
        }
        $id = (string) ($_POST['id'] ?? '');
        if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
            json_out(['error' => 'bad_id'], 400);
        }
        $manifest = load_manifest();
        $kept = [];
        foreach ($manifest as $it) {
            if ($it['id'] === $id) {
                @unlink(UPLOAD_DIR . '/' . $it['store']);
            } else {
                $kept[] = $it;
            }
        }
        save_manifest($kept);
        json_out(['docs' => array_map('public_item', $kept)]);
        // no break

    default:
        json_out(['error' => 'unknown_action'], 400);
}
