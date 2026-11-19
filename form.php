<?php
/**
 * BOZKURT — iletişim ve kariyer formu işleyicisi
 * Natro Linux Hosting (PHP 7.4+ / 8.x) için tasarlandı.
 *
 * Gönderim: Microsoft 365 Graph API (client credentials, Mail.Send uygulama izni)
 * - Natro'da PHP mail() kapalı olduğu için SMTP yerine Graph kullanılır.
 * - Yapılandırma public_html DIŞINDAKI bozkurt-config.php dosyasından okunur.
 * - Test modunda alıcı test_to adresine yönlenir.
 *
 * - JSON yanıt: fetch ile gönderim
 * - HTML yanıt: JavaScript olmadan gönderim (iletişim formu)
 * - Honeypot + IP başına hız sınırı + sunucu tarafı doğrulama
 */

declare(strict_types=1);

const SITE_NAME          = 'BOZKURT-BF';
const MAX_CV_BYTES       = 3 * 1024 * 1024;   // 3 MB
const SIMPLE_ATTACH_BYTES = 2 * 1024 * 1024;  // 2 MB üstü Graph upload session
const COOLDOWN           = 20;                 // saniye

ini_set('default_charset', 'UTF-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

$isAjax = (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'fetch')
    || (strpos((string) ($_SERVER['HTTP_ACCEPT'] ?? ''), 'application/json') !== false);

/* ------------------------------------------------------------------ */
/*  Metinler                                                          */
/* ------------------------------------------------------------------ */

function ui_text(string $key): string
{
    $lang = $GLOBALS['FORM_LANG'] ?? 'tr';
    $map = [
        'ok_title' => [
            'tr' => 'Mesajınız alındı', 'en' => 'Message received', 'de' => 'Nachricht erhalten',
            'ru' => 'Сообщение получено', 'fr' => 'Message reçu', 'ar' => 'تم استلام رسالتك',
        ],
        'ok_note' => [
            'tr' => 'Ekibimiz en kısa sürede size dönüş yapacak.',
            'en' => 'Our team will get back to you shortly.',
            'de' => 'Unser Team meldet sich in Kürze bei Ihnen.',
            'ru' => 'Наша команда свяжется с вами в ближайшее время.',
            'fr' => 'Notre équipe vous répondra dans les meilleurs délais.',
            'ar' => 'سيتواصل فريقنا معك في أقرب وقت ممكن.',
        ],
        'fail_title' => [
            'tr' => 'Gönderilemedi', 'en' => 'Sending failed', 'de' => 'Senden fehlgeschlagen',
            'ru' => 'Не удалось отправить', 'fr' => "Échec de l'envoi", 'ar' => 'تعذّر الإرسال',
        ],
        'fail_note' => [
            'tr' => 'Lütfen daha sonra tekrar deneyin.',
            'en' => 'Please try again later.',
            'de' => 'Bitte versuchen Sie es später erneut.',
            'ru' => 'Пожалуйста, попробуйте позже.',
            'fr' => 'Veuillez réessayer plus tard.',
            'ar' => 'يرجى المحاولة لاحقًا.',
        ],
    ];
    return $map[$key][$lang] ?? $map[$key]['en'];
}

function respond(bool $ok, string $message, int $status, bool $ajax): void
{
    http_response_code($status);

    if ($ajax) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => $ok, 'message' => $message], JSON_UNESCAPED_UNICODE);
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    $lang = $GLOBALS['FORM_LANG'] ?? 'tr';
    $dir = $lang === 'ar' ? 'rtl' : 'ltr';
    $title = ui_text($ok ? 'ok_title' : 'fail_title');
    $note = ui_text($ok ? 'ok_note' : 'fail_note');
    echo '<!doctype html><html lang="' . $lang . '" dir="' . $dir . '"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>' . $title . ' | ' . SITE_NAME . '</title>'
        . '<style>body{font-family:system-ui,sans-serif;background:#eef0f4;color:#1d1d1d;'
        . 'display:grid;place-items:center;min-height:100vh;margin:0;padding:24px}'
        . 'main{background:#fff;border:1px solid #dfe2e8;padding:40px;max-width:460px}'
        . 'h1{font-size:20px;margin:0 0 12px}p{font-size:15px;line-height:1.6;margin:0}'
        . 'a{display:inline-block;margin-top:22px;background:#214080;color:#fff;'
        . 'padding:14px 26px;text-decoration:none;font-size:11px;letter-spacing:.16em;'
        . 'text-transform:uppercase}</style></head><body><main>'
        . '<h1>' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</h1>'
        . '<p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
        . '<p style="margin-top:10px;color:#6b7280">' . $note . '</p>'
        . '<a href="/">BOZKURT</a></main></body></html>';
    exit;
}

/* ------------------------------------------------------------------ */
/*  Girdi yardımcıları                                                */
/* ------------------------------------------------------------------ */

function str_len(string $value): int
{
    return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
}

function str_cut(string $value, int $max): string
{
    return function_exists('mb_substr') ? mb_substr($value, 0, $max, 'UTF-8') : substr($value, 0, $max);
}

function field(string $key, int $max = 5000): string
{
    $value = $_POST[$key] ?? '';
    if (!is_string($value)) {
        return '';
    }
    $value = str_replace(["\r", "\n", "\0"], ' ', $value);
    $value = trim($value);
    return str_cut($value, $max);
}

function field_list(string $key, int $maxItems = 30): array
{
    $value = $_POST[$key] ?? [];
    if (!is_array($value)) {
        return [];
    }
    $out = [];
    foreach ($value as $item) {
        if (!is_string($item)) {
            continue;
        }
        $item = trim(str_replace(["\r", "\n", "\0"], ' ', $item));
        if ($item !== '') {
            $out[] = str_cut($item, 80);
        }
    }
    return array_slice(array_values(array_unique($out)), 0, $maxItems);
}

/* ------------------------------------------------------------------ */
/*  Yapılandırma                                                      */
/* ------------------------------------------------------------------ */

function load_config(): array
{
    $path = getenv('BOZKURT_CONFIG');
    if (!is_string($path) || $path === '' || !is_file($path)) {
        $path = dirname(__DIR__) . '/bozkurt-config.php';
    }
    if (!is_file($path)) {
        $path = dirname(__DIR__) . '/private/bozkurt-config.php';
    }
    if (!is_file($path)) {
        error_log('[BOZKURT form] yapılandırma bulunamadı.');
        return [];
    }
    $cfg = require $path;
    return is_array($cfg) ? $cfg : [];
}

function graph_ready(array $cfg): bool
{
    foreach (['tenant_id', 'client_id', 'client_secret', 'sender', 'contact_to', 'career_to'] as $key) {
        if (empty($cfg[$key])) {
            return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------------ */
/*  HTTP                                                              */
/* ------------------------------------------------------------------ */

/**
 * @return array{status:int, body:string, error:string}
 */
function http_call(string $method, string $url, array $headers = [], ?string $body = null): array
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];
        if ($body !== null) {
            $opts[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $opts);
        $res = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        return ['status' => $status, 'body' => is_string($res) ? $res : '', 'error' => $error];
    }

    $context = stream_context_create([
        'http' => [
            'method'        => $method,
            'header'        => implode("\r\n", $headers),
            'content'       => $body ?? '',
            'timeout'       => 30,
            'ignore_errors' => true,
        ],
        'ssl' => [
            'verify_peer'      => true,
            'verify_peer_name' => true,
        ],
    ]);
    $res = @file_get_contents($url, false, $context);
    $status = 0;
    if (isset($http_response_header[0]) && preg_match('#\s(\d{3})\s#', $http_response_header[0], $m)) {
        $status = (int) $m[1];
    }
    return ['status' => $status, 'body' => is_string($res) ? $res : '', 'error' => ''];
}

/* ------------------------------------------------------------------ */
/*  Graph                                                             */
/* ------------------------------------------------------------------ */

function graph_token(array $cfg): ?string
{
    $tenant = rawurlencode((string) $cfg['tenant_id']);
    $cacheKey = hash('sha256', $cfg['tenant_id'] . '|' . $cfg['client_id']);
    $cacheFile = sys_get_temp_dir() . '/bozkurt-graph-' . $cacheKey . '.json';

    if (is_file($cacheFile)) {
        $cached = json_decode((string) @file_get_contents($cacheFile), true);
        if (is_array($cached) && !empty($cached['access_token']) && (int) ($cached['expires_at'] ?? 0) > time() + 60) {
            return (string) $cached['access_token'];
        }
    }

    $body = http_build_query([
        'client_id'     => $cfg['client_id'],
        'client_secret' => $cfg['client_secret'],
        'scope'         => 'https://graph.microsoft.com/.default',
        'grant_type'    => 'client_credentials',
    ]);
    $res = http_call(
        'POST',
        'https://login.microsoftonline.com/' . $tenant . '/oauth2/v2.0/token',
        ['Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'],
        $body
    );
    $json = json_decode($res['body'], true);
    if ($res['status'] === 200 && is_array($json) && !empty($json['access_token'])) {
        $expiresIn = (int) ($json['expires_in'] ?? 3599);
        $payload = json_encode([
            'access_token' => $json['access_token'],
            'expires_at'   => time() + max(60, $expiresIn - 60),
        ]);
        if ($payload !== false) {
            @file_put_contents($cacheFile, $payload, LOCK_EX);
            @chmod($cacheFile, 0600);
        }
        return (string) $json['access_token'];
    }

    error_log('[BOZKURT form] token alınamadı: HTTP ' . $res['status'] . ' ' . substr($res['body'], 0, 300));
    return null;
}

/**
 * @param array<string,mixed> $message
 * @param array{name:string,type:string,size:int,content:string}|null $attachment
 */
function graph_send(array $cfg, array $message, ?array $attachment): bool
{
    $token = graph_token($cfg);
    if ($token === null) {
        return false;
    }

    $sender = rawurlencode((string) $cfg['sender']);
    $base = 'https://graph.microsoft.com/v1.0/users/' . $sender;

    if ($attachment !== null && $attachment['size'] > SIMPLE_ATTACH_BYTES) {
        return graph_send_large($base, $token, $message, $attachment);
    }

    if ($attachment !== null) {
        $message['attachments'] = [[
            '@odata.type'  => '#microsoft.graph.fileAttachment',
            'name'         => $attachment['name'],
            'contentType'  => $attachment['type'],
            'contentBytes' => base64_encode($attachment['content']),
        ]];
    }

    $payload = json_encode(
        ['message' => $message, 'saveToSentItems' => false],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    if ($payload === false) {
        return false;
    }

    $res = http_call(
        'POST',
        $base . '/sendMail',
        ['Authorization: Bearer ' . $token, 'Content-Type: application/json', 'Accept: application/json'],
        $payload
    );
    if ($res['status'] === 202) {
        return true;
    }

    error_log('[BOZKURT form] sendMail: HTTP ' . $res['status'] . ' ' . substr($res['body'], 0, 400));
    return false;
}

/**
 * 2 MB üzeri ekler için taslak + upload session + gönder.
 *
 * @param array<string,mixed> $message
 * @param array{name:string,type:string,size:int,content:string} $attachment
 */
function graph_send_large(string $base, string $token, array $message, array $attachment): bool
{
    $jsonHeaders = [
        'Authorization: Bearer ' . $token,
        'Content-Type: application/json',
        'Accept: application/json',
    ];

    $draftPayload = json_encode($message, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($draftPayload === false) {
        return false;
    }
    $draft = http_call('POST', $base . '/messages', $jsonHeaders, $draftPayload);
    $draftJson = json_decode($draft['body'], true);
    $messageId = is_array($draftJson) ? (string) ($draftJson['id'] ?? '') : '';
    if ($draft['status'] !== 201 || $messageId === '') {
        error_log('[BOZKURT form] taslak oluşturulamadı: HTTP ' . $draft['status'] . ' ' . substr($draft['body'], 0, 400));
        return false;
    }

    $sessionPayload = json_encode([
        'AttachmentItem' => [
            'attachmentType' => 'file',
            'name'           => $attachment['name'],
            'size'           => $attachment['size'],
            'contentType'    => $attachment['type'],
        ],
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    $session = http_call(
        'POST',
        $base . '/messages/' . rawurlencode($messageId) . '/attachments/createUploadSession',
        $jsonHeaders,
        (string) $sessionPayload
    );
    $sessionJson = json_decode($session['body'], true);
    $uploadUrl = is_array($sessionJson) ? (string) ($sessionJson['uploadUrl'] ?? '') : '';
    if (($session['status'] !== 200 && $session['status'] !== 201) || $uploadUrl === '') {
        error_log('[BOZKURT form] upload session: HTTP ' . $session['status'] . ' ' . substr($session['body'], 0, 400));
        http_call('DELETE', $base . '/messages/' . rawurlencode($messageId), ['Authorization: Bearer ' . $token], null);
        return false;
    }

    $size = strlen($attachment['content']);
    $upload = http_call(
        'PUT',
        $uploadUrl,
        [
            'Content-Type: application/octet-stream',
            'Content-Length: ' . $size,
            'Content-Range: bytes 0-' . ($size - 1) . '/' . $size,
        ],
        $attachment['content']
    );
    if ($upload['status'] !== 200 && $upload['status'] !== 201) {
        error_log('[BOZKURT form] ek yüklenemedi: HTTP ' . $upload['status'] . ' ' . substr($upload['body'], 0, 400));
        http_call('DELETE', $base . '/messages/' . rawurlencode($messageId), ['Authorization: Bearer ' . $token], null);
        return false;
    }

    $send = http_call(
        'POST',
        $base . '/messages/' . rawurlencode($messageId) . '/send',
        ['Authorization: Bearer ' . $token, 'Content-Length: 0'],
        ''
    );
    if ($send['status'] === 202) {
        return true;
    }

    error_log('[BOZKURT form] taslak gönderilemedi: HTTP ' . $send['status'] . ' ' . substr($send['body'], 0, 400));
    return false;
}

/* ------------------------------------------------------------------ */
/*  CV                                                                */
/* ------------------------------------------------------------------ */

/**
 * @return array{attachment: array{name:string,type:string,size:int,content:string}|null, error: string|null}
 */
function cv_upload(): array
{
    if (!isset($_FILES['cv']) || !is_array($_FILES['cv'])) {
        return ['attachment' => null, 'error' => 'missing'];
    }
    $file = $_FILES['cv'];
    $code = (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($code === UPLOAD_ERR_NO_FILE) {
        return ['attachment' => null, 'error' => 'missing'];
    }
    if ($code !== UPLOAD_ERR_OK) {
        return ['attachment' => null, 'error' => 'upload'];
    }

    $size = (int) ($file['size'] ?? 0);
    if ($size <= 0) {
        return ['attachment' => null, 'error' => 'missing'];
    }
    if ($size > MAX_CV_BYTES) {
        return ['attachment' => null, 'error' => 'size'];
    }

    $name = basename((string) ($file['name'] ?? 'cv'));
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $types = [
        'pdf'  => 'application/pdf',
        'doc'  => 'application/msword',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ];
    if (!isset($types[$ext])) {
        return ['attachment' => null, 'error' => 'type'];
    }

    $tmp = (string) ($file['tmp_name'] ?? '');
    if (PHP_SAPI !== 'cli' && ($tmp === '' || !is_uploaded_file($tmp))) {
        return ['attachment' => null, 'error' => 'upload'];
    }
    $content = @file_get_contents($tmp);
    if ($content === false) {
        return ['attachment' => null, 'error' => 'upload'];
    }

    return [
        'attachment' => ['name' => $name, 'type' => $types[$ext], 'size' => $size, 'content' => $content],
        'error' => null,
    ];
}

/* ------------------------------------------------------------------ */
/*  İstek                                                             */
/* ------------------------------------------------------------------ */

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    respond(false, 'Bu adres yalnızca form gönderimini kabul eder.', 405, $isAjax);
}

$requestedLang = field('lang', 8);
if (in_array($requestedLang, ['tr', 'en', 'de', 'ru', 'fr', 'ar'], true)) {
    $GLOBALS['FORM_LANG'] = $requestedLang;
}

// Honeypot
if (field('website', 200) !== '') {
    respond(true, '', 200, $isAjax);
}

$cfg = load_config();
if (!graph_ready($cfg)) {
    error_log('[BOZKURT form] Graph yapılandırması eksik.');
    respond(false, 'Form yapılandırması henüz tamamlanmadı. Lütfen daha sonra tekrar deneyin.', 500, $isAjax);
}

$formType = field('form_type', 20);
if (!in_array($formType, ['contact', 'career'], true)) {
    $formType = (isset($_POST['position']) || isset($_FILES['cv'])) ? 'career' : 'contact';
}

$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$rateFile = sys_get_temp_dir() . '/bozkurt-form-' . hash('sha256', $ip);
if (is_file($rateFile) && (time() - (int) filemtime($rateFile)) < COOLDOWN) {
    respond(false, 'Çok sık gönderim yapıldı. Lütfen biraz bekleyip tekrar deneyin.', 429, $isAjax);
}
@touch($rateFile);

$name    = field('name', 120);
$email   = field('email', 160);
$phone   = field('phone', 60);
$lang    = field('lang', 8);
$subjectInput = field('subject', 160);
$message = field('message', 5000);

if (str_len($name) < 2) {
    respond(false, 'Lütfen adınızı ve soyadınızı yazın.', 422, $isAjax);
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    respond(false, 'Geçerli bir e-posta adresi girin.', 422, $isAjax);
}

$testMode = !empty($cfg['test_mode']);
$dateLine = date('d.m.Y H:i');
$bodyLines = [];

if ($formType === 'career') {
    $position = field('position', 160);
    $city = field('city', 120);
    $consent = field('consent', 8);
    $cv = cv_upload();

    if (str_len($phone) < 5) {
        respond(false, 'Lütfen geçerli bir telefon numarası yazın.', 422, $isAjax);
    }
    if ($position === '') {
        respond(false, 'Lütfen başvurduğunuz pozisyonu seçin.', 422, $isAjax);
    }
    if ($consent !== '1') {
        respond(false, 'Aydınlatma metnini onaylamanız gerekiyor.', 422, $isAjax);
    }
    if ($cv['error'] === 'missing') {
        respond(false, 'Lütfen özgeçmiş dosyanızı ekleyin.', 422, $isAjax);
    }
    if ($cv['error'] === 'size') {
        respond(false, 'Özgeçmiş dosyası en fazla 3 MB olabilir.', 422, $isAjax);
    }
    if ($cv['error'] === 'type') {
        respond(false, 'Yalnızca PDF, DOC veya DOCX dosyası yükleyin.', 422, $isAjax);
    }
    if ($cv['error'] !== null) {
        respond(false, 'Dosya yüklenemedi. Lütfen tekrar deneyin.', 422, $isAjax);
    }

    $mailSubject = 'Kariyer başvurusu: ' . ($position !== '' ? $position : 'Genel') . ' — ' . $name;
    $bodyLines = [
        'KARİYER BAŞVURUSU',
        'Ad Soyad   : ' . $name,
        'Pozisyon   : ' . $position,
        'Şehir      : ' . $city,
        'Telefon    : ' . $phone,
        'E-Posta    : ' . $email,
        'Dil        : ' . $lang,
        'IP         : ' . $ip,
        'Tarih      : ' . $dateLine,
        '',
        'CAD        : ' . implode(', ', field_list('cad')),
        'Hidrolik   : ' . field('hydraulics', 120),
        'Saha       : ' . field('fieldwork', 120),
        'Kalite     : ' . field('qms', 120),
        'Muayene    : ' . field('inspection', 120),
        'ERP        : ' . field('erp', 120),
        'Planlama   : ' . field('planning', 120),
        'Dil        : ' . field('language', 120),
        'Gümrük     : ' . field('customs', 120),
        'Ehliyet    : ' . field('license', 120),
        'Seyahat    : ' . field('travel', 120),
        'Sistemler  : ' . implode(', ', field_list('systems')),
        '',
        'Ön yazı:',
        $message,
    ];
    $toEmail = $testMode ? (string) ($cfg['test_to'] ?? '') : (string) $cfg['career_to'];
    $attachment = $cv['attachment'];
} else {
    $company = field('company', 160);
    $kvkk = field('kvkk', 8);

    if (str_len($message) < 10) {
        respond(false, 'Lütfen mesajınızı biraz daha açıklayıcı yazın.', 422, $isAjax);
    }
    if ($kvkk !== '1') {
        respond(false, 'KVKK aydınlatma metnini onaylamanız gerekiyor.', 422, $isAjax);
    }

    $mailSubject = 'Web formu: ' . ($subjectInput !== '' ? $subjectInput : 'Genel');
    $bodyLines = [
        'İLETİŞİM FORMU',
        'Ad Soyad : ' . $name,
        'Firma    : ' . $company,
        'E-Posta  : ' . $email,
        'Telefon  : ' . $phone,
        'Konu     : ' . $subjectInput,
        'Dil      : ' . $lang,
        'IP       : ' . $ip,
        'Tarih    : ' . $dateLine,
        '',
        $message,
    ];
    $toEmail = $testMode ? (string) ($cfg['test_to'] ?? '') : (string) $cfg['contact_to'];
    $attachment = null;
}

if ($toEmail === '') {
    error_log('[BOZKURT form] alıcı adresi tanımlı değil.');
    respond(false, 'Form yapılandırması henüz tamamlanmadı. Lütfen daha sonra tekrar deneyin.', 500, $isAjax);
}

if ($testMode) {
    $realTo = $formType === 'career' ? (string) $cfg['career_to'] : (string) $cfg['contact_to'];
    array_unshift($bodyLines, 'TEST MODU — Asıl alıcı: ' . $realTo, '');
    $mailSubject = '[TEST] ' . $mailSubject;
}

$body = implode("\n", $bodyLines) . "\n";

$messagePayload = [
    'subject' => $mailSubject,
    'body'    => ['contentType' => 'Text', 'content' => $body],
    'toRecipients' => [[
        'emailAddress' => ['address' => $toEmail],
    ]],
    'replyTo' => [[
        'emailAddress' => ['address' => $email],
    ]],
];

$sent = graph_send($cfg, $messagePayload, $attachment);

if (!$sent) {
    error_log('[BOZKURT form] Graph gönderimi başarısız: ' . $email);
    respond(false, 'Mesaj gönderilemedi. Lütfen daha sonra tekrar deneyin.', 500, $isAjax);
}

respond(true, 'Mesajınız alındı. Ekibimiz en kısa sürede size dönüş yapacak.', 200, $isAjax);
