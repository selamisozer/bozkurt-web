<?php
/**
 * BOZKURT — iletişim formu işleyicisi
 * Natro Linux Hosting (PHP 8.x) için tasarlandı.
 *
 * - JSON yanıt: fetch ile gönderim (form JS'i)
 * - HTML yanıt: JavaScript olmadan gönderim
 * - Honeypot + IP başına hız sınırı + sunucu tarafı doğrulama
 */

declare(strict_types=1);

const TO_EMAIL   = 'info@bozkurt-bf.com';   // Formun düşeceği adres
const FROM_EMAIL = 'info@bozkurt-bf.com'; // Mevcut kutu; Reply-To gönderene ayarlanır
const SITE_NAME  = 'BOZKURT-BF';
const COOLDOWN   = 20; // saniye

ini_set('default_charset', 'UTF-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

$isAjax = (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'fetch');

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
        . 'a{display:inline-block;margin-top:22px;background:#1f3f7f;color:#fff;'
        . 'padding:14px 26px;text-decoration:none;font-size:11px;letter-spacing:.16em;'
        . 'text-transform:uppercase}</style></head><body><main>'
        . '<h1>' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</h1>'
        . '<p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
        . '<p style="margin-top:10px;color:#6b7280">'
        . $note
        . '</p>'
        . '<a href="/">BOZKURT</a></main></body></html>';
    exit;
}

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

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    respond(false, 'Bu adres yalnızca form gönderimini kabul eder.', 405, $isAjax);
}

$requestedLang = field('lang', 8);
if (in_array($requestedLang, ['tr', 'en', 'de', 'ru', 'fr', 'ar'], true)) {
    $GLOBALS['FORM_LANG'] = $requestedLang;
}

// Honeypot: botlar doldurur, sessizce başarı dön.
if (field('website', 200) !== '') {
    respond(true, '', 200, $isAjax);
}

$name    = field('name', 120);
$company = field('company', 160);
$email   = field('email', 160);
$phone   = field('phone', 60);
$subject = field('subject', 160);
$message = field('message', 5000);
$lang    = field('lang', 8);
$kvkk    = field('kvkk', 8);

if (str_len($name) < 2) {
    respond(false, 'Lütfen adınızı ve soyadınızı yazın.', 422, $isAjax);
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    respond(false, 'Geçerli bir e-posta adresi girin.', 422, $isAjax);
}
if (str_len($message) < 10) {
    respond(false, 'Lütfen mesajınızı biraz daha açıklayıcı yazın.', 422, $isAjax);
}
if ($kvkk !== '1') {
    respond(false, 'KVKK aydınlatma metnini onaylamanız gerekiyor.', 422, $isAjax);
}

// Aynı IP'den art arda gönderim koruması
$ip       = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$rateFile = sys_get_temp_dir() . '/bozkurt-form-' . hash('sha256', $ip);
if (is_file($rateFile) && (time() - (int) filemtime($rateFile)) < COOLDOWN) {
    respond(false, 'Çok sık gönderim yapıldı. Lütfen biraz bekleyip tekrar deneyin.', 429, $isAjax);
}
@touch($rateFile);

$mailSubject = 'Web formu: ' . ($subject !== '' ? $subject : 'Genel');
$encodedSubject = '=?UTF-8?B?' . base64_encode($mailSubject) . '?=';

$body = "Ad Soyad : {$name}\n"
    . "Firma    : {$company}\n"
    . "E-Posta  : {$email}\n"
    . "Telefon  : {$phone}\n"
    . "Konu     : {$subject}\n"
    . "Dil      : {$lang}\n"
    . "IP       : {$ip}\n"
    . "Tarih    : " . date('d.m.Y H:i') . "\n"
    . "----------------------------------------\n\n"
    . $message . "\n";

$headers = [
    'From: ' . SITE_NAME . ' <' . FROM_EMAIL . '>',
    'Reply-To: ' . $email,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'X-Mailer: PHP/' . phpversion(),
];

// -f: zarf göndericisi alan adıyla hizalanır (SPF/DMARC uyumu için gerekli).
$sent = @mail(TO_EMAIL, $encodedSubject, $body, implode("\r\n", $headers), '-f' . FROM_EMAIL);

if (!$sent) {
    error_log('[BOZKURT form] mail() gönderilemedi: ' . $email);
    respond(false, 'Mesaj gönderilemedi. Lütfen daha sonra tekrar deneyin.', 500, $isAjax);
}

respond(true, 'Mesajınız alındı. Ekibimiz en kısa sürede size dönüş yapacak.', 200, $isAjax);
