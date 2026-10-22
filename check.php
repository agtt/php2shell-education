<?php
/** Local, non-invasive PHP2Shell version check. */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(2);
}

function affected($version)
{
    // PHP's fixes for CVE-2026-109618 and CVE-2026-109619 shipped in
    // 8.2.35, 8.3.36, 8.4.27, and 8.5.12.
    if ($version < 80200) return true;
    if ($version < 80300) return $version < 80235;
    if ($version < 80400) return $version < 80336;
    if ($version < 80500) return $version < 80427;
    if ($version < 80600) return $version < 80512;
    return false;
}

if ($argc === 1) {
    $version = PHP_VERSION_ID;
} elseif (($argc === 2 && preg_match('/^https?:\/\//i', $argv[1]))
    || ($argc === 3 && $argv[1] === '--url')) {
    $url = $argc === 2 ? $argv[1] : $argv[2];
    $parts = parse_url($url);
    if ($parts === false || !isset($parts['scheme'])
        || !in_array($parts['scheme'], array('http', 'https'), true)
        || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
        exit(2);
    }

    // One ordinary GET. No upload, crafted body, retry, or exploit stage.
    $context = stream_context_create(array('http' => array(
        'method' => 'GET',
        'timeout' => 5,
        'follow_location' => 0,
        'ignore_errors' => true,
    )));
    $stream = @fopen($url, 'r', false, $context);
    if ($stream === false) {
        exit(2);
    }
    $metadata = stream_get_meta_data($stream);
    fclose($stream);
    $headers = isset($metadata['wrapper_data']) ? $metadata['wrapper_data'] : array();
    if (!isset($headers[0]) || !preg_match('/^HTTP\/\S+ 2\d\d\b/', $headers[0])) {
        exit(2);
    }

    $poweredBy = null;
    foreach ($headers as $header) {
        if (stripos($header, 'X-Powered-By:') === 0) {
            $poweredBy = trim(substr($header, strlen('X-Powered-By:')));
            break;
        }
    }
    if (!is_string($poweredBy) || !preg_match('/^PHP\/(\d+)\.(\d+)\.(\d+)$/', $poweredBy, $match)) {
        exit(2);
    }
    $version = (int) $match[1] * 10000 + (int) $match[2] * 100 + (int) $match[3];
} else {
    exit(2);
}

$isAffected = affected($version);
echo $isAffected ? "vulnerable\n" : "not vulnerable\n";
exit($isAffected ? 1 : 0);
