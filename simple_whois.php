<?php
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');

$domain = $_POST['domain'] ?? '';
$type = $_POST['type'] ?? 'whois';

if (empty($domain)) {
    echo json_encode(['error' => '请输入域名']);
    exit;
}

// 简单的响应测试
echo json_encode([
    'status' => 'success',
    'domain' => $domain,
    'type' => $type,
    'message' => '服务器正常响应',
    'timestamp' => date('Y-m-d H:i:s')
]);
?>