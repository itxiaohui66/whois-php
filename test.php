<?php
header('Content-Type: application/json');

// 测试基本功能
echo json_encode([
    'status' => 'OK',
    'message' => '服务器正常运行',
    'php_version' => PHP_VERSION,
    'functions' => [
        'dns_get_record' => function_exists('dns_get_record'),
        'exec' => function_exists('exec'),
        'json_encode' => function_exists('json_encode')
    ]
]);
?>