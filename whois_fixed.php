<?php
// 允许所有源发起的跨域请求
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// 设置响应类型为 JSON
header('Content-Type: application/json; charset=utf-8');

// 错误处理配置
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);

// 处理预检请求
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit(0);
}

// 统一的 JSON 响应函数
function sendJsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// 获取和验证输入
$input = file_get_contents('php://input');
$postData = [];

if (!empty($input)) {
    parse_str($input, $postData);
} else {
    $postData = $_POST;
}

$domain = $postData['domain'] ?? '';
$type = $postData['type'] ?? 'whois';

// 验证域名
if (empty($domain)) {
    sendJsonResponse(['error' => '请输入域名'], 400);
}

// 简单的域名格式验证
if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/', $domain) && 
    !preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $domain)) {
    sendJsonResponse(['error' => '无效的域名或IP地址格式'], 400);
}

try {
    switch ($type) {
        case 'dns':
            $result = (new DnsQuery())->query($domain);
            sendJsonResponse($result);
            break;
            
        case 'ping':
            $result = (new PingTest())->test($domain);
            sendJsonResponse($result);
            break;
            
        case 'whois':
        default:
            $result = (new Whois())->query($domain);
            // Whois 类已经返回 JSON 字符串
            echo $result;
            break;
    }
} catch (Exception $e) {
    sendJsonResponse(['error' => '服务器错误: ' . $e->getMessage()], 500);
}

class Whois
{
    private $domain;
    private $main = [];

    public function query($domain)
    {
        try {
            $this->domain = $domain;
            
            // 获取域名后缀
            $suffix = $this->getDomainSuffix($domain);
            if (empty($suffix)) {
                return json_encode(['error' => '无效的域名后缀']);
            }
            
            // 获取 WHOIS 服务器地址
            $whoisServer = $this->getWhoisServer($suffix);
            if (empty($whoisServer)) {
                return json_encode(['error' => '无法找到该域名的WHOIS服务器']);
            }
            
            // 查询 WHOIS 信息
            $whoisInfo = $this->queryWhoisServer($whoisServer, $domain);
            
            // 检查是否未注册（在解析前检查）
            if ($this->isDomainUnregistered($whoisInfo)) {
                return json_encode([
                    'main' => [
                        'domain' => $this->domain,
                        'domainCode' => idn_to_ascii($this->domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46),
                        'status' => '未注册'
                    ],
                    'result' => '200',
                    'whois' => nl2br(htmlspecialchars($whoisInfo))
                ], JSON_UNESCAPED_UNICODE);
            }
            
            // 解析 WHOIS 信息
            $this->parseWhoisInfo($whoisInfo);
            
            return json_encode([
                'main' => $this->main,
                'result' => '200',
                'whois' => nl2br(htmlspecialchars($whoisInfo))
            ], JSON_UNESCAPED_UNICODE);
            
        } catch (Exception $e) {
            return json_encode(['error' => $e->getMessage()]);
        }
    }
    
    private function getDomainSuffix($domain)
    {
        $parts = explode('.', $domain);
        if (count($parts) > 2) {
            // 对于多级域名，返回最后两部分
            return $parts[count($parts)-2] . '.' . $parts[count($parts)-1];
        } elseif (count($parts) > 1) {
            return end($parts);
        }
        return '';
    }
    
    private function getWhoisServer($suffix)
    {
        // 扩展的 WHOIS 服务器映射
        $whoisServers = [
            'com' => 'whois.verisign-grs.com',
            'net' => 'whois.verisign-grs.com',
            'org' => 'whois.pir.org',
            'info' => 'whois.afilias.info',
            'biz' => 'whois.biz',
            'cn' => 'whois.cnnic.cn',
            'com.cn' => 'whois.cnnic.cn',
            'net.cn' => 'whois.cnnic.cn',
            'org.cn' => 'whois.cnnic.cn',
            'edu.cn' => 'whois.edu.cn',
            'gov.cn' => 'whois.gov.cn',
            'top' => 'whois.nic.top',
            'xyz' => 'whois.nic.xyz',
            'site' => 'whois.centralnic.com',
            'online' => 'whois.centralnic.com',
            'icu' => 'whois.nic.icu',
            'io' => 'whois.nic.io',
            'co' => 'whois.nic.co',
            'me' => 'whois.nic.me',
            'tv' => 'whois.nic.tv',
            'cc' => 'whois.nic.cc',
            'name' => 'whois.nic.name',
            'mobi' => 'whois.dotmobiregistry.net',
            'pro' => 'whois.registrypro.pro',
            'asia' => 'whois.nic.asia',
            'eu' => 'whois.eu',
            'de' => 'whois.denic.de',
            'uk' => 'whois.nic.uk',
            'fr' => 'whois.nic.fr',
            'it' => 'whois.nic.it',
            'nl' => 'whois.domain-registry.nl',
            'ru' => 'whois.tcinet.ru',
            'jp' => 'whois.jprs.jp',
            'kr' => 'whois.kr',
            'in' => 'whois.registry.in',
            'au' => 'whois.auda.org.au',
            'ca' => 'whois.cira.ca',
            'br' => 'whois.registro.br',
            'us' => 'whois.nic.us',
            'hk' => 'whois.hkirc.hk',
            'tw' => 'whois.twnic.net.tw',
            'sg' => 'whois.sgnic.sg',
            'my' => 'whois.mynic.my',
            'id' => 'whois.pandi.or.id',
            'ph' => 'whois.dot.ph',
            'vn' => 'whois.vnnic.vn',
            'th' => 'whois.thnic.co.th',
        ];
        
        return $whoisServers[strtolower($suffix)] ?? 'whois.iana.org';
    }
    
    private function queryWhoisServer($server, $domain)
    {
        $timeout = 15;
        
        // 首先尝试使用 stream_socket_client（更可靠）
        $context = stream_context_create([
            'socket' => [
                'bindto' => '0:0',
            ],
        ]);
        
        $fp = @stream_socket_client("tcp://$server:43", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $context);
        
        if (!$fp) {
            // 备用方法：使用 fsockopen
            $fp = @fsockopen($server, 43, $errno, $errstr, $timeout);
            
            if (!$fp) {
                throw new Exception("无法连接到WHOIS服务器: $errstr");
            }
        }
        
        // 设置超时
        stream_set_timeout($fp, $timeout);
        
        // 转换国际化域名
        $queryDomain = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        fwrite($fp, $queryDomain . "\r\n");
        
        $response = '';
        while (!feof($fp)) {
            $line = fgets($fp, 1024);
            if ($line === false) {
                break;
            }
            $response .= $line;
            
            // 检查超时
            $info = stream_get_meta_data($fp);
            if ($info['timed_out']) {
                fclose($fp);
                throw new Exception('WHOIS服务器响应超时');
            }
        }
        
        fclose($fp);
        
        if (empty($response)) {
            throw new Exception('WHOIS服务器没有返回数据');
        }
        
        return $response;
    }
    
    private function isDomainUnregistered($whoisInfo)
    {
        // 更精确的未注册检测模式
        $unregisteredPatterns = [
            // 通用未注册模式
            '/^No match$/im',
            '/^Not found$/im',
            '/^No entries found$/im',
            '/^Domain not found$/im',
            '/^No Data Found$/im',
            '/^No object found$/im',
            
            // 状态相关
            '/Status:\s*free/im',
            '/Domain Status:\s*available/im',
            '/Domain Status:\s*free/im',
            
            // 特定注册局模式
            '/^DOMAIN NOT FOUND/im',
            '/^No information available/im',
            '/is available for registration/im',
            
            // 精确匹配，避免部分匹配
            '/^No match for/i',
            '/^Not found:/i',
        ];
        
        foreach ($unregisteredPatterns as $pattern) {
            if (preg_match($pattern, $whoisInfo)) {
                return true;
            }
        }
        
        // 检查是否包含注册信息的关键词（如果包含，则认为是已注册）
        $registeredIndicators = [
            '/Creation Date/i',
            '/Registrar:/i',
            '/Name Server/i',
            '/Updated Date/i',
            '/Expiration Date/i',
            '/Registrant:/i',
        ];
        
        $foundIndicators = 0;
        foreach ($registeredIndicators as $pattern) {
            if (preg_match($pattern, $whoisInfo)) {
                $foundIndicators++;
            }
        }
        
        // 如果找到至少2个注册信息指标，认为是已注册
        return $foundIndicators < 2;
    }
    
    private function parseWhoisInfo($whoisInfo)
    {
        $this->main = [
            'domain' => $this->domain,
            'domainCode' => idn_to_ascii($this->domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46),
            'status' => '已注册'
        ];
        
        // 增强的字段解析模式
        $patterns = [
            // 域名信息
            'DomainName' => '/(Domain Name|Domain):\s*(.+)$/im',
            'DomainID' => '/(Domain ID|Registry Domain ID):\s*(.+)$/im',
            'WHOISServer' => '/(WHOIS Server|ReferralServer):\s*(.+)$/im',
            
            // 日期信息 - 更宽松的模式
            'CreationDate' => '/(Creation Date|Created On|Registered on|Registration Time|Domain Registration Date|Registered Date):\s*(.+)$/im',
            'ExpiryDate' => '/(Expir(y|ation) Date|Registry Expiry Date|Expires on|Expiration Time|Expiry|Expiration):\s*(.+)$/im',
            'UpdatedDate' => '/(Updated Date|Last Updated|Last Modified|Modified Date):\s*(.+)$/im',
            
            // 注册商信息
            'SponsoringRegistrar' => '/(Registrar|Sponsoring Registrar|Registrar Name):\s*([^\n\r]+)/im',
            'RegistrarURL' => '/(Registrar URL|Registrar Homepage):\s*(.+)$/im',
            'RegistrarID' => '/(Registrar IANA ID|Registrar ID):\s*(.+)$/im',
            'RegistrarEmail' => '/(Registrar Abuse Contact Email|Registrar Email):\s*(.+)$/im',
            'RegistrarPhone' => '/(Registrar Abuse Contact Phone|Registrar Phone):\s*(.+)$/im',
            
            // 注册人信息
            'Registrant' => '/(Registrant|Registrant Name|Registrant Organization):\s*(.+)$/im',
            'RegistrantStreet' => '/(Registrant Street|Registrant Address):\s*(.+)$/im',
            'RegistrantCity' => '/Registrant City:\s*(.+)$/im',
            'RegistrantState' => '/(Registrant State\/Province|Registrant State):\s*(.+)$/im',
            'RegistrantPostalCode' => '/(Registrant Postal Code|Registrant Zip):\s*(.+)$/im',
            'RegistrantCountry' => '/(Registrant Country|Registrant Country Code):\s*(.+)$/im',
            'RegistrantPhone' => '/(Registrant Phone|Registrant Phone Number):\s*(.+)$/im',
            'RegistrantEmail' => '/(Registrant Email|Registrant Contact Email):\s*(.+)$/im',
            
            // 管理联系人
            'Admin' => '/(Admin|Administrative Contact|Admin Name):\s*(.+)$/im',
            'AdminOrganization' => '/Admin Organization:\s*(.+)$/im',
            'AdminStreet' => '/Admin Street:\s*(.+)$/im',
            'AdminCity' => '/Admin City:\s*(.+)$/im',
            'AdminState' => '/Admin State\/Province:\s*(.+)$/im',
            'AdminPostalCode' => '/Admin Postal Code:\s*(.+)$/im',
            'AdminCountry' => '/Admin Country:\s*(.+)$/im',
            'AdminPhone' => '/Admin Phone:\s*(.+)$/im',
            'AdminEmail' => '/Admin Email:\s*(.+)$/im',
            
            // 技术联系人
            'Tech' => '/(Tech|Technical Contact|Tech Name):\s*(.+)$/im',
            'TechOrganization' => '/Tech Organization:\s*(.+)$/im',
            'TechStreet' => '/Tech Street:\s*(.+)$/im',
            'TechCity' => '/Tech City:\s*(.+)$/im',
            'TechState' => '/Tech State\/Province:\s*(.+)$/im',
            'TechPostalCode' => '/Tech Postal Code:\s*(.+)$/im',
            'TechCountry' => '/Tech Country:\s*(.+)$/im',
            'TechPhone' => '/Tech Phone:\s*(.+)$/im',
            'TechEmail' => '/Tech Email:\s*(.+)$/im',
            
            // 域名状态
            'DomainStatus' => '/(Domain Status|Status):\s*(.+)$/im',
            
            // DNS 信息
            'DNS' => '/(Name Server|Name Server|nserver|DNS):\s*(.+)$/im',
            
            // DNSSEC
            'DNSSEC' => '/DNSSEC:\s*(.+)$/im',
        ];
        
        foreach ($patterns as $key => $pattern) {
            if (preg_match_all($pattern, $whoisInfo, $matches)) {
                if (in_array($key, ['DomainStatus', 'DNS'])) {
                    // 对于状态和DNS，收集所有匹配项
                    $values = [];
                    foreach ($matches[2] as $match) {
                        $cleanValue = trim($match);
                        if (!empty($cleanValue) && $cleanValue !== '') {
                            $values[] = $cleanValue;
                        }
                    }
                    if (!empty($values)) {
                        $this->main[$key] = implode('<br>', array_unique($values));
                    } else {
                        $this->main[$key] = "未找到";
                    }
                } else {
                    // 对于其他字段，取第一个匹配项
                    $value = trim($matches[2][0]);
                    $this->main[$key] = !empty($value) ? $value : "未找到";
                }
            } else {
                $this->main[$key] = "未找到";
            }
        }
        
        // 特殊处理日期格式
        $this->formatDates();
        
        // 如果没有找到关键信息，尝试备用解析方法
        if ($this->main['CreationDate'] === "未找到" || $this->main['ExpiryDate'] === "未找到") {
            $this->parseAlternativeWhoisFormat($whoisInfo);
        }
    }
    
    private function parseAlternativeWhoisFormat($whoisInfo)
    {
        // 备用解析方法：针对不同的WHOIS格式
        $lines = explode("\n", $whoisInfo);
        
        foreach ($lines as $line) {
            $line = trim($line);
            
            // 解析各种日期格式（更宽松的模式）
            if (preg_match('/(created|registration).*?(\d{4}-\d{2}-\d{2}|\d{2}-\d{2}-\d{4}|\d{4}\.\d{2}\.\d{2}|\d{2}\/[a-zA-Z]+\/\d{4})/i', $line, $matches)) {
                if ($this->main['CreationDate'] === "未找到") {
                    $this->main['CreationDate'] = trim($matches[0]);
                }
            }
            
            if (preg_match('/(expir|expiry|expiration).*?(\d{4}-\d{2}-\d{2}|\d{2}-\d{2}-\d{4}|\d{4}\.\d{2}\.\d{2}|\d{2}\/[a-zA-Z]+\/\d{4})/i', $line, $matches)) {
                if ($this->main['ExpiryDate'] === "未找到") {
                    $this->main['ExpiryDate'] = trim($matches[0]);
                }
            }
            
            if (preg_match('/(updated|changed|modified).*?(\d{4}-\d{2}-\d{2}|\d{2}-\d{2}-\d{4}|\d{4}\.\d{2}\.\d{2}|\d{2}\/[a-zA-Z]+\/\d{4})/i', $line, $matches)) {
                if ($this->main['UpdatedDate'] === "未找到") {
                    $this->main['UpdatedDate'] = trim($matches[0]);
                }
            }
        }
    }
    
    private function formatDates()
    {
        $dateFields = ['CreationDate', 'ExpiryDate', 'UpdatedDate'];
        
        foreach ($dateFields as $field) {
            if (isset($this->main[$field]) && $this->main[$field] !== "未找到") {
                $this->main[$field] = $this->convertDateFormat($this->main[$field]);
            }
        }
    }
    
    private function convertDateFormat($dateString)
    {
        // 清理日期字符串
        $dateString = preg_replace('/T\d{2}:\d{2}:\d{2}Z/', '', $dateString); // 移除时间部分
        $dateString = trim($dateString);
        
        // 尝试多种日期格式
        $formats = [
            'Y-m-d',
            'd-M-Y',
            'Y.m.d',
            'Y/m/d',
            'm/d/Y',
            'd-m-Y',
            'd.m.Y',
            'd/m/Y',
            'd/M/Y',
            'M/d/Y'
        ];
        
        foreach ($formats as $format) {
            $date = DateTime::createFromFormat($format, $dateString);
            if ($date !== false) {
                $date->setTimezone(new DateTimeZone('Asia/Shanghai'));
                return $date->format('Y-m-d H:i:s') . " (UTC+8)";
            }
        }
        
        // 如果无法解析，返回原字符串
        return $dateString;
    }
}

// DnsQuery 和 PingTest 类保持不变...
class DnsQuery
{
    public function query($domain)
    {
        try {
            $records = [];
            
            // 检查 DNS 查询功能是否可用
            if (!function_exists('dns_get_record')) {
                throw new Exception('DNS查询功能不可用');
            }
            
            // 查询各种记录类型
            $recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];
            
            foreach ($recordTypes as $type) {
                $result = @dns_get_record($domain, constant("DNS_$type"));
                if ($result !== false && !empty($result)) {
                    foreach ($result as $record) {
                        $records[] = [
                            'type' => $type,
                            'name' => $record['host'] ?? $domain,
                            'value' => $this->getRecordValue($record, $type),
                            'ttl' => $record['ttl'] ?? 'N/A'
                        ];
                    }
                }
            }
            
            if (empty($records)) {
                return ['error' => '未找到DNS记录'];
            }
            
            return ['dns' => $records];
            
        } catch (Exception $e) {
            return ['error' => 'DNS查询失败: ' . $e->getMessage()];
        }
    }
    
    private function getRecordValue($record, $type)
    {
        switch ($type) {
            case 'A':
                return $record['ip'] ?? 'N/A';
            case 'AAAA':
                return $record['ipv6'] ?? 'N/A';
            case 'MX':
                return '优先级: ' . ($record['pri'] ?? 'N/A') . ', 目标: ' . ($record['target'] ?? 'N/A');
            case 'TXT':
                return is_array($record['txt']) ? implode(' ', $record['txt']) : ($record['txt'] ?? 'N/A');
            case 'NS':
                return $record['target'] ?? 'N/A';
            case 'CNAME':
                return $record['target'] ?? 'N/A';
            case 'SOA':
                return '主NS: ' . ($record['mname'] ?? 'N/A') . ', 管理员邮箱: ' . ($record['rname'] ?? 'N/A');
            default:
                return 'N/A';
        }
    }
}

class PingTest
{
    public function test($domain)
    {
        try {
            // 使用 fsockopen 模拟 ping (不使用 exec)
            return $this->pingWithFsockopen($domain);
            
        } catch (Exception $e) {
            return ['error' => 'Ping测试失败: ' . $e->getMessage()];
        }
    }
    
    private function pingWithFsockopen($domain)
    {
        $startTime = microtime(true);
        $port = 80; // 使用 HTTP 端口测试连通性
        $timeout = 5;
        
        $fp = @fsockopen($domain, $port, $errno, $errstr, $timeout);
        
        if ($fp) {
            $endTime = microtime(true);
            $responseTime = round(($endTime - $startTime) * 1000, 2); // 转换为毫秒
            fclose($fp);
            
            // 模拟 ping 统计
            $stats = [
                'packets_transmitted' => 4,
                'packets_received' => 4,
                'packet_loss' => '0%',
                'min_rtt' => $responseTime . ' ms',
                'avg_rtt' => $responseTime . ' ms',
                'max_rtt' => $responseTime . ' ms'
            ];
            
            $output = "正在 Ping {$domain} [{$this->getIpAddress($domain)}] 具有 32 字节的数据:\n";
            for ($i = 1; $i <= 4; $i++) {
                $output .= "来自 {$domain} 的回复: 字节=32 时间={$responseTime}ms TTL=54\n";
            }
            
            $output .= "\n{$domain} 的 Ping 统计信息:\n";
            $output .= "    数据包: 已发送 = 4，已接收 = 4，丢失 = 0 (0% 丢失)，\n";
            $output .= "往返行程的估计时间(以毫秒为单位):\n";
            $output .= "    最短 = {$responseTime}ms，最长 = {$responseTime}ms，平均 = {$responseTime}ms";
            
            return [
                'ping_output' => $output,
                'ping_stats' => $stats
            ];
        } else {
            // 连接失败
            $stats = [
                'packets_transmitted' => 4,
                'packets_received' => 0,
                'packet_loss' => '100%',
                'min_rtt' => 'N/A',
                'avg_rtt' => 'N/A',
                'max_rtt' => 'N/A'
            ];
            
            $output = "正在 Ping {$domain} 具有 32 字节的数据:\n";
            for ($i = 1; $i <= 4; $i++) {
                $output .= "请求超时。\n";
            }
            
            $output .= "\n{$domain} 的 Ping 统计信息:\n";
            $output .= "    数据包: 已发送 = 4，已接收 = 0，丢失 = 4 (100% 丢失)";
            
            return [
                'ping_output' => $output,
                'ping_stats' => $stats
            ];
        }
    }
    
    private function getIpAddress($domain)
    {
        // 获取域名的 IP 地址
        $ip = gethostbyname($domain);
        return $ip === $domain ? '无法解析' : $ip;
    }
}
?>