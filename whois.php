<?php
// 允许所有源发起的跨域请求
header('Access-Control-Allow-Origin: *');
// 允许特定的 HTTP 方法
header('Access-Control-Allow-Methods: POST');
// 允许的请求头
header('Access-Control-Allow-Headers: Content-Type');

// 设置响应类型为 JSON
header('Content-Type: application/json');

// 处理预检请求
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit(0);
}

// 错误处理 - 禁用 HTML 错误显示
ini_set('display_errors', 0);
error_reporting(0);

// 统一的 JSON 响应函数
function jsonResponse($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data);
    exit;
}

// 验证输入
$domain = $_POST['domain'] ?? '';
$type = $_POST['type'] ?? 'whois';

if (empty($domain)) {
    jsonResponse(['error' => "请输入域名"], 400);
}

// 提取域名
if (!preg_match("~^(?:f|ht)tps?://~i", $domain)) {
    $domain = "http://" . $domain;
}

$parsedUrl = parse_url($domain);

if ($parsedUrl && isset($parsedUrl['host'])) {
    $domain = $parsedUrl['host'];
} else {
    jsonResponse(['error' => "无效的域名格式"], 400);
}

try {
    switch($type) {
        case 'dns':
            $dnsQuery = new DnsQuery();
            $result = $dnsQuery->query($domain);
            jsonResponse($result);
            break;
        case 'ping':
            $pingTest = new PingTest();
            $result = $pingTest->test($domain);
            jsonResponse($result);
            break;
        case 'whois':
        default:
            $whoisQuery = new Whois();
            $result = $whoisQuery->query($domain);
            // Whois 类已经返回 JSON，直接输出
            echo $result;
            break;
    }
} catch (Exception $e) {
    jsonResponse(['error' => '查询过程中发生错误: ' . $e->getMessage()], 500);
}

class Whois
{
    private string $domain;
    private array $main;

    private function getWhoisAddress(string $suffix)
    {
        $curl = curl_init();
        $url = "https://www.iana.org/whois?q=" . $suffix;
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_HEADER, 1);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3";
        curl_setopt($curl, CURLOPT_USERAGENT, $userAgent);
        $data = curl_exec($curl);
        
        if (curl_error($curl)) {
            curl_close($curl);
            throw new Exception('IANA 查询失败: ' . curl_error($curl));
        }
        
        curl_close($curl);
        return $data;
    }

    private function intercept(string $original_string): string
    {
        $noWhois = "This query returned 0 objects.";
        if (strpos($original_string, $noWhois) !== false) {
            throw new Exception("暂不支持此后缀或者无此后缀域名");
        }

        $start_character = "whois:";
        $end_character = "status";

        $start_pos = strpos($original_string, $start_character);
        if ($start_pos === false) {
            throw new Exception("无法找到 WHOIS 服务器地址");
        }
        
        $end_pos = strpos($original_string, $end_character, $start_pos + 1);
        if ($end_pos === false) {
            throw new Exception("无法解析 WHOIS 服务器信息");
        }
        
        $result = substr($original_string, $start_pos + 6, $end_pos - $start_pos - 6);
        return trim($result);
    }

    private function getDomainWhois(string $whoisServiceAddress, string $domain)
    {
        $fp = @fsockopen($whoisServiceAddress, 43, $errno, $errstr, 5);
        if (!$fp) {
            throw new Exception("无法连接到 WHOIS 服务器: $errstr");
        }
        
        $domain = idn_to_ascii($domain);
        $out = $domain . "\r\n";
        fwrite($fp, $out);
        
        $whoisInformation = "";
        while (!feof($fp)) {
            $line = fgets($fp);
            if ($line === false) break;
            $whoisInformation .= $line . "<br>";
        }
        fclose($fp);

        $this->splitWhois($whoisInformation);
        return str_replace(' ', '', $whoisInformation);
    }

    private function splitWhois(string $whoisInformation)
    {
        $main = array('domain' => $this->domain, 'domainCode' => idn_to_ascii($this->domain));

        // 内联 data.json 数据，避免文件读取问题
        $data = [
            "CreationDate" => ["Creation Date", "Created Date", "Registration Time", "Domain Registration Date"],
            "ExpiryDate" => ["Expiry Date", "Expiration Date", "Registry Expiry Date", "Expiration Time"],
            "UpdatedDate" => ["Updated Date", "Last Updated"],
            "SponsoringRegistrar" => ["Sponsoring Registrar", "Registrar"],
            "RegistrarURL" => ["Registrar URL"],
            "Registrant" => ["Registrant", "Registrant Name", "Registrant Organization"],
            "DomainStatus" => ["Domain Status", "Status"],
            "DNS" => ["Name Server", "nserver", "DNS"],
            "DNSSEC" => ["DNSSEC"],
            "RegistrantContactEmail" => ["Registrant Contact Email", "Registrant Email", "Admin Email"],
            "unregistered" => ["No match", "not found", "No entries found", "Status: free", "AVAILABLE", "Not Registered"]
        ];

        foreach ($data["unregistered"] as $keyword) {
            if (strpos($whoisInformation, $keyword) !== false) {
                throw new Exception("未注册");
            }
        }

        foreach ($data as $key => $value) {
            if ($key === "unregistered") continue;
            
            $pattern = implode('|', $value);
            $Regular = '/(?:'.$pattern.'):(.*?)(?:\n|$)/i';
            if (preg_match_all($Regular, $whoisInformation, $matches)) {
                if ($key == "DomainStatus" || $key == "DNS") {
                    $a = array();
                    foreach ($matches[1] as $values) {
                        $parts = explode(" ", strtolower(trim($values)));
                        $a[] = $parts[0];
                    }
                    $rowData = implode('<br>', array_unique($a));
                } else {
                    $rowData = trim($matches[1][0]);
                }
                $rowData = $this->utc($rowData);
                $main[$key] = $rowData;
            } else {
                $main[$key] = "404";
            }
        }
        $this->main = $main;
    }

    private function utc($rowData)
    {
        $inputFormat = 'Y-m-d\TH:i:s\Z';
        $inputFormatTwo = 'Y-m-d\TH:i:s.u\Z';
        $outputFormat = 'Y-m-d H:i:s';
        $timezoneOffset = '+08:00';
        $date = DateTime::createFromFormat($inputFormat, $rowData);
        $dateTwo = DateTime::createFromFormat($inputFormatTwo, $rowData);
        if ($date !== false) {
            $date->setTimezone(new DateTimeZone($timezoneOffset));
            $date->modify('+8 hours');
            $formattedDate = $date->format($outputFormat);
            $rowData = $formattedDate . "&nbsp;&nbsp;UTC+8";
        } else if ($dateTwo !== false) {
            $dateTwo->setTimezone(new DateTimeZone($timezoneOffset));
            $dateTwo->modify('+8 hours');
            $formattedDate = $dateTwo->format($outputFormat);
            $rowData = $formattedDate . "&nbsp;&nbsp;UTC+8";
        }
        return $rowData;
    }

    public function query($domain)
    {
        try {
            $this->domain = $domain;
            $suffix = ltrim(strstr($domain, '.'), ".");
            if (empty($suffix)) {
                throw new Exception("无效的域名后缀");
            }
            
            $data = $this->getWhoisAddress($suffix);
            $whoisServiceAddress = $this->intercept($data);
            $whois = $this->getDomainWhois($whoisServiceAddress, $domain);
            
            return json_encode([
                'main' => $this->main, 
                'result' => "200", 
                'whois' => $whois
            ]);
        } catch (Exception $e) {
            return json_encode([
                'error' => $e->getMessage()
            ]);
        }
    }
}

class DnsQuery
{
    public function query($domain)
    {
        try {
            $dnsRecords = [];
            
            // 查询常见的 DNS 记录类型
            $recordTypes = [
                'A'     => DNS_A,
                'AAAA'  => DNS_AAAA,
                'MX'    => DNS_MX,
                'TXT'   => DNS_TXT,
                'NS'    => DNS_NS,
                'CNAME' => DNS_CNAME
            ];
            
            foreach ($recordTypes as $typeName => $typeConstant) {
                $records = @dns_get_record($domain, $typeConstant);
                if ($records !== false && count($records) > 0) {
                    foreach ($records as $record) {
                        $dnsRecord = [
                            'type' => $typeName,
                            'name' => $record['host'] ?? $domain,
                            'ttl'  => $record['ttl'] ?? 'N/A'
                        ];
                        
                        switch ($typeName) {
                            case 'A':
                                $dnsRecord['value'] = $record['ip'] ?? 'N/A';
                                break;
                            case 'AAAA':
                                $dnsRecord['value'] = $record['ipv6'] ?? 'N/A';
                                break;
                            case 'MX':
                                $dnsRecord['value'] = ($record['pri'] ?? '') . ' ' . ($record['target'] ?? 'N/A');
                                break;
                            case 'TXT':
                                $dnsRecord['value'] = is_array($record['txt']) ? implode(' ', $record['txt']) : ($record['txt'] ?? 'N/A');
                                break;
                            case 'NS':
                                $dnsRecord['value'] = $record['target'] ?? 'N/A';
                                break;
                            case 'CNAME':
                                $dnsRecord['value'] = $record['target'] ?? 'N/A';
                                break;
                            default:
                                $dnsRecord['value'] = 'N/A';
                        }
                        
                        $dnsRecords[] = $dnsRecord;
                    }
                }
            }
            
            if (empty($dnsRecords)) {
                return ['error' => '未找到DNS记录或域名解析失败'];
            }
            
            return ['dns' => $dnsRecords];
        } catch (Exception $e) {
            return ['error' => 'DNS查询失败: ' . $e->getMessage()];
        }
    }
}

class PingTest
{
    public function test($domain)
    {
        try {
            $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
            
            if ($isWindows) {
                $command = "ping -n 4 " . escapeshellarg($domain);
            } else {
                $command = "ping -c 4 " . escapeshellarg($domain);
            }
            
            $output = [];
            $returnCode = 0;
            
            // 执行 ping 命令
            @exec($command . " 2>&1", $output, $returnCode);
            
            $pingOutput = implode("\n", $output);
            
            // 如果 ping 命令执行失败，返回错误信息
            if ($returnCode !== 0 && empty($pingOutput)) {
                return [
                    'error' => 'Ping测试失败: 命令执行错误',
                    'ping_output' => '无法执行ping命令，请检查服务器配置'
                ];
            }
            
            // 解析 ping 统计信息
            $stats = $this->parsePingOutput($pingOutput, $isWindows);
            
            return [
                'ping_output' => $pingOutput,
                'ping_stats' => $stats
            ];
        } catch (Exception $e) {
            return ['error' => 'Ping测试失败: ' . $e->getMessage()];
        }
    }
    
    private function parsePingOutput($output, $isWindows)
    {
        $stats = [
            'packets_transmitted' => 4,
            'packets_received' => 0,
            'packet_loss' => '100%',
            'min_rtt' => 'N/A',
            'avg_rtt' => 'N/A',
            'max_rtt' => 'N/A'
        ];
        
        if ($isWindows) {
            // Windows ping 输出解析
            foreach (explode("\n", $output) as $line) {
                if (preg_match('/Sent = (\d+), Received = (\d+), Lost = (\d+)/', $line, $matches)) {
                    $stats['packets_transmitted'] = intval($matches[1]);
                    $stats['packets_received'] = intval($matches[2]);
                    $lost = intval($matches[3]);
                    $stats['packet_loss'] = round(($lost / $stats['packets_transmitted']) * 100) . '%';
                }
                if (preg_match('/Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms/', $line, $matches)) {
                    $stats['min_rtt'] = $matches[1] . ' ms';
                    $stats['max_rtt'] = $matches[2] . ' ms';
                    $stats['avg_rtt'] = $matches[3] . ' ms';
                }
            }
        } else {
            // Linux/Unix ping 输出解析
            foreach (explode("\n", $output) as $line) {
                if (preg_match('/(\d+) packets transmitted, (\d+) (?:packets )?received/', $line, $matches)) {
                    $stats['packets_transmitted'] = intval($matches[1]);
                    $stats['packets_received'] = intval($matches[2]);
                    $loss = (($stats['packets_transmitted'] - $stats['packets_received']) / $stats['packets_transmitted']) * 100;
                    $stats['packet_loss'] = round($loss) . '%';
                }
                if (preg_match('/min\/avg\/max\/(?:mdev|stddev) = ([.\d]+)\/([.\d]+)\/([.\d]+)/', $line, $matches)) {
                    $stats['min_rtt'] = $matches[1] . ' ms';
                    $stats['avg_rtt'] = $matches[2] . ' ms';
                    $stats['max_rtt'] = $matches[3] . ' ms';
                }
            }
        }
        
        return $stats;
    }
}
?>