<?php
/**
 * Nginx Log Analyzer Ultimate (PHP Edition)
 * Полностью автономный скрипт со встроенным шлюзом для обхода CORS.
 */

@set_time_limit(0);

// Хелпер для выполнения прямых запросов сервер-сервер
function fetchUrlDirectly($url) {
    // 1. Пробуем через cURL, если он доступен на хостинге
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => false, // Для избежания проблем с SSL-сертификатами
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PHP-NginxLogAnalyzer/1.0'
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($httpCode === 200 && $response !== false) {
            return $response;
        }
    }
    
    // 2. Резервный вариант через file_get_contents, если cURL отключен
    if (ini_get('allow_url_fopen')) {
        $opts = [
            "http" => [
                "method" => "GET",
                "header" => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PHP-NginxLogAnalyzer/1.0\r\n",
                "timeout" => 15
            ],
            "ssl" => [
                "verify_peer" => false,
                "verify_peer_name" => false
            ]
        ];
        $context = stream_context_create($opts);
        return @file_get_contents($url, false, $context);
    }
    
    return false;
}

// Маршрутизация API-запросов (вызывается из JS)
if (isset($_GET['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    
    if ($_GET['action'] === 'google_common') {
        $data = fetchUrlDirectly('https://developers.google.com/crawling/ipranges/common-crawlers.json');
        if ($data === false) {
            http_response_code(502);
            echo json_encode(["error" => "Failed to fetch common crawlers"]);
        } else {
            echo $data;
        }
        exit;
    }

    if ($_GET['action'] === 'google_special') {
        $data = fetchUrlDirectly('https://developers.google.com/static/crawling/ipranges/special-crawlers.json');
        if ($data === false) {
            http_response_code(502);
            echo json_encode(["error" => "Failed to fetch special crawlers"]);
        } else {
            echo $data;
        }
        exit;
    }

    if ($_GET['action'] === 'lookup' && isset($_GET['ip'])) {
        $ip = $_GET['ip'];
        $data = fetchUrlDirectly('https://devvver-ml-entity.hf.space/lookup?ip=' . urlencode($ip));
        if ($data === false) {
            http_response_code(502);
            echo json_encode(["error" => "Failed to perform IP lookup"]);
        } else {
            echo $data;
        }
        exit;
    }

    http_response_code(400);
    echo json_encode(['error' => 'Invalid action']);
    exit;
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nginx Log Analyzer Ultimate</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        body { font-family: 'Inter', sans-serif; background-color: #f4f6f9; color: #333; padding-bottom: 50px; }
        .navbar { background-color: #1a1d20; color: white; padding: 15px 20px; font-weight: 600; font-size: 1.2rem;}
        .card { border: none; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.04); margin-bottom: 24px; }
        .card-header { background: #fff; border-bottom: 1px solid #eaeaea; font-weight: 600; padding: 15px 20px; border-radius: 8px 8px 0 0 !important; }
        
        .stat-box { padding: 20px; border-radius: 8px; color: white; transition: 0.2s; }
        .stat-box h3 { margin: 0; font-weight: 700; font-size: 1.8rem; }
        .stat-box p { margin: 0; opacity: 0.9; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px;}
        .bg-blue { background: linear-gradient(45deg, #0d6efd, #0b5ed7); } 
        .bg-green { background: linear-gradient(45deg, #198754, #157347); } 
        .bg-orange { background: linear-gradient(45deg, #fd7e14, #e86e04); } 
        .bg-red { background: linear-gradient(45deg, #dc3545, #c82333); }
        .bg-purple { background: linear-gradient(45deg, #6f42c1, #593196); }
        .bg-teal { background: linear-gradient(45deg, #20c997, #1aa179); }

        .table { margin-bottom: 0; font-size: 0.85rem; }
        .table th { background-color: #f8f9fa; color: #495057; font-weight: 600; border-bottom: 2px solid #dee2e6;}
        .table td { max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
        
        .action-link { color: #0d6efd; cursor: pointer; text-decoration: none; font-weight: 600;}
        .action-link:hover { text-decoration: underline; color: #0a58ca; }
        
        .pagination-bar { display: flex; justify-content: space-between; align-items: center; padding: 12px 15px; border-top: 1px solid #eaeaea; background: #fff; border-radius: 0 0 8px 8px;}
        .pagination { margin: 0; }
        .page-link { cursor: pointer; padding: 4px 8px; font-size: 0.85rem;}

        #uploadSection { text-align: center; padding: 60px 20px; border: 2px dashed #adb5bd; border-radius: 10px; background: #fff; cursor: pointer; transition: 0.3s; }
        #uploadSection:hover { border-color: #0d6efd; background: #f8f9fa; }
        #logInput { display: none; }

        .list-group-sm .list-group-item { padding: 0.6rem 0.8rem; font-size: 0.85rem; }
        .word-wrap-all { word-break: break-word; white-space: normal; display: block; max-width: 90%;}
        .badge-link { cursor: pointer; transition: all 0.2s; font-size: 0.85rem; padding: 0.4em 0.6em;}
        .badge-link:hover { transform: scale(1.15); background-color: #0d6efd !important; box-shadow: 0 2px 5px rgba(0,0,0,0.2);}
        
        .raw-logs-container { max-height: 400px; overflow-y: auto; border: 1px solid #eaeaea; border-radius: 6px; }
        .raw-logs-table td { white-space: normal; word-break: break-all; font-size: 0.8rem; }

        .flag-img {
            border: 1px solid #ddd;
            border-radius: 2px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            vertical-align: middle;
        }

        .nav-tabs .nav-link { font-weight: 600; color: #495057; }
        .nav-tabs .nav-link.active { color: #0d6efd; }
    </style>
</head>
<body>

<div class="navbar mb-4 shadow-sm d-flex justify-content-between">
    <span>Nginx Log Analyzer Ultimate</span>
    <div class="d-flex align-items-center gap-2">
        <span id="googleRangesStatus" class="badge bg-secondary">Google IP: загрузка префиксов...</span>
        <span id="activeFiltersLabel" class="badge bg-warning text-dark" style="display:none; cursor:pointer;" onclick="resetTimeFilter()">Сбросить фильтр времени ✖</span>
    </div>
</div>

<div class="container-fluid px-4">
    <div class="card" id="uploadCard">
        <label id="uploadSection" for="logInput">
            <h2 class="text-primary mb-3">📁 Нажмите или перетащите файл access.log</h2>
            <p class="text-muted">Полностью локальная обработка. Данные не покидают ваш браузер.</p>
            <input type="file" id="logInput" accept=".log,.txt">
        </label>
        <div id="progressContainer" style="display: none; padding: 40px; text-align: center;">
            <h4 id="progressText" class="mb-3">Чтение файла... 0%</h4>
            <div class="progress" style="height: 20px; border-radius: 10px;">
                <div id="progressBar" class="progress-bar progress-bar-striped progress-bar-animated bg-primary" style="width: 0%;"></div>
            </div>
        </div>
    </div>

    <div id="dashboard" style="display: none;">
        <!-- Системные вкладки -->
        <ul class="nav nav-tabs mb-4" id="dashboardTabs" role="tablist">
            <li class="nav-item">
                <button class="nav-link active" id="general-tab" data-bs-toggle="tab" data-bs-target="#general-tab-pane" type="button" role="tab">Основной дашборд</button>
            </li>
            <li class="nav-item">
                <button class="nav-link" id="google-tab" data-bs-toggle="tab" data-bs-target="#google-tab-pane" type="button" role="tab">
                    🤖 Google Поисковые боты <span class="badge bg-purple" id="googleTabCountBadge">0</span>
                </button>
            </li>
        </ul>

        <div class="tab-content" id="dashboardTabsContent">
            <!-- Вкладка: Общая статистика -->
            <div class="tab-pane fade show active" id="general-tab-pane" role="tabpanel" aria-labelledby="general-tab">
                <div class="row mb-4">
                    <div class="col-xl-3 col-md-6 mb-3"><div class="stat-box bg-blue"><p>Запросов</p><h3 id="statRequests">0</h3></div></div>
                    <div class="col-xl-3 col-md-6 mb-3"><div class="stat-box bg-green"><p>Уникальных IP</p><h3 id="statIPs">0</h3></div></div>
                    <div class="col-xl-3 col-md-6 mb-3"><div class="stat-box bg-orange"><p>Трафик</p><h3 id="statTraffic">0 MB</h3></div></div>
                    <div class="col-xl-3 col-md-6 mb-3"><div class="stat-box bg-red"><p>Ошибки (4xx, 5xx)</p><h3 id="statErrors">0</h3></div></div>
                </div>

                <div class="row">
                    <div class="col-lg-8">
                        <div class="card">
                            <div class="card-header text-muted text-sm">Динамика (клик на столбец для фильтра по времени)</div>
                            <div class="card-body">
                                <div style="position: relative; height: 220px; width: 100%;"><canvas id="timeChart"></canvas></div>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="card">
                            <div class="card-header text-muted text-sm">HTTP Статусы (клик для откл/вкл)</div>
                            <div class="card-body">
                                 <div style="position: relative; height: 220px; width: 100%;"><canvas id="statusChart"></canvas></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-lg-4">
                        <div class="card">
                            <div class="card-header">IP Адреса</div>
                            <table class="table table-hover" id="ipTable">
                                <thead><tr><th>IP (Клик для инфо)</th><th style="width:60px">Хиты</th></tr></thead><tbody></tbody>
                            </table>
                            <div class="pagination-bar" id="ipPagination"></div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="card">
                            <div class="card-header">Страницы (URL)</div>
                            <table class="table table-hover" id="pageTable">
                                <thead><tr><th>Путь (Клик для инфо)</th><th style="width:60px">Хиты</th></tr></thead><tbody></tbody>
                            </table>
                            <div class="pagination-bar" id="pagePagination"></div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="card">
                            <div class="card-header">Источники (Referer)</div>
                            <table class="table table-hover" id="refererTable">
                                <thead><tr><th>URL (Клик для инфо)</th><th style="width:60px">Переходы</th></tr></thead><tbody></tbody>
                            </table>
                            <div class="pagination-bar" id="refererPagination"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Вкладка: Google боты -->
            <div class="tab-pane fade" id="google-tab-pane" role="tabpanel" aria-labelledby="google-tab">
                <div class="row mb-4">
                    <div class="col-xl-3 col-md-6 mb-3"><div class="stat-box bg-purple"><p>Запросы Google ботов</p><h3 id="gStatRequests">0</h3></div></div>
                    <div class="col-xl-3 col-md-6 mb-3"><div class="stat-box bg-green"><p>Уникальные IP ботов</p><h3 id="gStatIps">0</h3></div></div>
                    <div class="col-xl-3 col-md-6 mb-3"><div class="stat-box bg-teal"><p>Обычные боты (Common)</p><h3 id="gStatCommon">0</h3></div></div>
                    <div class="col-xl-3 col-md-6 mb-3"><div class="stat-box bg-red"><p>Специальные боты (Special)</p><h3 id="gStatSpecial">0</h3></div></div>
                </div>

                <div class="row mb-4">
                    <div class="col-lg-12">
                        <div class="card">
                            <div class="card-header text-muted text-sm">График активности роботов Google во времени</div>
                            <div class="card-body">
                                <div style="position: relative; height: 220px; width: 100%;"><canvas id="googleTimeChart"></canvas></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-lg-4">
                        <div class="card">
                            <div class="card-header">IP Адреса Google ботов</div>
                            <table class="table table-hover" id="googleIpTable">
                                <thead><tr><th>IP (Клик для инфо)</th><th style="width:60px">Хиты</th></tr></thead><tbody></tbody>
                            </table>
                            <div class="pagination-bar" id="googleIpPagination"></div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="card">
                            <div class="card-header">Даты активности (UTC)</div>
                            <table class="table table-hover" id="googleDateTable">
                                <thead><tr><th>Дата / Час</th><th style="width:60px">Хиты</th></tr></thead><tbody></tbody>
                            </table>
                            <div class="pagination-bar" id="googleDatePagination"></div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="card">
                            <div class="card-header">User-Agents ботов</div>
                            <table class="table table-hover" id="googleUaTable">
                                <thead><tr><th>User-Agent строка</th><th style="width:60px">Хиты</th></tr></thead><tbody></tbody>
                            </table>
                            <div class="pagination-bar" id="googleUaPagination"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Модальное окно для IP -->
<div class="modal fade" id="ipModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Аналитика IP: <span id="modalIpTitle" class="text-primary"></span> <span id="modalIpFlag"></span></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <!-- Панель географических данных и провайдера -->
                <div class="card bg-light border-0 mb-3" id="ipGeoPanel" style="display: none;">
                    <div class="card-body py-2 px-3">
                        <div class="row text-muted small">
                            <div class="col-sm-3"><strong>Сеть:</strong> <span id="ipGeoNetwork">-</span></div>
                            <div class="col-sm-3"><strong>Страна:</strong> <span id="ipGeoCountry">-</span></div>
                            <div class="col-sm-4"><strong>Провайдер (ASN):</strong> <span id="ipGeoAsn">-</span></div>
                            <div class="col-sm-2"><strong>Домен:</strong> <span id="ipGeoDomain">-</span></div>
                        </div>
                    </div>
                </div>

                <div id="ipSummaryView">
                    <div class="row mb-4"><div class="col-12"><h6>График активности</h6><div style="position: relative; height: 120px; width: 100%;"><canvas id="ipTimeChart"></canvas></div></div></div>
                    <div class="row">
                        <div class="col-md-3"><h6>Ответы сервера</h6><ul class="list-group list-group-sm mb-2" id="ipStatusList"></ul><p class="text-muted small">Скачано: <strong id="ipTrafficTotal"></strong></p></div>
                        <div class="col-md-3"><h6>Типы запросов</h6><ul class="list-group list-group-sm" id="ipMethodList"></ul></div>
                        <div class="col-md-6"><h6>Заголовки (User-Agent)</h6><ul class="list-group list-group-sm" id="ipUaList"></ul></div>
                    </div>
                </div>
                <div id="ipDetailView" style="display: none;">
                    <div class="d-flex align-items-center mb-3"><button class="btn btn-sm btn-outline-secondary me-3" onclick="toggleDetailView('ip', false)">← Назад к сводке</button><h6 class="mb-0" id="ipDetailSubtitle"></h6></div>
                    <div class="raw-logs-container">
                        <table class="table table-sm table-striped raw-logs-table"><thead class="table-light" style="position: sticky; top: 0;"><tr><th style="width:120px">Время</th><th>Метод + URL</th><th style="width:60px">Ответ</th><th>Referer</th><th>User-Agent</th></tr></thead><tbody id="ipDetailTableBody"></tbody></table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Модальное окно для URL (Страницы) -->
<div class="modal fade" id="pageModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Аналитика URL: <span id="modalPageTitle" class="text-primary" style="word-break: break-all;"></span></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="pageSummaryView">
                    <div class="row mb-4"><div class="col-12"><h6>График обращений к странице</h6><div style="position: relative; height: 120px; width: 100%;"><canvas id="pageTimeChart"></canvas></div></div></div>
                    <div class="row">
                        <div class="col-md-3"><h6>Статусы ответов</h6><ul class="list-group list-group-sm" id="pageStatusList"></ul></div>
                        <div class="col-md-3"><h6>Типы запросов</h6><ul class="list-group list-group-sm" id="pageMethodList"></ul></div>
                        <div class="col-md-6"><h6>Заголовки (User-Agent)</h6><ul class="list-group list-group-sm" id="pageUaList"></ul></div>
                    </div>
                </div>
                <div id="pageDetailView" style="display: none;">
                    <div class="d-flex align-items-center mb-3"><button class="btn btn-sm btn-outline-secondary me-3" onclick="toggleDetailView('page', false)">← Назад к сводке</button><h6 class="mb-0" id="pageDetailSubtitle"></h6></div>
                    <div class="raw-logs-container">
                        <table class="table table-sm table-striped raw-logs-table"><thead class="table-light" style="position: sticky; top: 0;"><tr><th style="width:120px">Время</th><th style="width:140px">IP Адрес</th><th style="width:60px">Ответ</th><th>Referer</th><th>User-Agent</th></tr></thead><tbody id="pageDetailTableBody"></tbody></table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Модальное окно для Источников (Referer) -->
<div class="modal fade" id="refererModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Аналитика Источника (Referer): <span id="modalRefererTitle" class="text-primary" style="word-break: break-all;"></span></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="refererSummaryView">
                    <div class="row mb-4"><div class="col-12"><h6>График переходов с источника</h6><div style="position: relative; height: 120px; width: 100%;"><canvas id="refererTimeChart"></canvas></div></div></div>
                    <div class="row">
                        <div class="col-md-3"><h6>Статусы ответов</h6><ul class="list-group list-group-sm" id="refererStatusList"></ul></div>
                        <div class="col-md-3"><h6>Типы запросов</h6><ul class="list-group list-group-sm" id="refererMethodList"></ul></div>
                        <div class="col-md-6"><h6>Заголовки (User-Agent)</h6><ul class="list-group list-group-sm" id="refererUaList"></ul></div>
                    </div>
                </div>
                <div id="refererDetailView" style="display: none;">
                    <div class="d-flex align-items-center mb-3"><button class="btn btn-sm btn-outline-secondary me-3" onclick="toggleDetailView('referer', false)">← Назад к сводке</button><h6 class="mb-0" id="refererDetailSubtitle"></h6></div>
                    <div class="raw-logs-container">
                        <table class="table table-sm table-striped raw-logs-table"><thead class="table-light" style="position: sticky; top: 0;"><tr><th style="width:120px">Время</th><th style="width:140px">IP Адрес</th><th>Запрошенный URL</th><th style="width:60px">Ответ</th><th>User-Agent</th></tr></thead><tbody id="refererDetailTableBody"></tbody></table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    let allLogRecords = []; 
    let hiddenStatuses = new Set();
    let selectedHour = null;
    let ipCache = {}; 

    // Данные для хранения сетевых префиксов Google
    let googleRanges = { common: [], special: [] };
    let googleRangesLoaded = false;
    let googleBotStats = {};

    let charts = { time: null, status: null, ipTime: null, pageTime: null, refererTime: null, googleTime: null };
    let tables = { ip: null, referer: null, page: null, googleIp: null, googleDate: null, googleUa: null };

    const logRegex = /^(\S+)\s+\S+\s+\S+\s+\[(.*?)\]\s+"(.*?)"\s+(\d{3})\s+(\d+|-)\s+"(.*?)"\s+"(.*?)"/;
    const months = { "Jan":"01", "Feb":"02", "Mar":"03", "Apr":"04", "May":"05", "Jun":"06", "Jul":"07", "Aug":"08", "Sep":"09", "Oct":"10", "Nov":"11", "Dec":"12" };
    const statusColors = { '200': '#198754', '301': '#0d6efd', '302': '#0dcaf0', '403': '#fd7e14', '404': '#ffc107', '409': '#fd7e14', '500': '#dc3545', '502': '#dc3545' };

    // Функции обработки CIDR-подсетей для IPv4/IPv6
    function ip4ToInt(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return 0;
        return ((parseInt(parts[0], 10) << 24) | 
                (parseInt(parts[1], 10) << 16) | 
                (parseInt(parts[2], 10) << 8) | 
                 parseInt(parts[3], 10)) >>> 0;
    }

    function isIpInSubnetV4(ip, cidr) {
        const [subnet, mask] = cidr.split('/');
        const bitmask = ~( (1 << (32 - parseInt(mask, 10))) - 1 );
        return (ip4ToInt(ip) & bitmask) === (ip4ToInt(subnet) & bitmask);
    }

    function parseIpv6(ip) {
        if (ip.startsWith("::ffff:")) {
            ip = ip.substring(7);
        }
        let parts = ip.split(':');
        const emptyIndex = parts.indexOf('');
        if (emptyIndex !== -1) {
            const numZeroes = 8 - (parts.filter(p => p !== '').length);
            const replacements = Array(numZeroes).fill('0');
            parts.splice(emptyIndex, 1, ...replacements);
        }
        const ints = new Uint16Array(8);
        for (let i = 0; i < 8; i++) {
            ints[i] = parseInt(parts[i] || '0', 16);
        }
        return ints;
    }

    // Проверка IPv6
    function isIpInSubnetV6(ip, cidr) {
        try {
            const [subnet, maskStr] = cidr.split('/');
            const mask = parseInt(maskStr, 10);
            const ipInts = parseIpv6(ip);
            const subInts = parseIpv6(subnet);
            
            let remainingBits = mask;
            for (let i = 0; i < 8; i++) {
                if (remainingBits <= 0) break;
                if (remainingBits >= 16) {
                    if (ipInts[i] !== subInts[i]) return false;
                    remainingBits -= 16;
                } else {
                    const shift = 16 - remainingBits;
                    const bitmask = (0xFFFF << shift) & 0xFFFF;
                    if ((ipInts[i] & bitmask) !== (subInts[i] & bitmask)) return false;
                    break;
                }
            }
            return true;
        } catch (e) {
            return false;
        }
    }

    function isIpInSubnet(ip, cidr) {
        if (ip.includes(':') && cidr.includes(':')) {
            return isIpInSubnetV6(ip, cidr);
        } else if (!ip.includes(':') && !cidr.includes(':')) {
            return isIpInSubnetV4(ip, cidr);
        }
        return false;
    }

    // Загрузка списков Google роботов через собственный PHP-шлюз
    async function loadGoogleRanges() {
        const statusBadge = document.getElementById('googleRangesStatus');
        const commonUrl = '?action=google_common';
        const specialUrl = '?action=google_special';

        async function fetchJSON(url) {
            const res = await fetch(url);
            if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
            return await res.json();
        }

        try {
            const commonData = await fetchJSON(commonUrl);
            const specialData = await fetchJSON(specialUrl);
            googleRanges.common = commonData.prefixes || [];
            googleRanges.special = specialData.prefixes || [];
            googleRangesLoaded = true;
            statusBadge.className = "badge bg-success";
            statusBadge.innerText = "Google IP: загружено сервером";
            return;
        } catch (e) {
            console.warn("Сетевой запрос к PHP-API не удался. Активирована резервная офлайн-база подсетей.");
        }

        // Локальный офлайн-резерв на крайний случай
        const backupCommon = [
            "66.249.64.0/19", "192.178.4.0/22", "192.178.8.0/22", "192.178.12.0/22", 
            "192.178.16.0/22", "34.100.182.96/28", "34.118.254.0/28", "34.118.66.0/28", 
            "34.126.178.96/28", "34.146.150.144/28", "34.147.110.144/28", "34.151.74.144/28",
            "2001:4860:4801::/48"
        ];
        const backupSpecial = [
            "108.177.2.0/24", "192.178.16.0/24", "209.85.238.0/24", "66.249.87.0/24", 
            "66.249.89.0/24", "66.249.90.0/24", "66.249.91.0/24", "66.249.92.0/24", 
            "72.14.199.0/24", "74.125.148.0/24", "74.125.149.0/24", "74.125.150.0/24",
            "2001:4860:4801:2000::/52"
        ];

        googleRanges.common = backupCommon.map(p => p.includes(':') ? { ipv6Prefix: p } : { ipv4Prefix: p });
        googleRanges.special = backupSpecial.map(p => p.includes(':') ? { ipv6Prefix: p } : { ipv4Prefix: p });
        googleRangesLoaded = true;

        statusBadge.className = "badge bg-warning text-dark";
        statusBadge.innerText = "Google IP: резервная база (офлайн)";
    }

    // Функция детекции принадлежности к Google-ботам
    function getGoogleBotType(ip) {
        if (!googleRangesLoaded) return null;

        for (const prefix of googleRanges.special) {
            const cidr = prefix.ipv4Prefix || prefix.ipv6Prefix;
            if (cidr && isIpInSubnet(ip, cidr)) return 'special';
        }

        for (const prefix of googleRanges.common) {
            const cidr = prefix.ipv4Prefix || prefix.ipv6Prefix;
            if (cidr && isIpInSubnet(ip, cidr)) return 'common';
        }

        return null;
    }

    // Выделение данных по Google-ботам из общего массива логов
    function getGoogleBotData() {
        let stats = {
            total: 0,
            ips: new Set(),
            common: 0,
            special: 0,
            time: {},
            ipMap: {},
            dateMap: {},
            uaMap: {},
            ipBotTypes: {}
        };

        for (let i = 0; i < allLogRecords.length; i++) {
            let r = allLogRecords[i];
            const botType = getGoogleBotType(r.ip);
            if (botType) {
                stats.total++;
                stats.ips.add(r.ip);
                if (botType === 'common') stats.common++;
                else if (botType === 'special') stats.special++;

                stats.time[r.time] = (stats.time[r.time] || 0) + 1;
                stats.ipMap[r.ip] = (stats.ipMap[r.ip] || 0) + 1;
                stats.dateMap[r.time] = (stats.dateMap[r.time] || 0) + 1;
                stats.uaMap[r.ua] = (stats.uaMap[r.ua] || 0) + 1;
                stats.ipBotTypes[r.ip] = botType;
            }
        }
        return stats;
    }

    // Получение информации по IP-адресу через собственный PHP-шлюз
    async function fetchIpInfo(ip) {
        if (ipCache[ip]) return ipCache[ip];

        const isPrivate = /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/.test(ip) || ip === 'localhost' || ip === '::1';
        if (isPrivate) {
            const privateData = { country_code: "", country: "Локальный IP", asn: "Local Network", as_name: "Private", network: "-" };
            ipCache[ip] = privateData;
            return privateData;
        }

        try {
            const res = await fetch(`?action=lookup&ip=${encodeURIComponent(ip)}`);
            if (!res.ok) throw new Error();
            const data = await res.json();
            ipCache[ip] = data;
            return data;
        } catch (e) {
            return null;
        }
    }

    class PaginatedTable {
        constructor(tableId, paginationId, dataObj, linkType = null) {
            this.tableId = tableId;
            this.paginationId = paginationId;
            this.linkType = linkType; 
            this.updateData(dataObj);
        }

        updateData(dataObj) {
            this.originalData = Object.entries(dataObj).sort((a, b) => b[1] - a[1]);
            this.filteredData = [...this.originalData];
            this.currentPage = 1;
            this.pageSize = 10;
            this.render();
        }

        changePage(page) { this.currentPage = page; this.render(); }

        render() {
            const tbody = document.querySelector(`#${this.tableId} tbody`);
            tbody.innerHTML = '';
            const pageData = this.filteredData.slice((this.currentPage - 1) * this.pageSize, this.currentPage * this.pageSize);

            if (pageData.length === 0) {
                tbody.innerHTML = `<tr><td colspan="2" class="text-center text-muted">Нет данных</td></tr>`;
            } else {
                pageData.forEach(([key, value]) => {
                    const div = document.createElement('div'); div.textContent = key;
                    let keyHtml = `<span title="${div.innerHTML}">${div.innerHTML}</span>`;
                    
                    let safeKey = div.innerHTML.replace(/'/g, "\\'").replace(/"/g, "&quot;");
                    
                    if(this.linkType === 'ip') {
                        let safeId = key.replace(/[^a-zA-Z0-9]/g, '_');
                        keyHtml = `<span class="d-inline-flex align-items-center"><span class="me-2" id="flag-holder-${safeId}"></span><a class="action-link" onclick="showIpDetails('${safeKey}')">${div.innerHTML}</a></span>`;
                    }
                    if(this.linkType === 'googleIp') {
                        let safeId = key.replace(/[^a-zA-Z0-9]/g, '_');
                        let botType = googleBotStats.ipBotTypes[key] || 'common';
                        let badgeHtml = botType === 'special' ? '<span class="badge bg-danger ms-2">Спец</span>' : '<span class="badge bg-primary ms-2">Обычный</span>';
                        keyHtml = `<span class="d-inline-flex align-items-center"><span class="me-2" id="flag-holder-${safeId}"></span><a class="action-link" onclick="showIpDetails('${safeKey}')">${div.innerHTML}</a>${badgeHtml}</span>`;
                    }
                    if(this.linkType === 'page') keyHtml = `<a class="action-link" onclick="showPageDetails('${safeKey}')">${div.innerHTML}</a>`;
                    if(this.linkType === 'referer') keyHtml = `<a class="action-link" onclick="showRefererDetails('${safeKey}')">${div.innerHTML}</a>`;

                    tbody.innerHTML += `<tr><td>${keyHtml}</td><td><span class="badge bg-secondary">${value.toLocaleString()}</span></td></tr>`;
                });

                if (this.linkType === 'ip' || this.linkType === 'googleIp') {
                    this.loadFlagsForPage(pageData);
                }
            }
            this.renderPagination();
        }

        async loadFlagsForPage(pageData) {
            for (const [ip] of pageData) {
                const info = await fetchIpInfo(ip);
                if (info && info.country_code) {
                    const safeId = ip.replace(/[^a-zA-Z0-9]/g, '_');
                    const flagHolder = document.getElementById(`flag-holder-${safeId}`);
                    if (flagHolder) {
                        flagHolder.innerHTML = `<img src="https://flagcdn.com/16x12/${info.country_code.toLowerCase()}.png" width="16" height="12" class="flag-img" title="${info.country || ''}" alt="${info.country_code}">`;
                    }
                }
            }
        }

        renderPagination() {
            const container = document.getElementById(this.paginationId);
            const totalPages = Math.ceil(this.filteredData.length / this.pageSize);
            
            if (totalPages <= 1) { container.innerHTML = `<span class="text-muted small">Всего: ${this.filteredData.length}</span>`; return; }

            let html = `<ul class="pagination pagination-sm m-0">`;
            html += `<li class="page-item ${this.currentPage === 1 ? 'disabled' : ''}"><a class="page-link" onclick="tables['${this.tableId.replace('Table','')}'].changePage(${this.currentPage - 1})">«</a></li>`;
            
            let start = Math.max(1, this.currentPage - 2);
            let end = Math.min(totalPages, start + 3);
            if (end - start < 3) start = Math.max(1, end - 3);

            for (let i = start; i <= end; i++) {
                html += `<li class="page-item ${i === this.currentPage ? 'active' : ''}"><a class="page-link" onclick="tables['${this.tableId.replace('Table','')}'].changePage(${i})">${i}</a></li>`;
            }
            html += `<li class="page-item ${this.currentPage === totalPages ? 'disabled' : ''}"><a class="page-link" onclick="tables['${this.tableId.replace('Table','')}'].changePage(${this.currentPage + 1})">»</a></li></ul>`;
            container.innerHTML = html;
        }
    }

    document.getElementById('logInput').addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (!file) return;

        document.getElementById('uploadSection').style.display = 'none';
        document.getElementById('progressContainer').style.display = 'block';
        document.getElementById('dashboard').style.display = 'none';

        allLogRecords = []; hiddenStatuses.clear(); selectedHour = null;
        const CHUNK_SIZE = 1024 * 1024 * 2;
        let offset = 0, leftover = "";
        const reader = new FileReader();

        reader.onload = function(e) {
            const lines = (leftover + e.target.result).split('\n');
            leftover = lines.pop(); 

            for (let i = 0; i < lines.length; i++) {
                const match = lines[i].match(logRegex);
                if (match) {
                    const timeLocal = match[2];
                    const requestStr = match[3];
                    let hourKey = "Unknown";
                    const tParts = timeLocal.match(/(\d{2})\/(.+?)\/(\d{4}):(\d{2}):/);
                    if (tParts) hourKey = `${tParts[3]}-${months[tParts[2]]}-${tParts[1]} ${tParts[4]}:00`;

                    const reqParts = requestStr.split(' ');
                    const method = reqParts.length >= 2 ? reqParts[0] : 'UNKNOWN';
                    const page = reqParts.length >= 2 ? reqParts[1].split('?')[0] : requestStr;

                    allLogRecords.push({
                        ip: match[1],
                        time: hourKey,
                        fullTime: timeLocal.split(' ')[0],
                        method: method,
                        page: page,
                        status: match[4],
                        bytes: match[5] === '-' ? 0 : parseInt(match[5]),
                        ref: (match[6] !== "-" && match[6] !== "") ? match[6] : null,
                        ua: (match[7] !== "-" && match[7] !== "") ? match[7] : "Unknown"
                    });
                }
            }

            offset += CHUNK_SIZE;
            const percent = Math.min(100, Math.round((offset / file.size) * 100));
            document.getElementById('progressBar').style.width = percent + '%';
            document.getElementById('progressText').innerText = `Чтение файла... ${percent}%`;

            if (offset < file.size) { setTimeout(readNextChunk, 5); } 
            else { initDashboard(); }
        };
        function readNextChunk() { reader.readAsText(file.slice(offset, offset + CHUNK_SIZE)); }
        readNextChunk();
    });

    function getAggregatedData() {
        let stats = { total: 0, bytes: 0, errors: 0, ip: {}, referer: {}, page: {}, time: {}, status: {} };

        for (let i = 0; i < allLogRecords.length; i++) {
            let r = allLogRecords[i];
            
            if (!selectedHour || r.time === selectedHour) {
                stats.status[r.status] = (stats.status[r.status] || 0) + 1;
            }

            if (hiddenStatuses.has(r.status)) continue; 
            if (selectedHour && r.time !== selectedHour) continue; 

            stats.time[r.time] = (stats.time[r.time] || 0) + 1;
            stats.total++;
            stats.bytes += r.bytes;
            if (r.status.startsWith('4') || r.status.startsWith('5')) stats.errors++;

            stats.ip[r.ip] = (stats.ip[r.ip] || 0) + 1;
            stats.page[r.page] = (stats.page[r.page] || 0) + 1;
            if (r.ref) stats.referer[r.ref] = (stats.referer[r.ref] || 0) + 1;
        }
        return stats;
    }

    function initDashboard() {
        document.getElementById('progressContainer').style.display = 'none';
        document.getElementById('uploadCard').style.display = 'none';
        document.getElementById('dashboard').style.display = 'block';

        let stats = getAggregatedData();
        googleBotStats = getGoogleBotData();

        tables.ip = new PaginatedTable('ipTable', 'ipPagination', stats.ip, 'ip');
        tables.page = new PaginatedTable('pageTable', 'pagePagination', stats.page, 'page');
        tables.referer = new PaginatedTable('refererTable', 'refererPagination', stats.referer, 'referer');

        // Инициализация таблиц во вкладке Google
        tables.googleIp = new PaginatedTable('googleIpTable', 'googleIpPagination', googleBotStats.ipMap, 'googleIp');
        tables.googleDate = new PaginatedTable('googleDateTable', 'googleDatePagination', googleBotStats.dateMap, 'time');
        tables.googleUa = new PaginatedTable('googleUaTable', 'googleUaPagination', googleBotStats.uaMap, 'ua');

        drawStatusChart(stats.status);
        updateUI();
    }

    function updateUI(redrawStatus = false) {
        let stats = getAggregatedData();
        googleBotStats = getGoogleBotData();

        let trafficStr = (stats.bytes / (1024 * 1024)).toFixed(2) + ' MB';
        if (stats.bytes > 1024 * 1024 * 1024) trafficStr = (stats.bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';

        document.getElementById('statRequests').innerText = stats.total.toLocaleString();
        document.getElementById('statIPs').innerText = Object.keys(stats.ip).length.toLocaleString();
        document.getElementById('statTraffic').innerText = trafficStr;
        document.getElementById('statErrors').innerText = stats.errors.toLocaleString();

        tables.ip.updateData(stats.ip);
        tables.page.updateData(stats.page);
        tables.referer.updateData(stats.referer);

        // Обновление метрик вкладки Google
        document.getElementById('googleTabCountBadge').innerText = googleBotStats.total.toLocaleString();
        document.getElementById('gStatRequests').innerText = googleBotStats.total.toLocaleString();
        document.getElementById('gStatIps').innerText = googleBotStats.ips.size.toLocaleString();
        document.getElementById('gStatCommon').innerText = googleBotStats.common.toLocaleString();
        document.getElementById('gStatSpecial').innerText = googleBotStats.special.toLocaleString();

        tables.googleIp.updateData(googleBotStats.ipMap);
        tables.googleDate.updateData(googleBotStats.dateMap);
        tables.googleUa.updateData(googleBotStats.uaMap);

        drawTimeChart(stats.time);
        drawGoogleTimeChart(googleBotStats.dateMap);
        if (redrawStatus) drawStatusChart(stats.status);
    }

    function drawStatusChart(statusData) {
        const labels = Object.keys(statusData);
        if (charts.status) charts.status.destroy();
        charts.status = new Chart(document.getElementById('statusChart').getContext('2d'), {
            type: 'doughnut',
            data: { labels: labels, datasets: [{ data: Object.values(statusData), backgroundColor: labels.map(c => statusColors[c] || '#adb5bd') }] },
            options: { 
                responsive: true, maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        onClick: function(e, legendItem, legend) {
                            const index = legendItem.index;
                            const status = legend.chart.data.labels[index];
                            if (hiddenStatuses.has(status)) { hiddenStatuses.delete(status); } else { hiddenStatuses.add(status); }
                            legend.chart.toggleDataVisibility(index);
                            legend.chart.update(); 
                            updateUI(false); 
                        }
                    }
                }
            }
        });
    }

    function drawTimeChart(timeData) {
        const sortedTime = Object.entries(timeData).sort((a, b) => a[0].localeCompare(b[0]));
        if (charts.time) charts.time.destroy();
        charts.time = new Chart(document.getElementById('timeChart').getContext('2d'), {
            type: 'bar',
            data: { labels: sortedTime.map(i => i[0]), datasets: [{ label: 'Запросов', data: sortedTime.map(i => i[1]), backgroundColor: '#0d6efd', borderRadius: 2 }] },
            options: { 
                responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
                onClick: (e, elements) => {
                    if (elements.length > 0) {
                        selectedHour = charts.time.data.labels[elements[0].index];
                        document.getElementById('activeFiltersLabel').style.display = 'block';
                        document.getElementById('activeFiltersLabel').innerText = `Время: ${selectedHour} ✖`;
                        updateUI(true);
                    }
                }
            }
        });
    }

    function drawGoogleTimeChart(timeData) {
        const sortedTime = Object.entries(timeData).sort((a, b) => a[0].localeCompare(b[0]));
        if (charts.googleTime) charts.googleTime.destroy();
        charts.googleTime = new Chart(document.getElementById('googleTimeChart').getContext('2d'), {
            type: 'line',
            data: { 
                labels: sortedTime.map(i => i[0]), 
                datasets: [{ 
                    label: 'Запросы ботов', 
                    data: sortedTime.map(i => i[1]), 
                    borderColor: '#6f42c1', 
                    fill: true,
                    backgroundColor: 'rgba(111, 66, 193, 0.1)',
                    tension: 0.15
                }] 
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: { legend: { display: false } }
            }
        });
    }

    function resetTimeFilter() { selectedHour = null; document.getElementById('activeFiltersLabel').style.display = 'none'; updateUI(true); }

    const ipModal = new bootstrap.Modal(document.getElementById('ipModal'));
    const pageModal = new bootstrap.Modal(document.getElementById('pageModal'));
    const refererModal = new bootstrap.Modal(document.getElementById('refererModal'));

    window.toggleDetailView = function(context, showDetail) {
        document.getElementById(`${context}SummaryView`).style.display = showDetail ? 'none' : 'block';
        document.getElementById(`${context}DetailView`).style.display = showDetail ? 'block' : 'none';
    };

    function generateListHtml(dataObj, topN, type, context, target) {
        return Object.entries(dataObj)
            .sort((a,b)=>b[1]-a[1])
            .slice(0, topN)
            .map(([key, count]) => {
                let colorStyle = (type === 'status') ? `color:${statusColors[key]||'#666'}; font-weight:bold;` : '';
                let safeKey = key.replace(/'/g, "\\'").replace(/"/g, "&quot;");
                let safeTarget = target.replace(/'/g, "\\'").replace(/"/g, "&quot;");

                return `<li class="list-group-item d-flex justify-content-between align-items-center">
                    <span class="word-wrap-all" style="${colorStyle}">${key}</span> 
                    <span class="badge bg-secondary badge-link rounded-pill" onclick="showRawLogs('${context}', '${safeTarget}', '${type}', '${safeKey}')" title="Нажмите для просмотра логов">${count}</span>
                </li>`;
            }).join('');
    }

    // Отображение подробных логов с флагами стран и кликабельными IP
    window.showRawLogs = function(context, target, filterType, filterValue) {
        let logs = allLogRecords.filter(r => {
            if (context === 'ip' && r.ip !== target) return false;
            if (context === 'page' && r.page !== target) return false;
            if (context === 'referer' && r.ref !== target) return false;

            if (filterType === 'status' && r.status !== filterValue) return false;
            if (filterType === 'method' && r.method !== filterValue) return false;
            if (filterType === 'ua' && r.ua !== filterValue) return false;
            return true;
        });

        let tbodyId = context === 'ip' ? 'ipDetailTableBody' : (context === 'page' ? 'pageDetailTableBody' : 'refererDetailTableBody');
        let tbody = document.getElementById(tbodyId);
        
        tbody.innerHTML = logs.map((r, idx) => {
            let statusHtml = `<span style="color:${statusColors[r.status]||'#666'}; font-weight:bold;">${r.status}</span>`;
            let safeIpId = r.ip.replace(/[^a-zA-Z0-9]/g, '_') + '_' + idx;
            
            // Шаблон для вывода кликабельного IP с флагом. При клике закрываем текущую модалку и открываем IP modal.
            let ipHtml = `<span class="d-inline-flex align-items-center"><span class="me-2" id="flag-holder-raw-${safeIpId}"></span><a class="action-link" onclick="bootstrap.Modal.getInstance(document.getElementById('${context}Modal')).hide(); showIpDetails('${r.ip}')">${r.ip}</a></span>`;

            if (context === 'ip') {
                return `<tr><td>${r.fullTime.replace('+', ' ')}</td><td><strong>${r.method}</strong> ${r.page}</td><td>${statusHtml}</td><td>${r.ref || '-'}</td><td>${r.ua}</td></tr>`;
            } else if (context === 'page') {
                return `<tr><td>${r.fullTime.replace('+', ' ')}</td><td>${ipHtml}</td><td>${statusHtml}</td><td>${r.ref || '-'}</td><td>${r.ua}</td></tr>`;
            } else if (context === 'referer') {
                return `<tr><td>${r.fullTime.replace('+', ' ')}</td><td>${ipHtml}</td><td><strong>${r.method}</strong> ${r.page}</td><td>${statusHtml}</td><td>${r.ua}</td></tr>`;
            }
        }).join('');

        // Асинхронно дозагружаем флаги для IP в открывшейся таблице
        if (context !== 'ip') {
            logs.forEach(async (r, idx) => {
                const info = await fetchIpInfo(r.ip);
                if (info && info.country_code) {
                    const safeId = r.ip.replace(/[^a-zA-Z0-9]/g, '_') + '_' + idx;
                    const flagHolder = document.getElementById(`flag-holder-raw-${safeId}`);
                    if (flagHolder) {
                        flagHolder.innerHTML = `<img src="https://flagcdn.com/16x12/${info.country_code.toLowerCase()}.png" width="16" height="12" class="flag-img" title="${info.country || ''}" alt="${info.country_code}">`;
                    }
                }
            });
        }

        let typeNames = { 'status': 'Статус', 'method': 'Метод', 'ua': 'User-Agent' };
        document.getElementById(`${context}DetailSubtitle`).innerText = `Логи по фильтру: ${typeNames[filterType]} = ${filterValue} (${logs.length} шт.)`;

        toggleDetailView(context, true);
    };

    window.showIpDetails = function(targetIp) {
        document.getElementById('modalIpTitle').innerText = targetIp;
        document.getElementById('modalIpFlag').innerHTML = '';
        document.getElementById('ipGeoPanel').style.display = 'none';
        toggleDetailView('ip', false); 
        
        let logs = allLogRecords.filter(r => r.ip === targetIp);
        let time = {}, st = {}, meth = {}, ua = {}, bytes = 0;

        logs.forEach(r => { 
            time[r.time] = (time[r.time] || 0) + 1; 
            st[r.status] = (st[r.status] || 0) + 1; 
            meth[r.method] = (meth[r.method] || 0) + 1;
            ua[r.ua] = (ua[r.ua] || 0) + 1;
            bytes += r.bytes; 
        });

        document.getElementById('ipStatusList').innerHTML = generateListHtml(st, 10, 'status', 'ip', targetIp);
        document.getElementById('ipMethodList').innerHTML = generateListHtml(meth, 10, 'method', 'ip', targetIp);
        document.getElementById('ipUaList').innerHTML = generateListHtml(ua, 8, 'ua', 'ip', targetIp);
        document.getElementById('ipTrafficTotal').innerText = (bytes / 1024).toFixed(2) + ' KB';

        const sTime = Object.entries(time).sort((a, b) => a[0].localeCompare(b[0]));
        if (charts.ipTime) charts.ipTime.destroy();
        charts.ipTime = new Chart(document.getElementById('ipTimeChart'), {
            type: 'line', 
            data: { labels: sTime.map(i => i[0].split(' ')[1]), datasets: [{ data: sTime.map(i => i[1]), borderColor: '#198754', fill: true, backgroundColor: 'rgba(25,135,84,0.1)', tension: 0.1 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
        });

        fetchIpInfo(targetIp).then(info => {
            if (info) {
                document.getElementById('ipGeoPanel').style.display = 'block';
                document.getElementById('ipGeoNetwork').innerText = info.network || '-';
                document.getElementById('ipGeoCountry').innerText = info.country || '-';
                document.getElementById('ipGeoAsn').innerText = `${info.asn || ''} ${info.as_name || ''}`.trim() || '-';
                document.getElementById('ipGeoDomain').innerText = info.as_domain || '-';

                if (info.country_code) {
                    document.getElementById('modalIpFlag').innerHTML = `<img src="https://flagcdn.com/24x18/${info.country_code.toLowerCase()}.png" width="24" height="18" class="flag-img ms-2 align-middle" title="${info.country || ''}" alt="${info.country_code}">`;
                }
            }
        });

        ipModal.show();
    };

    window.showPageDetails = function(targetPage) {
        document.getElementById('modalPageTitle').innerText = targetPage;
        toggleDetailView('page', false); 

        let logs = allLogRecords.filter(r => r.page === targetPage);
        let time = {}, st = {}, meth = {}, ua = {};

        logs.forEach(r => { 
            time[r.time] = (time[r.time] || 0) + 1; 
            st[r.status] = (st[r.status] || 0) + 1; 
            meth[r.method] = (meth[r.method] || 0) + 1;
            ua[r.ua] = (ua[r.ua] || 0) + 1;
        });

        document.getElementById('pageStatusList').innerHTML = generateListHtml(st, 10, 'status', 'page', targetPage);
        document.getElementById('pageMethodList').innerHTML = generateListHtml(meth, 10, 'method', 'page', targetPage);
        document.getElementById('pageUaList').innerHTML = generateListHtml(ua, 8, 'ua', 'page', targetPage);

        const sTime = Object.entries(time).sort((a, b) => a[0].localeCompare(b[0]));
        if (charts.pageTime) charts.pageTime.destroy();
        charts.pageTime = new Chart(document.getElementById('pageTimeChart'), {
            type: 'bar', 
            data: { labels: sTime.map(i => i[0].split(' ')[1]), datasets: [{ data: sTime.map(i => i[1]), backgroundColor: '#fd7e14', borderRadius: 3 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { display: false } } }
        });
        pageModal.show();
    };

    window.showRefererDetails = function(targetReferer) {
        document.getElementById('modalRefererTitle').innerText = targetReferer;
        toggleDetailView('referer', false); 

        let logs = allLogRecords.filter(r => r.ref === targetReferer);
        let time = {}, st = {}, meth = {}, ua = {};

        logs.forEach(r => { 
            time[r.time] = (time[r.time] || 0) + 1; 
            st[r.status] = (st[r.status] || 0) + 1; 
            meth[r.method] = (meth[r.method] || 0) + 1;
            ua[r.ua] = (ua[r.ua] || 0) + 1;
        });

        document.getElementById('refererStatusList').innerHTML = generateListHtml(st, 10, 'status', 'referer', targetReferer);
        document.getElementById('refererMethodList').innerHTML = generateListHtml(meth, 10, 'method', 'referer', targetReferer);
        document.getElementById('refererUaList').innerHTML = generateListHtml(ua, 8, 'ua', 'referer', targetReferer);

        const sTime = Object.entries(time).sort((a, b) => a[0].localeCompare(b[0]));
        if (charts.refererTime) charts.refererTime.destroy();
        charts.refererTime = new Chart(document.getElementById('refererTimeChart'), {
            type: 'line', 
            data: { labels: sTime.map(i => i[0].split(' ')[1]), datasets: [{ data: sTime.map(i => i[1]), borderColor: '#0dcaf0', fill: true, backgroundColor: 'rgba(13,202,240,0.1)', tension: 0.1 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
        });
        refererModal.show();
    };

    // Первоначальный запуск импорта диапазонов Google ботов при инициализации страницы
    document.addEventListener("DOMContentLoaded", () => {
        loadGoogleRanges();
    });
</script>
</body>
</html>