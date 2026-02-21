package api

const uiHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>netxfw Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .card { margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2.5rem; font-weight: bold; }
        .navbar-brand { font-weight: bold; color: #0d6efd !important; }
        code { color: #d63384; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark mb-4">
        <div class="container d-flex justify-content-between">
            <a class="navbar-brand" href="#">🛡️ netxfw <small class="text-muted">Management</small></a>
            <div class="d-flex align-items-center">
                <input type="password" id="web-token" class="form-control form-control-sm me-2" placeholder="Auth Token" onchange="saveToken(this.value)" style="width: 150px;">
                <span id="auth-status" class="badge bg-secondary">Unknown Auth</span>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="row">
            <div class="col-md-4">
                <div class="card text-center text-white bg-primary">
                    <div class="card-body">
                        <h5 class="card-title">Pass Count</h5>
                        <p class="stat-value" id="pass-count">0</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center text-white bg-danger">
                    <div class="card-body">
                        <h5 class="card-title">Drop Count</h5>
                        <p class="stat-value" id="drop-count">0</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center text-white bg-success">
                    <div class="card-body">
                        <h5 class="card-title">Conntrack Total</h5>
                        <p class="stat-value" id="ct-count">0</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Control Center</h5>
                        <div class="d-flex align-items-center">
                            <select id="sync-mode" class="form-select form-select-sm me-2" style="width: auto;">
                                <option value="incremental">Incremental</option>
                                <option value="overwrite">Full Overwrite</option>
                            </select>
                            <button class="btn btn-sm btn-outline-primary me-2" onclick="syncRules('file2map')" title="Load rules from local file to BPF Map">📥 Load from File</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="syncRules('map2file')" title="Save current BPF Map rules to local file">💾 Sync to File</button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-12">
                                <div class="input-group">
                                    <span class="input-group-text">🔍 Search Rules</span>
                                    <input type="text" id="rule-search" class="form-control" placeholder="Search IP or CIDR across all tables..." onkeyup="handleSearch(event)">
                                    <button class="btn btn-primary" onclick="refreshRules()">Search</button>
                                </div>
                            </div>
                        </div>
                        <div class="form-check form-switch mb-3">
                            <input class="form-check-input" type="checkbox" id="afxdp-toggle" onchange="toggleConfig('afxdp', this.checked)">
                            <label class="form-check-label" for="afxdp-toggle">Enable AF_XDP Redirection (DPI Path)</label>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="deny-toggle" onchange="toggleConfig('default_deny', this.checked)">
                            <label class="form-check-label" for="deny-toggle">Default Deny Policy</label>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Active Whitelist <small id="whitelist-count" class="text-muted"></small></h5>
                        <button class="btn btn-sm btn-outline-success" onclick="addRulePrompt('whitelist')">+ Add CIDR/Port</button>
                    </div>
                    <div class="card-body p-0">
                        <table class="table table-hover mb-0">
                            <thead>
                                <tr><th>CIDR / Rule</th><th>Port/Info</th><th>Action</th></tr>
                            </thead>
                            <tbody id="whitelist-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">IP + Port Rules <small id="ipport-count" class="text-muted"></small></h5>
                        <button class="btn btn-sm btn-outline-warning" onclick="addRulePrompt('ip_port_rules')">+ Add IP:Port Rule</button>
                    </div>
                    <div class="card-body p-0">
                        <table class="table table-hover mb-0">
                            <thead>
                                <tr><th>IP / CIDR</th><th>Port</th><th>Policy</th><th>Action</th></tr>
                            </thead>
                            <tbody id="ipport-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Top 20 Active Connections <small class="text-muted">(Last Seen)</small></h5>
                    </div>
                    <div class="card-body p-0">
                        <table class="table table-hover mb-0">
                            <thead>
                                <tr>
                                    <th>Source</th>
                                    <th>Destination</th>
                                    <th>Protocol</th>
                                    <th>Last Seen</th>
                                </tr>
                            </thead>
                            <tbody id="conntrack-table">
                                <!-- Conntrack entries injected here -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Active Blacklist <small id="blacklist-count" class="text-muted"></small></h5>
                        <button class="btn btn-sm btn-outline-danger" onclick="addRulePrompt('blacklist')">+ Add CIDR</button>
                    </div>
                    <div class="card-body p-0">
                        <table class="table table-hover mb-0">
                            <thead>
                                <tr><th>CIDR</th><th>Hit Count</th><th>Action</th></tr>
                            </thead>
                            <tbody id="blacklist-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function getAuthHeaders() {
            const token = localStorage.getItem('netxfw_token') || '';
            return {
                'Content-Type': 'application/json',
                'X-NetXFW-Token': token,
                'Authorization': 'Bearer ' + token
            };
        }

        function saveToken(token) {
            localStorage.setItem('netxfw_token', token);
            refreshRules();
            refreshStats();
        }

        function updateAuthStatus(ok) {
            const status = document.getElementById('auth-status');
            if (ok) {
                status.innerText = 'Authenticated';
                status.className = 'badge bg-success';
            } else {
                status.innerText = 'Auth Required / Invalid';
                status.className = 'badge bg-danger';
            }
        }

        function refreshStats() {
            fetch('/api/stats', { headers: getAuthHeaders() }).then(r => {
                updateAuthStatus(r.ok);
                return r.json();
            }).then(data => {
                document.getElementById('pass-count').innerText = data.pass.toLocaleString();
                document.getElementById('drop-count').innerText = data.drop.toLocaleString();
            }).catch(e => console.error('Auth error', e));

            fetch('/api/conntrack', { headers: getAuthHeaders() })
                .then(r => r.json())
                .then(data => {
                    document.getElementById('ct-count').innerText = data.total.toLocaleString();
                    const tbody = document.getElementById('conntrack-table');
                    tbody.innerHTML = '';
                    if (data.top) {
                        data.top.forEach(entry => {
                            const protocol = entry.Protocol === 6 ? 'TCP' : (entry.Protocol === 17 ? 'UDP' : entry.Protocol);
                            const timeStr = new Date(entry.LastSeen).toLocaleTimeString();
                            tbody.innerHTML += '<tr>' +
                                '<td><code>' + entry.SrcIP + ':' + entry.SrcPort + '</code></td>' +
                                '<td><code>' + entry.DstIP + ':' + entry.DstPort + '</code></td>' +
                                '<td><span class="badge bg-secondary">' + protocol + '</span></td>' +
                                '<td>' + timeStr + '</td>' +
                            '</tr>';
                        });
                    }
                });
        }

        function refreshRules() {
            const search = document.getElementById('rule-search').value;
            fetch('/api/rules?search=' + encodeURIComponent(search), { headers: getAuthHeaders() }).then(r => {
                updateAuthStatus(r.ok);
                return r.json();
            }).then(data => {
                const limit = data.limit || 100;

                // Update Blacklist
                const btbody = document.getElementById('blacklist-table');
                btbody.innerHTML = '';
                if (data.blacklist) {
                    for (const [cidr, count] of Object.entries(data.blacklist)) {
                        btbody.innerHTML += '<tr>' +
                                '<td><code>' + cidr + '</code></td>' +
                                '<td>' + count + '</td>' +
                                '<td><button class="btn btn-sm btn-danger" onclick="removeRule(\'blacklist\', \'' + cidr + '\')">Unlock</button></td>' +
                            '</tr>';
                    }
                }
                document.getElementById('blacklist-count').innerText =
                    (data.totalBlacklist > limit ? '(Showing ' + limit + ' of ' + data.totalBlacklist + ')' : '(' + data.totalBlacklist + ')');

                // Update Whitelist
                const wtbody = document.getElementById('whitelist-table');
                wtbody.innerHTML = '';
                if (data.whitelist) {
                    for (const [cidr, port] of Object.entries(data.whitelist)) {
                        let info = port > 1 ? "Port: " + port : "Full Access";
                        wtbody.innerHTML += '<tr>' +
                                '<td><code>' + cidr + '</code></td>' +
                                '<td><span class="badge bg-success">' + info + '</span></td>' +
                                '<td><button class="btn btn-sm btn-outline-danger" onclick="removeRule(\'whitelist\', \'' + cidr + '\')">Remove</button></td>' +
                            '</tr>';
                    }
                }
                document.getElementById('whitelist-count').innerText =
                    (data.totalWhitelist > limit ? '(Showing ' + limit + ' of ' + data.totalWhitelist + ')' : '(' + data.totalWhitelist + ')');

                // Update IP+Port Rules
                const ptbody = document.getElementById('ipport-table');
                ptbody.innerHTML = '';
                if (data.ipPortRules) {
                    for (const [key, action] of Object.entries(data.ipPortRules)) {
                        const lastColon = key.lastIndexOf(':');
                        const ip = key.substring(0, lastColon);
                        const port = key.substring(lastColon + 1);
                        const policy = (action === "allow" || action === 1) ? "ALLOW" : "DENY";
                        const badgeClass = (action === "allow" || action === 1) ? "bg-success" : "bg-danger";

                        ptbody.innerHTML += '<tr>' +
                                '<td><code>' + ip + '</code></td>' +
                                '<td>' + port + '</td>' +
                                '<td><span class="badge ' + badgeClass + '">' + policy + '</span></td>' +
                                '<td><button class="btn btn-sm btn-outline-danger" onclick="removeRule(\'ip_port_rules\', \'' + key + '\')">Remove</button></td>' +
                            '</tr>';
                    }
                }
                document.getElementById('ipport-count').innerText =
                    (data.totalIPPort > limit ? '(Showing ' + limit + ' of ' + data.totalIPPort + ')' : '(' + data.totalIPPort + ')');
            }).catch(e => console.error('Auth error', e));
        }

        function handleSearch(event) {
            if (event.key === 'Enter') {
                refreshRules();
            }
        }

        function toggleConfig(key, value) {
            fetch('/api/config', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({key, value})
            });
        }

        function syncRules(direction) {
            const mode = document.getElementById('sync-mode').value;
            let msg = direction === 'map2file' ? 'Confirm sync BPF Map to local file?' :
                      'Confirm ' + mode + ' sync from local file to BPF Map?';
            if (!confirm(msg)) return;

            fetch('/api/sync', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({direction, mode})
            }).then(r => {
                if (r.ok) {
                    alert('Sync successful!');
                    refreshRules();
                } else {
                    r.text().then(txt => alert('Sync failed: ' + txt));
                }
            });
        }

        function addRulePrompt(type) {
            let promptMsg = "Enter IP or CIDR (e.g. 1.2.3.4 or 1.2.3.0/24):";
            if (type === 'ip_port_rules') {
                promptMsg = "Enter Rule as IP:Port:Action (e.g. 1.2.3.4:80:deny or 1.2.3.4:443:allow):";
            }
            const cidr = prompt(promptMsg);
            if (!cidr) return;

            fetch('/api/rules', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({type, action: 'add', cidr})
            }).then(r => {
                if (r.ok) refreshRules();
                else r.text().then(alert);
            });
        }

        function removeRule(type, cidr) {
            if (!confirm('Are you sure you want to remove this rule?')) return;
            fetch('/api/rules', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({type, action: 'remove', cidr})
            }).then(r => {
                if (r.ok) refreshRules();
                else r.text().then(alert);
            });
        }

        // Init
        document.getElementById('web-token').value = localStorage.getItem('netxfw_token') || '';
        refreshStats();
        refreshRules();
        setInterval(refreshStats, 3000);
    </script>
</body>
</html>
`
