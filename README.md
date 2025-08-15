# SentinelCAP - Advanced WiFi Security Testing Tool

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-ESP8266-orange.svg)
![Version](https://img.shields.io/badge/version-2.1.0-green.svg)

## 🛡️ Overview

SentinelCAP is a comprehensive WiFi security testing and penetration testing tool built for ESP8266 microcontrollers. It provides security professionals and researchers with a powerful platform to test WiFi network vulnerabilities through various attack vectors including Evil Twin attacks, deauthentication attacks, and mass SSID spoofing.

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is intended for educational purposes and authorized security testing only. Users are responsible for complying with all applicable laws and regulations. Only use this tool on networks you own or have explicit permission to test. Unauthorized access to computer networks is illegal in many jurisdictions.

## ✨ Key Features

### 🎯 Core Attack Modules
- **Evil Twin Hotspot**: Creates fake access points to capture credentials through captive portals
- **Deauthentication Attack**: Disconnects clients from target networks
- **Mass SSID Spoofing**: Broadcasts multiple fake SSIDs simultaneously
- **WiFi Network Scanner**: Comprehensive scanning and target selection

### 🌐 Captive Portal Management
- **Template Editor**: Built-in HTML editor with syntax highlighting
- **Multiple Templates**: Default, Facebook, Google, Router login pages
- **Template Variables**: Dynamic content with `{SSID}`, `{DEVICE_NAME}`, `{CURRENT_TIME}`
- **Custom Templates**: Upload and manage custom captive portal designs

### 📊 Management & Monitoring
- **Real-time Dashboard**: Live status monitoring and control interface
- **Password Logging**: Automatic capture and storage of credentials
- **File Management**: SPIFFS file system management via web interface
- **System Monitoring**: Memory usage, uptime, and system statistics

### 🔧 Advanced Features
- **OLED Display Support**: Real-time status display on connected OLED screens
- **Settings Management**: Persistent configuration storage
- **Report Generation**: JSON-based penetration testing reports
- **Remote Management**: Complete web-based control interface

## 🔧 Hardware Requirements

### Minimum Requirements
- **ESP8266** microcontroller (NodeMCU, Wemos D1 Mini, etc.)
- **4MB Flash Memory** minimum
- **Power Supply** (USB or external 3.3V)

### Optional Hardware
- **OLED Display** (128x64, I2C) for status monitoring
- **External Antenna** for improved range
- **Battery Pack** for portable operations

### Recommended Setup
ESP8266 NodeMCU v1.0

CPU: 80MHz (160MHz boost available)
Flash: 4MB
RAM: 80KB
WiFi: 802.11 b/g/n

Run
Copy code

## 📦 Installation

### Prerequisites
- Arduino IDE (1.8.0 or later)
- ESP8266 Board Package
- Required Libraries (see below)

### Required Libraries
// Install via Arduino Library Manager
ESP8266WiFi
DNSServer
ESP8266WebServer
ArduinoJson (v6.x)
Adafruit GFX Library
Adafruit SSD1306 (if using OLED)
Installation Steps
Clone the Repository


git clone https://github.com/yourusername/SentinelCAP.git
cd SentinelCAP
Install Arduino IDE and ESP8266 Package

Download Arduino IDE from arduino.cc
Add ESP8266 board URL: http://arduino.esp8266.com/stable/package_esp8266com_index.json
Install ESP8266 package via Board Manager
Install Required Libraries

Open Arduino IDE
Go to Sketch → Include Library → Manage Libraries
Install all required libraries listed above
Configure and Upload


// In SentinelCAP.ino, configure your settings:
#define DEFAULT_AP_SSID "SentinelCAP"
...
Upload to ESP8266

Select your ESP8266 board and port
Upload the sketch
🚀 Usage Guide
Initial Setup
Connect to SentinelCAP Network

SSID: SentinelCAP (or your configured SSID)
Password: 12345678 (default)
Access Web Interface

Open browser and navigate to: http://192.168.4.1
Default dashboard loads automatically
Basic Operations
WiFi Scanning
javascript
5 lines
Click to expand
// Scan for available networks
1. Navigate to "WiFi Scanner" tab
...
Evil Twin Attack
javascript
5 lines
Click to expand
// Setup and launch Evil Twin
1. Select target network from scanner
...
Deauthentication Attack
javascript
5 lines
Click to expand
// Disconnect clients from target network
1. Ensure target network is selected
...
Mass SSID Spoofing
javascript
5 lines
Click to expand
// Broadcast multiple fake SSIDs
1. Navigate to "Mass Spoofing" section
...
Advanced Configuration
Custom Captive Portal Templates
html
18 lines
Click to expand
<!-- Template variables available -->
{SSID} - Target network name
...
Settings Configuration
json
8 lines
Click to expand
{
"device_name": "SentinelCAP",
...
📊 API Reference
REST Endpoints
Network Management
http

Run
Copy code
GET /api/scan          # Scan for WiFi networks
GET /api/status        # Get device status
POST /api/select       # Select target network
Attack Control
http

Run
Copy code
POST /api/start-evil-twin    # Start Evil Twin attack
POST /api/stop-evil-twin     # Stop Evil Twin attack
POST /api/start-deauth       # Start deauth attack
POST /api/stop-deauth        # Stop deauth attack
POST /api/start-mass-spoof   # Start mass SSID spoofing
POST /api/stop-mass-spoof    # Stop mass SSID spoofing
Data Management
http

Run
Copy code
GET /api/passwords     # Get captured passwords
DELETE /api/passwords  # Clear password logs
GET /api/files         # List SPIFFS files
POST /api/upload       # Upload file to device
DELETE /api/files/{filename}  # Delete file
