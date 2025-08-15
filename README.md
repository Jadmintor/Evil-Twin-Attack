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
