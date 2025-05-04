# Smart Medical Box
   
A cloud-connected smart medication reminder system to help patients and medical professionals ensure timely medication.

Conference Published - 2024 IEEE International Women in Engineering (WIE) Conference on Electrical and Computer Engineering (WIECON-ECE)

DOI: 10.1109/WIECON-ECE64149.2024
6-7 Dec. 2024

Paper Link- https://ieeexplore.ieee.org/document/10914895
## Overview

The Smart Medical Box is an IoT device designed to address medication adherence issues, particularly for antibiotics that require strict timing. The system uses hardware components connected to cloud-based services to provide timely medication reminders while ensuring data security.

Key features:
- Automated medication reminders through visual and audio alerts
- User-friendly interface with LCD display and joystick navigation
- Secure cloud-based data storage and management
- Real-time monitoring and accessibility
- Cost-effective solution for medication management

## Hardware Components

- Arduino Mega 2560 R3 (Main controller)
- 16x2 serial LCD module display
- Potentiometer (For LCD contrast adjustment)
- Active speaker buzzer module
- Joystick pin breakout module
- RTC module DS3231 AT24C32 I2C
- Push button switch
- ESP8266 Wi-Fi module

## Setup Instructions

### Hardware Assembly

1. Connect the 16x2 LCD to Arduino Mega using the I2C interface
2. Connect the joystick module to Arduino Mega
3. Connect the RTC module to Arduino Mega via I2C
4. Connect the buzzer module to a digital pin on Arduino Mega
5. Connect the push button to a digital pin on Arduino Mega
6. Connect the ESP8266 Wi-Fi module to Arduino Mega via serial pins

Refer to the wiring diagram in the `/hardware` directory for detailed connections.

### Software Setup

1. Install the Arduino IDE
2. Install required libraries:
   - LiquidCrystal_I2C
   - RTClib
   - ESP8266WiFi
   - ESP8266HTTPClient
   - ArduinoJson
3. Upload the Arduino sketch from `/arduino` directory
4. Set up the cloud server (refer to cloud setup instructions)

### Cloud Server Setup

1. Create a DigitalOcean account
2. Create a droplet with appropriate specifications
3. Set up MySQL database
4. Configure security settings (HTTPS, firewall)
5. Deploy server code from `/server` directory

## Usage

1. Power on the Smart Medical Box
2. Use the joystick to navigate through the menu
3. Add medication schedules by following the on-screen instructions
4. The device will alert when it's time to take medication
5. Acknowledge the alert by pressing the button
6. Monitor medication adherence through the web interface

## Security Features

- Data encryption using AES
- HTTPS-secured communications
- User authentication
- Data integrity checking
- Regular security updates

## Repository Structure

```
smart-medical-box/
├── arduino/            # Arduino code for the device
├── server/             # Server-side code for cloud implementation
├── hardware/           # Hardware schematics and wiring diagrams
├── database/           # Database schema and setup scripts
├── documentation/      # Additional documentation
└── images/             # Project images
```

## Future Enhancements

- Integration of AI for predictive adherence
- Machine learning for personalized medication reminders
- Anomaly detection for unusual medication patterns
- Mobile application for remote monitoring

## Authors

- Afsana Khan
- Masud Mohiuddin
- Prothoma Khan Chowdhury
- Md Mizanur Rahman
- Nazib Abdun Nasir
- Md Tanzim Reza


