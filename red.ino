// This software is licensed under the MIT License.
// See the license file for details.
// For more details visit github.com/spacehuhn/DeauthDetector

// include necessary libraries
#include <ESP8266WiFi.h>       // For the WiFi Sniffer
#include <Adafruit_NeoPixel.h> // For the Neopixel/WS2812 LED(s)

// include ESP8266 Non-OS SDK functions
extern "C" {
#include "user_interface.h"
}

// ===== SETTINGS ===== //
#define LED 4              /* LED pin */
#define LED_NUM 1          /* Number of LEDs */
#define BUZZER 5           /* Buzzer pin */
#define SERIAL_BAUD 115200 /* Baudrate for serial communication */
#define CH_TIME 140        /* Scan time (in ms) per channel */
#define PKT_RATE 5         /* Min. packets before it gets recognized as an attack */
#define PKT_TIME 1         /* Min. interval (CH_TIME*CH_RANGE) before it gets recognized as an attack */

// Channels to scan on (US=1-11, EU=1-13, JAP=1-14)
const short channels[] { 1,2,3,4,5,6,7,8,9,10,11,12,13/*,14*/ };

// ===== Runtime variables ===== //
Adafruit_NeoPixel pixels { LED_NUM, LED, NEO_GRB + NEO_KHZ800 }; // Neopixel LEDs
bool song_playing { false };      // If a siren is currently playing
bool attack_active { false };     // Track attack state for LED blinking
int note_index { 0 };             // Index for siren alternation
int note_time { 500 };            // Duration for each siren tone switch
int ch_index { 0 };               // Current index of channel array
int packet_rate { 0 };            // Deauth packet counter (resets with each update)
int attack_counter { 0 };         // Attack counter
unsigned long update_time { 0 };  // Last update time
unsigned long ch_time { 0 };      // Last channel hop time
unsigned long song_time { 0 };    // Last siren update
unsigned long blink_time { 0 };   // Last LED blink time

// ===== Sniffer function ===== //
void sniffer(uint8_t *buf, uint16_t len) {
  if (!buf || len < 28) return; // Drop packets without MAC header

  byte pkt_type = buf[12]; // second half of frame control field

  // If captured packet is a deauthentication or disassociation frame
  if (pkt_type == 0xA0 || pkt_type == 0xC0) {
    ++packet_rate;
  }
}

// ===== Attack detection functions ===== //
void attack_started() {
  song_playing = true;
  attack_active = true;
  note_time = 500; // Set duration for each siren tone switch
  Serial.println("ATTACK DETECTED");
}

void attack_stopped() {
  song_playing = false;
  attack_active = false;
  noTone(BUZZER); // Stop playing sound
  
  for(int i = 0; i < LED_NUM; ++i)
    pixels.setPixelColor(i, pixels.Color(0, 0, 100)); // Green and blue
  pixels.show();

  Serial.println("ATTACK STOPPED");
}

// ===== Setup ===== //
void setup() {
  Serial.begin(SERIAL_BAUD); // Start serial communication

  // Init LEDs
  pixels.begin();
  for(int i = 0; i < LED_NUM; ++i)
    pixels.setPixelColor(i, pixels.Color(0, 0, 100)); // Default to green and blue
  pixels.show();

  pinMode(BUZZER, OUTPUT); // Init buzzer pin

  WiFi.disconnect();                   // Disconnect from any saved or active WiFi connections
  wifi_set_opmode(STATION_MODE);       // Set device to client/station mode
  wifi_set_promiscuous_rx_cb(sniffer); // Set sniffer function
  wifi_set_channel(channels[0]);       // Set channel
  wifi_promiscuous_enable(true);       // Enable sniffer

  Serial.println("Started \o/");
}

// ===== Loop ===== //
void loop() {
  unsigned long current_time = millis(); // Get current time (in ms)

  // Update each second (or scan-time-per-channel * channel-range)
  if (current_time - update_time >= (sizeof(channels) * CH_TIME)) {
    update_time = current_time; // Update time variable

    // When detected deauth packets exceed the minimum allowed number
    if (packet_rate >= PKT_RATE) {
      ++attack_counter; // Increment attack counter
    } else {
      if (attack_counter >= PKT_TIME) attack_stopped();
      attack_counter = 0; // Reset attack counter
    }

    // When attack exceeds minimum allowed time
    if (attack_counter == PKT_TIME) {
      attack_started();
    }

    Serial.print("Packets/s: ");
    Serial.println(packet_rate);

    packet_rate = 0; // Reset packet rate
  }

  // Channel hopping
  if (sizeof(channels) > 1 && current_time - ch_time >= CH_TIME) {
    ch_time = current_time; // Update time variable

    // Get next channel
    ch_index = (ch_index + 1) % (sizeof(channels) / sizeof(channels[0]));
    short ch = channels[ch_index];

    wifi_set_channel(ch); // Set new channel
  }

  // Police siren effect
  if (song_playing && current_time - song_time >= note_time) {
    song_time = current_time;
    
    // Alternate between two frequencies (Police Siren Effect)
    if (note_index % 2 == 0) {
        tone(BUZZER, 440);  // Low siren tone
    } else {
        tone(BUZZER, 880);  // High siren tone
    }

    note_index++; // Toggle siren tone
  }

  // Blinking red LEDs during attack
  if (attack_active && current_time - blink_time >= 500) {
    blink_time = current_time;
    static bool led_on = false;
    
    for(int i = 0; i < LED_NUM; ++i)
      pixels.setPixelColor(i, led_on ? pixels.Color(120, 0, 0) : pixels.Color(0, 0, 0));
    pixels.show();
    
    led_on = !led_on;
  }
}
