#pragma once

#if defined(BOARD_SENSECAP_T1000)
// nRF52840 GPIO mapping (P1.x = 32 + x)
#define PIN_LORA_MISO   (32 + 8)   // P1.08
#define PIN_LORA_MOSI   (32 + 9)   // P1.09
#define PIN_LORA_SCK    (11)       // P0.11
#define PIN_LORA_NSS    (12)       // P0.12
#define PIN_LORA_RST    (32 + 10)  // P1.10
#define PIN_LORA_DIO1   (32 + 1)   // P1.01 (IRQ)
#define PIN_LORA_BUSY   (7)        // P0.07 (DIO2/Busy)
#define PIN_LED         (RADIOLIB_NC)
#else
// Hardware Pin Mapping for Heltec V3
#define PIN_LORA_NSS    8
#define PIN_LORA_DIO1   14
#define PIN_LORA_RST    12
#define PIN_LORA_BUSY   13
#define PIN_LORA_SCK    9
#define PIN_LORA_MISO   11
#define PIN_LORA_MOSI   10
#define PIN_LED         35
#endif
