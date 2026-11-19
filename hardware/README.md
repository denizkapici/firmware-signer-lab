# Hardware: signer-board (revision A)

KiCad 10 project in [`signer-board/`](signer-board/). Not manufactured yet.

| Item | Value |
| --- | --- |
| MCU | STM32F407VGT6, LQFP-100, internal 16 MHz HSI (no crystal) |
| Supply | 5 V on J3 → U2 AP2112K-3.3 LDO (EN tied to VIN) → 3.3 V; 1 µF on 5 V |
| Decoupling | nine 100 nF on 3.3 V, plus 1 µF ×3 and 4.7 µF bulk; VCAP1/VCAP2 2.2 µF each |
| Boot | R1 10 kΩ pull-down on BOOT0: boots from flash |
| Reset | NRST with 100 nF to GND (C15) and SW1 to GND; internal pull-up |
| Debug | J1, 5-pin SWD: 1 3V3, 2 SWDIO (PA13), 3 GND, 4 SWCLK (PA14), 5 NRST |
| UART | J2, 3-pin 3.3 V header: 1 PC10 (TX), 2 PC11 (RX), 3 GND |
| Approve button | SW2 from PA0 to 3.3 V, R3 10 kΩ pull-down (pressed = high) |
| Status LED | D1 on PD12 through R2 1 kΩ |
| PCB | 2 layers, 60 × 50 mm, ground zones on both layers |

## Pin map shared with firmware and simulation

| Function | Pin | Firmware | Renode (`simulation/signer.repl`) |
| --- | --- | --- | --- |
| UART TX / RX | PC10 / PC11 | `firmware/uart.c` (UART4, AF8) | `sysbus.uart4` |
| Approve button | PA0 | `firmware/gpio.c` | `gpioPortA.approveButton` |
| Status LED | PD12 | `firmware/gpio.c` | `gpioPortD.statusLed` |

## Exporting fabrication and review files

Run from this directory with KiCad 10's `kicad-cli` (on Windows it is in
`C:\Program Files\KiCad\10.0\bin\`):

```bash
mkdir -p exports/gerber
kicad-cli sch export pdf  -o exports/signer-board-schematic.pdf signer-board/signer-board.kicad_sch
kicad-cli sch export bom  -o exports/signer-board-bom.csv      signer-board/signer-board.kicad_sch
kicad-cli pcb export gerbers -o exports/gerber/                signer-board/signer-board.kicad_pcb
kicad-cli pcb export drill   -o exports/gerber/                signer-board/signer-board.kicad_pcb
kicad-cli pcb render --side top -o exports/signer-board-top.png signer-board/signer-board.kicad_pcb
```

Commit `exports/` so the board can be reviewed without opening KiCad.

## Known gaps (planned for revision B)

- No reverse-polarity or ESD protection on the 5 V input.
- No USB connection; the UART needs an external USB-UART adapter.
- No mounting holes or test points.
- No display, so the user cannot see what is being approved.
