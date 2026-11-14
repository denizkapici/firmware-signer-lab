#ifndef SIGNER_BOARD_H
#define SIGNER_BOARD_H

/*
 * STM32F407 register map used by the signer firmware.
 * Only the registers the firmware touches are listed; addresses come from
 * RM0090 (STM32F405/407 reference manual).
 */

#include <stdint.h>

#define REG32(address) (*(volatile uint32_t *)(address))

/* Core clock after reset: 16 MHz HSI, no PLL. */
#define SIGNER_CORE_CLOCK_HZ 16000000u

/* RCC */
#define RCC_CSR      REG32(0x40023874u)
#define RCC_AHB1ENR  REG32(0x40023830u)
#define RCC_APB1ENR  REG32(0x40023840u)

#define RCC_AHB1ENR_GPIOAEN (1u << 0)
#define RCC_AHB1ENR_GPIOCEN (1u << 2)
#define RCC_AHB1ENR_GPIODEN (1u << 3)
#define RCC_APB1ENR_UART4EN (1u << 19)

#define RCC_CSR_RMVF    (1u << 24)
#define RCC_CSR_IWDGRST (1u << 29)

/* GPIOA: approval button on PA0 */
#define GPIOA_MODER  REG32(0x40020000u)
#define GPIOA_PUPDR  REG32(0x4002000Cu)
#define GPIOA_IDR    REG32(0x40020010u)

/* GPIOC: UART4 TX/RX on PC10/PC11 */
#define GPIOC_MODER  REG32(0x40020800u)
#define GPIOC_AFRH   REG32(0x40020824u)

/* GPIOD: status LED on PD12 */
#define GPIOD_MODER  REG32(0x40020C00u)
#define GPIOD_OTYPER REG32(0x40020C04u)
#define GPIOD_PUPDR  REG32(0x40020C0Cu)
#define GPIOD_BSRR   REG32(0x40020C18u)

/* UART4 */
#define UART4_SR     REG32(0x40004C00u)
#define UART4_DR     REG32(0x40004C04u)
#define UART4_BRR    REG32(0x40004C08u)
#define UART4_CR1    REG32(0x40004C0Cu)

#define USART_SR_ORE   (1u << 3)
#define USART_SR_RXNE  (1u << 5)
#define USART_SR_TXE   (1u << 7)
#define USART_CR1_RE     (1u << 2)
#define USART_CR1_TE     (1u << 3)
#define USART_CR1_RXNEIE (1u << 5)
#define USART_CR1_UE     (1u << 13)

/* Independent watchdog */
#define IWDG_KR      REG32(0x40003000u)
#define IWDG_PR      REG32(0x40003004u)
#define IWDG_RLR     REG32(0x40003008u)
#define IWDG_SR      REG32(0x4000300Cu)

/* SysTick */
#define SYST_CSR     REG32(0xE000E010u)
#define SYST_RVR     REG32(0xE000E014u)
#define SYST_CVR     REG32(0xE000E018u)

/* NVIC and fault status (System Control Block) */
#define NVIC_ISER(n) REG32(0xE000E100u + 4u * (n))
#define SCB_SHCSR    REG32(0xE000ED24u)
#define SCB_CFSR     REG32(0xE000ED28u)
#define SCB_HFSR     REG32(0xE000ED2Cu)
#define SCB_MMFAR    REG32(0xE000ED34u)
#define SCB_BFAR     REG32(0xE000ED38u)

#define UART4_IRQn 52u

/* Handlers referenced from the vector table in startup.s. */
void SysTick_Handler(void);
void UART4_IRQHandler(void);
void fault_report(const uint32_t *frame) __attribute__((noreturn));

#endif
