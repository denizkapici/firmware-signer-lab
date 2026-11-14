#ifndef SIGNER_GPIO_H
#define SIGNER_GPIO_H

/* PA0: approval button, internal pull-down, pressed = logic 1.
 * PD12: status LED, push-pull, active high. */
void gpio_init(void);
void led_set(int on);
int button_pressed(void);

#endif
