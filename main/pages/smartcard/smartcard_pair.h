#ifndef SMARTCARD_PAIR_H
#define SMARTCARD_PAIR_H

/* Call once a Seedkeeper session is open. A paired card goes straight on to
 * next(). Otherwise the card ID is shown: pairing runs next(), anything else
 * runs refused(). Nothing is sent to the card on the way. */
void smartcard_pair_gate(void (*next)(void), void (*refused)(void));

/* Drop the callbacks of a gate still on screen. */
void smartcard_pair_cancel(void);

#endif
