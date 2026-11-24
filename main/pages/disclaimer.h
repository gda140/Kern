// Development disclaimer, shown on every power-on until accepted this boot.

#ifndef DISCLAIMER_H
#define DISCLAIMER_H

typedef void (*disclaimer_done_cb)(void);

/* Show the disclaimer and run `done` once it is acknowledged. Already
   acknowledged since this power-on: `done` runs straight away. */
void disclaimer_gate(disclaimer_done_cb done);

#endif // DISCLAIMER_H
