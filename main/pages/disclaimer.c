// Development disclaimer. Accepted in RAM only, so every power-on shows it
// again. A reboot clears the flag. Accepting it once this boot skips it
// until the next one, including after the session lock.

#include "disclaimer.h"
#include "../ui/dialog.h"

#include <stdbool.h>

#define DISCLAIMER_TITLE "This Kern fork version"

#define DISCLAIMER_TEXT                                                        \
  "It is a development build, not a product.\n\n"                              \
  "It has not been audited. Do not use it with real funds.\n\n"                \
  "Testnet is what it is built for. No security guarantees are made."

static disclaimer_done_cb done_callback = NULL;
static bool accepted_this_boot = false;

static void acknowledged_cb(void *user_data) {
  (void)user_data;
  accepted_this_boot = true;
  if (done_callback)
    done_callback();
}

void disclaimer_gate(disclaimer_done_cb done) {
  done_callback = done;
  if (accepted_this_boot) {
    if (done)
      done();
    return;
  }

  dialog_show_acknowledge(DISCLAIMER_TITLE, DISCLAIMER_TEXT, "I understand",
                          acknowledged_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}
