#include "smartcard_slot.h"

#if defined(CONFIG_KERN_BOARD_P4_PICO) && !defined(SIMULATOR)

#include "../../ui/theme.h"

static lv_obj_t *shown_body = NULL;
static int shown_mark = -1;
static lv_point_precise_t line_a[3];
static lv_point_precise_t line_b[2];

void smartcard_slot_reset(void) {
  shown_body = NULL;
  shown_mark = -1;
}

void smartcard_slot_notes(lv_obj_t *body) {
  smartcard_slot_reset();
  if (!body)
    return;
  lv_obj_set_flex_align(body, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_add_flag(body, LV_OBJ_FLAG_SCROLLABLE);
}

static lv_obj_t *flat(lv_obj_t *parent, int32_t w, int32_t h, int32_t radius,
                      lv_color_t color) {
  lv_obj_t *obj = lv_obj_create(parent);
  lv_obj_remove_style_all(obj);
  lv_obj_clear_flag(obj, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_size(obj, w, h);
  lv_obj_set_style_radius(obj, radius, 0);
  lv_obj_set_style_bg_color(obj, color, 0);
  lv_obj_set_style_bg_opa(obj, LV_OPA_COVER, 0);
  return obj;
}

static void draw_line(lv_obj_t *parent, const lv_point_precise_t *pts,
                      uint32_t n, int32_t size, int32_t thick, lv_color_t color,
                      int32_t x, int32_t y) {
  lv_obj_t *line = lv_line_create(parent);
  lv_obj_remove_style_all(line);
  lv_obj_set_pos(line, x, y);
  lv_obj_set_size(line, size, size);
  lv_line_set_points(line, pts, n);
  lv_obj_set_style_line_width(line, thick, 0);
  lv_obj_set_style_line_color(line, color, 0);
  lv_obj_set_style_line_rounded(line, true, 0);
  lv_obj_set_style_line_opa(line, LV_OPA_COVER, 0);
}

void smartcard_slot_show(lv_obj_t *body, int mark) {
  if (!body)
    return;
  if (shown_body == body && shown_mark == mark &&
      lv_obj_get_child_count(body) > 0)
    return;
  shown_body = body;
  shown_mark = mark;
  lv_obj_clean(body);
  lv_obj_clear_flag(body, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_flex_align(body, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(body, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_update_layout(body);

  int32_t avail_w = lv_obj_get_content_width(body);
  int32_t avail_h = lv_obj_get_content_height(body);
  if (avail_w < 40)
    avail_w = theme_screen_width() - 2 * theme_default_padding();
  if (avail_h < 40)
    avail_h = theme_screen_height() / 2;
  int32_t card_h = avail_h * 88 / 100;
  int32_t card_w = card_h * 3 / 5;
  if (card_w > avail_w * 88 / 100) {
    card_w = avail_w * 88 / 100;
    card_h = card_w * 5 / 3;
  }

  int32_t border = card_w / 22;
  if (border < 8)
    border = 8;
  int32_t radius = card_w / 14;

  lv_obj_t *card = flat(body, card_w, card_h, radius, panel_color());
  lv_obj_set_style_border_color(card, highlight_color(), 0);
  lv_obj_set_style_border_width(card, border, 0);
  lv_obj_add_flag(card, LV_OBJ_FLAG_OVERFLOW_VISIBLE);

  int32_t cols = 3;
  int32_t rows = 2;
  int32_t pad_w = card_w / 16;
  if (pad_w < 8)
    pad_w = 8;
  int32_t pad_h = pad_w * 8 / 5;
  int32_t gap = pad_w / 5;
  if (gap < 2)
    gap = 2;
  int32_t grid_w = cols * pad_w + (cols + 1) * gap;
  int32_t grid_h = rows * pad_h + (rows + 1) * gap;
  int32_t grid_x = (card_w - grid_w) / 2 + card_w / 8;
  if (grid_x + grid_w > card_w - border)
    grid_x = card_w - border - grid_w;
  int32_t grid_y = card_h / 8;
  for (int32_t row = 0; row < rows; row++) {
    for (int32_t col = 0; col < cols; col++) {
      lv_obj_t *pad = flat(card, pad_w, pad_h, gap / 2, highlight_color());
      lv_obj_set_pos(pad, grid_x + gap + col * (pad_w + gap),
                     grid_y + gap + row * (pad_h + gap));
    }
  }

  if (mark == SMARTCARD_SLOT_NONE)
    return;

  int32_t gap_top = card_w / 16;
  int32_t top = grid_y + grid_h + gap_top;
  int32_t room_h = card_h - border - top;
  int32_t room_w = card_w - 2 * border;
  int32_t mark_size = room_w < room_h ? room_w : room_h;
  int32_t thick = mark_size / 6;
  if (thick < 8)
    thick = 8;
  int32_t inset = thick / 2 + thick / 6;
  int32_t mx = (card_w - 2 * border - mark_size) / 2;
  if (mx < 0)
    mx = 0;
  int32_t my = top + (room_h - mark_size) / 2;
  int32_t inner = mark_size - 2 * inset;

  if (mark == SMARTCARD_SLOT_ABSENT) {
    line_a[0] = (lv_point_precise_t){inset, inset};
    line_a[1] = (lv_point_precise_t){mark_size - inset, mark_size - inset};
    line_b[0] = (lv_point_precise_t){mark_size - inset, inset};
    line_b[1] = (lv_point_precise_t){inset, mark_size - inset};
    draw_line(card, line_a, 2, mark_size, thick, error_color(), mx, my);
    draw_line(card, line_b, 2, mark_size, thick, error_color(), mx, my);
    return;
  }

  line_a[0] = (lv_point_precise_t){inset + inner * 4 / 100,
                                   inset + inner * 46 / 100};
  line_a[1] = (lv_point_precise_t){inset + inner * 36 / 100,
                                   inset + inner * 84 / 100};
  line_a[2] = (lv_point_precise_t){inset + inner * 96 / 100,
                                   inset + inner * 6 / 100};
  draw_line(card, line_a, 3, mark_size, thick, good_color(), mx, my);
}

#else

void smartcard_slot_reset(void) {}

void smartcard_slot_notes(lv_obj_t *body) { (void)body; }

void smartcard_slot_show(lv_obj_t *body, int mark) {
  (void)body;
  (void)mark;
}

#endif
