idf_component_register(
    SRCS "src/sec1210_frame.c" "src/sec1210.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    PRIV_REQUIRES esp_driver_uart esp_driver_gpio
)
