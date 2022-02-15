set(SOURCES bmp280.c)

idf_component_register(SRCS ${SOURCES}
                        INCLUDE_DIRS . 
                        REQUIRES log freertos esp_idf_lib_helpers I2Cdev)