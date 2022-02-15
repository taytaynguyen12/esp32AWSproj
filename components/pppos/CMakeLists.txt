set(SOURCES libGSM.c)

idf_component_register(SRCS ${SOURCES}
                        INCLUDE_DIRS . 
                        REQUIRES)