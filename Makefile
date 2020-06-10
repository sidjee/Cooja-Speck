CONTIKI_PROJECT = mqtt-sn
all: $(CONTIKI_PROJECT)

CONTIKI = ../..
CONTIKI_SOURCEFILES += ./encrypt_decrypt.c
CFLAGS += -std=c99
include $(CONTIKI)/Makefile.include
