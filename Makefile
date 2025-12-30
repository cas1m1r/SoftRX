CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
LDFLAGS ?=

# Prefer pkg-config if available so builds work across distros.
SECCOMP_CFLAGS := $(shell pkg-config --cflags libseccomp 2>/dev/null)
SECCOMP_LIBS   := $(shell pkg-config --libs libseccomp 2>/dev/null)

ifeq ($(strip $(SECCOMP_LIBS)),)
  # Fallback: assumes default include/lib paths.
  SECCOMP_CFLAGS :=
  SECCOMP_LIBS   := -lseccomp
endif

BIN_DIR := bin
CORE_DIR := core

LAUNCHER := $(BIN_DIR)/softrx_launcher

all: $(LAUNCHER)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(LAUNCHER): $(CORE_DIR)/softrx_launcher.c | $(BIN_DIR)
	@echo "[build] If this fails with 'seccomp.h: No such file', install libseccomp development headers."
	$(CC) $(CFLAGS) $(SECCOMP_CFLAGS) -o $@ $< $(SECCOMP_LIBS) -lpthread $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR) *.o softrx_out

.PHONY: all clean
