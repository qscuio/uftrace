# Makefile for uftrace plugins
#
# Automatically discovers and builds all plugin .c files in this directory.
# Each .c file is compiled into a corresponding .so shared library.
#
# Usage:
#   make            - Build all plugins
#   make clean      - Remove all built plugins
#   make install    - Install plugins to system directory
#
# To add a new plugin, simply create a new .c file in this directory.

CC ?= gcc
CFLAGS = -shared -fPIC -rdynamic -Wall -Wextra -O2
LDFLAGS = -ldl -lpthread

# Automatically find all .c files and derive .so names
PLUGIN_SRCS := $(wildcard *.c)
PLUGINS := $(PLUGIN_SRCS:.c=.so)

# Installation directory
PLUGINDIR ?= $(DESTDIR)/usr/lib/uftrace/plugins

.PHONY: all clean install

all: $(PLUGINS)

# Generic rule: compile any .c to .so
%.so: %.c
	@echo "  BUILD    $@"
	@$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	@echo "  CLEAN    plugins"
	@rm -f $(PLUGINS)

install: $(PLUGINS)
	@echo "  INSTALL  plugins -> $(PLUGINDIR)"
	@install -d $(PLUGINDIR)
	@install -m 755 $(PLUGINS) $(PLUGINDIR)/

# List all available plugins
list:
	@echo "Available plugins:"
	@for p in $(PLUGINS); do echo "  $$p"; done

# Show help
help:
	@echo "uftrace plugins Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build all plugins (default)"
	@echo "  clean    - Remove built plugins"
	@echo "  install  - Install to $(PLUGINDIR)"
	@echo "  list     - List available plugins"
	@echo ""
	@echo "Plugins found: $(PLUGINS)"
