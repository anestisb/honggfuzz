# Interface callback flags. Enable for each implemented method
#
# _HF_FILESPREPARSECALLBACK
#   Pre-parse input corpus
#
# _HF_MANGLERESIZECALLBACK: 
#   Input file resize routine (for dynamic size mangling)
#
# _HF_MANGLECALLBACK:
#   Main content mangling routine
#
# _HF_POSTMANGLECALLBACK:
#   Post mangling routine

EXTENSION_ROOT_DIR := extensions/$(EXTENSION)

EXTENSION_SRCFILES := $(EXTENSION_ROOT_DIR)/dex_extension.c
EXTENSION_CFLAGS   := -D_HF_FILESPREPARSECALLBACK \
                      -D_HF_MANGLECALLBACK \
                      -D_HF_POSTMANGLECALLBACK
EXTENSION_LDFLAGS  := -lz
