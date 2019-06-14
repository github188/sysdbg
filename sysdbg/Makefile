# TOP Makefile for sysdbg

WORKSPACE := $(shell pwd)
ARCH = no

ifeq ($(ARCH),no)
ARCH = arm
endif

OUTPUT := $(WORKSPACE)/release/$(ARCH)

include ${WORKSPACE}/autosubver.mk
$(call autogenerate_modsubversion, ${WORKSPACE}/src/auto_modsubver.h)

CC = $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar
STRIP := $(CROSS_COMPILE)strip
RM := rm -rf

CFLAGS += -fPIC -funwind-tables
CFLAGS += -lm -lpthread -ldl -lrt
LIBSO_FLAGS += -shared

SYSDBG_TARGET = sysdbg
LIB_TARGET = libsysdbg.a
LIB_SO_TARGET = libsysdbg.so

LIBS_SRC =  $(wildcard $(WORKSPACE)/src/*.c)
LIBS_SRC += $(wildcard $(WORKSPACE)/src/arch/$(ARCH)/*.c)
LIBS_SRC += $(wildcard $(WORKSPACE)/src/elf/*.c)
LIBS_SRC += $(filter-out %main.c,$(wildcard $(WORKSPACE)/src/tools/*.c))

LIBS_INCLUDES = -I $(WORKSPACE)/include \
		-I $(WORKSPACE)/src \
		-I $(WORKSPACE)/src/include \
		-I $(WORKSPACE)/src/elf

TOOLS_SRC = src/tools/main.c
TOOLS_INCLUDES = $(LIBS_INCLUDES) \
		 -I $(WORKSPACE)/src/tools

SYSDBG_OBJS := $(patsubst %.c, %.o, $(TOOLS_SRC))
LIB_OBJS := $(patsubst %.c, %.o, $(LIBS_SRC))

all: $(LIB_SO_TARGET) $(LIB_TARGET) $(SYSDBG_TARGET)

%.o : %.c
	$(CC) $(CFLAGS) $(LIBS_INCLUDES) -c $< -o $@

$(LIB_TARGET) :$(LIB_OBJS)
	$(AR)  cr $(OUTPUT)/$@ $(LIB_OBJS)
	@echo "static library build finish"

$(LIB_SO_TARGET) :$(LIB_OBJS)
	mkdir -p $(OUTPUT)
	$(CC) $(CFLAGS) $(LIBSO_FLAGS) $(LIBS_INCLUDES) -o $(OUTPUT)/$@ $(LIB_OBJS)
	@echo "shared library build finish"

$(SYSDBG_TARGET) :
	$(CC) $(TOOLS_SRC) -o $(OUTPUT)/$(SYSDBG_TARGET) $(CFLAGS) $(TOOLS_INCLUDES) $(OUTPUT)/$(LIB_TARGET)
	@echo "sysdbg build finish"

clean:
	@$(RM) $(SYSDBG_OBJS) $(OUTPUT)/$(SYSDBG_TARGET)
	@$(RM) $(LIB_OBJS) $(OUTPUT)/$(LIB_TARGET) $(OUTPUT)/$(LIB_SO_TARGET)
	@$(RM) $(WORKSPACE)/release
