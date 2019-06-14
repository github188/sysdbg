LOCAL_PATH := $(call my-dir)
SYSDBG_PATH:=${LOCAL_PATH}

include ${SYSDBG_PATH}/autosubver.mk
$(call autogenerate_modsubversion, ${SYSDBG_PATH}/src/auto_modsubver.h)

#------源文件---------------------------
LIBS_SRC =  $(wildcard $(LOCAL_PATH)/src/*.c)
LIBS_SRC += $(wildcard $(LOCAL_PATH)/src/arch/$(TARGET_ARCH)/*.c)
LIBS_SRC += $(wildcard $(LOCAL_PATH)/src/elf/*.c)
LIBS_SRC += $(filter-out %main.c,$(wildcard $(LOCAL_PATH)/src/tools/*.c))

LIBS_INCLUDES = $(LOCAL_PATH)/include/	\
                $(LOCAL_PATH)/src/ \
                $(LOCAL_PATH)/src/include/      \
                $(LOCAL_PATH)/src/elf/

TOOLS_SRC = src/tools/main.c
TOOLS_INCLUDES = $(LIBS_INCLUDES) \
		$(LOCAL_PATH)/src/tools/

#------编译标志-------------------------
SYSDBG_CFLAGS += -fPIC -funwind-tables
SYSDBG_EXPORT_LDLIBS += -lm -lpthread -ldl -lrt

SYSDBG_PREFIX = $(TARGET_ARCH) 
SYSDBG_RELEASE_PATH = $(LOCAL_PATH)/release/$(SYSDBG_PREFIX)

#------低版本C库兼容标志-------------------------
#true：使用旧版本动态库hash段
HASH_STYLE_Compatibility=
#true:不使用栈保护机制，适用于glibc2.4之前的C库
NO_STACK_PROTECTOR=

ifneq ($(strip $(NO_STACK_PROTECTOR)),)
   SYSDBG_CFLAGS += -fno-stack-protector
endif

#------清理sys-build框架默认没有清理的一些中间文件--------
sysdbg_clean:
	@rm -rf $(SYSDBG_RELEASE_PATH)
	@rm -rf $(LOCAL_PATH)/kernel/*.o $(LOCAL_PATH)/kernel/.*.cmd \
                $(LOCAL_PATH)/kernel/.tmp_versions $(LOCAL_PATH)/kernel/*.ko \
                $(LOCAL_PATH)/kernel/*.mod.c $(LOCAL_PATH)/kernel/modules.order \
                $(LOCAL_PATH)/kernel/Module.symvers
	@rm -rf $(LOCAL_PATH)/out/
 
$(call add-module-clean,,sysdbg_clean)

#---------编译静态库libsysdbg.a---------
include $(CLEAR_VARS)
LOCAL_MODULE := sysdbg-a
LOCAL_MODULE_FILENAME := libsysdbg
LOCAL_SRC_FILES := $(LIBS_SRC)
LOCAL_CFLAGS += $(SYSDBG_CFLAGS)
LOCAL_EXPORT_LDLIBS += $(SYSDBG_EXPORT_LDLIBS)
LOCAL_C_INCLUDES := $(LIBS_INCLUDES)
#默认发布路径，用于单独编译时
LOCAL_RELEASE_PATH := $(SYSDBG_RELEASE_PATH)
#正式发布路径，用于集成编译时
ifneq ($(strip $(TARGET_RELEASE_DIR)),)
LOCAL_RELEASE_PATH += $(TARGET_RELEASE_DIR)/cbb/sysdbg/lib/$(HOST_OS)_$(TARGET_PLATFORM)/$(APP_OPTIM) 
endif
#编译器改变时重新编译
LOCAL_RELATE_MODE := compiler
include $(BUILD_STATIC_LIBRARY)

#---------编译动态库libsysdbg.so---------
include $(CLEAR_VARS)
LOCAL_MODULE := sysdbg-so
LOCAL_MODULE_FILENAME := libsysdbg
LOCAL_SRC_FILES := $(LIBS_SRC)
LOCAL_CFLAGS += $(SYSDBG_CFLAGS)
#编译动态库时，要用LOCAL_LDLIBS来链接其它库
LOCAL_LDLIBS += $(SYSDBG_EXPORT_LDLIBS)
ifneq ($(strip $(HASH_STYLE_Compatibility)),)
LOCAL_LDFLAGS += -Wl,--hash-style=sysv
endif
LOCAL_C_INCLUDES := $(LIBS_INCLUDES)
LOCAL_RELEASE_PATH := $(SYSDBG_RELEASE_PATH)
ifneq ($(strip $(TARGET_RELEASE_DIR)),)
LOCAL_RELEASE_PATH += $(TARGET_RELEASE_DIR)/cbb/sysdbg/lib/$(HOST_OS)_$(TARGET_PLATFORM)/$(APP_OPTIM) 
endif
LOCAL_RELATE_MODE := compiler
include $(BUILD_SHARED_LIBRARY)

#----------发布头文件sysdbg.h-------------
include $(CLEAR_VARS)
LOCAL_MODULE :=sysdbg-release-header
LOCAL_TARGET_TOP := $(LOCAL_PATH)/include
LOCAL_TARGET_COPY_FILES := sysdbg.h
LOCAL_RELEASE_PATH := $(SYSDBG_RELEASE_PATH)
ifneq ($(strip $(TARGET_RELEASE_DIR)),)
LOCAL_RELEASE_PATH += $(TARGET_RELEASE_DIR)/cbb/sysdbg/include
endif
LOCAL_DEPS_MODULES := sysdbg-a sysdbg-so
include $(BUILD_TH3_BINARY)

#---------编译可执行文件sysdbg-------
include $(CLEAR_VARS)
LOCAL_MODULE := sysdbg
LOCAL_SRC_FILES := $(TOOLS_SRC)
LOCAL_STATIC_LIBRARIES := sysdbg-a
LOCAL_CFLAGS += $(SYSDBG_CFLAGS)
LOCAL_EXPORT_LDLIBS += $(SYSDBG_EXPORT_LDLIBS)
LOCAL_C_INCLUDES := $(TOOLS_INCLUDES)
LOCAL_RELEASE_PATH := $(SYSDBG_RELEASE_PATH)
ifneq ($(strip $(TARGET_RELEASE_DIR)),)
LOCAL_RELEASE_PATH += $(TARGET_RELEASE_DIR)/cbb/sysdbg/exe/$(HOST_OS)_$(TARGET_PLATFORM)/$(APP_OPTIM)
endif
LOCAL_RELATE_MODE := compiler
include $(BUILD_EXECUTABLE)

#------编译内核模块----------------
ifndef USE_MISC
  USE_MISC = 0
endif

ifeq ($(USE_MISC),1)
include $(CLEAR_VARS)
KERNEL_PATH :=$(strip $(wildcard $(KERNEL_PATH)))
#编译内核模块时，必须指定内核源码路径
ifndef KERNEL_PATH
$(error "please give us kernel path. eg:KERNEL_PATH=kernel/src")
endif
LOCAL_MODULE := debugmisc
LOCAL_TARGET_TOP := $(LOCAL_PATH)/kernel
$(if $(wildcard $(LOCAL_TARGET_TOP)/Makefile),,$(shell touch $(LOCAL_TARGET_TOP)/Makefile))
objects := $(notdir $(patsubst %.c,%.o,$(wildcard $(LOCAL_TARGET_TOP)/*.c)))
LOCAL_TARGET_CMD := \
            make -C $(KERNEL_PATH) M=$(LOCAL_TARGET_TOP) \
                    CROSS_COMPILE=$(strip $(TOOLCHAIN_ROOT))/$(strip $(TOOLCHAIN_NAME))\
                    ARCH=$(if $(filter ppc,$(TARGET_ARCH)),powerpc,$(TARGET_ARCH))\
		    modules\
		    obj-m=$(objects);\
            rm -v Makefile
LOCAL_TARGET_COPY_FILES := debugmisc.ko
LOCAL_RELEASE_PATH := $(SYSDBG_RELEASE_PATH)
include $(BUILD_TH3_BINARY)
endif


