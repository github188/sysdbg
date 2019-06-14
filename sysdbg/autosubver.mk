current_makefile := $(lastword $(MAKEFILE_LIST))
current_make_path := $(patsubst %/,%,$(dir $(current_makefile:%/=%)))

#ifneq ($(wildcard ../.git),)
MODULE_SUBVERSION := $(shell cd $(current_make_path) && git log -1 2> /dev/null | head -n 1 | awk ' {print $$2 } ' | cut -b -8)
#endif

ifeq ($(MODULE_SUBVERSION),)
MODULE_SUBVERSION := AA5555AA
endif

# module_auto_subversion_gen = $(shell echo "Do nothing..")
autogenerate_modsubversion = $(shell echo "/**" > $(1) ; \
	echo " * Kedacom module subversion defines." >> $(1) ; \
	echo " * Automatically generated file, DO NOT EDIT." >> $(1) ; \
	echo " * Don't push it to repository." >> $(1) ;	\
	echo " *" >> $(1) ;	\
	echo " */" >> $(1) ;	\
	echo "\#define MODULE_SUBVERSION $(MODULE_SUBVERSION)" >> $(1))
