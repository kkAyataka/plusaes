# Srouce Directory
ROOTDIR = ../../unit_test
SRCDIR = $(ROOTDIR)/src

INCLUDES = \
  -I../../include \
  -I$(ROOTDIR)/lib/include

LDADD = \
  -lpthread

bin_PROGRAMS = unit_test

unit_test_SOURCES = \
  $(ROOTDIR)/lib/include/gtest/gtest-all.cc \
  $(ROOTDIR)/lib/include/gtest/gtest_main.cc \
  $(SRCDIR)/test-plusaes.cpp

