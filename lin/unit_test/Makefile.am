# Srouce Directory
SRCDIR = ../../src/unit_test

INCLUDES = \
  -I../../include \
  -I$(SRCDIR)/_include

LDADD = \
  -lpthread

bin_PROGRAMS = unit_test

unit_test_SOURCES = \
  $(SRCDIR)/_include/gtest/gtest-all.cc \
  $(SRCDIR)/_include/gtest/gtest_main.cc \
  $(SRCDIR)/test-plusaes.cpp

