# Srouce Directory
ROOTDIR = ../../unit_test
SRCDIR = $(ROOTDIR)/src

INCLUDES = \
  -I../../include \
  -I../include/gtest-1.8.1

LDADD = \
  -lpthread

bin_PROGRAMS = unit_test

unit_test_SOURCES = \
  ../include/gtest-1.8.1/gtest/gtest-all.cc \
  $(SRCDIR)/main.cpp \
  $(SRCDIR)/test-plusaes.cpp \
  $(SRCDIR)/test-inc.cpp
