## sub directory

AM_CXXFLAGS=-Wall -pedantic -Werror -Wno-long-long

h_sources = EstEidCard.h PCSCManager.h
cc_sources = CardBase.cpp DynamicLibrary.cpp EstEidCard.cpp PCSCManager.cpp SCError.cpp

#Install the headers in a versioned directory - e.g. examplelib-1.0:
library_includedir=$(includedir)/$(GENERIC_LIBRARY_NAME)-$(GENERIC_API_VERSION)/$(GENERIC_LIBRARY_NAME)/cardlib
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir) -I..

noinst_LTLIBRARIES= libcardlib.la
libcardlib_la_SOURCES= $(h_sources) $(cc_sources) 
