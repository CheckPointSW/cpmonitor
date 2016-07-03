#   Copyright 2014 Check Point Software Technologies LTD
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#	you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

# Variable definition
BIN_NAME = cpmonitor

COREDIR = core
DUMPDIR = dump
PRINTERDIR = printer
KNOWNDIR = known

SRCS_MAIN = main.c 
OBJS_MAIN = main.o 

GLIB_FLAG = `pkg-config --cflags glib-2.0`

INCLUDES += -I/usr/lib/glib-2.0/include -I/usr/include/glib-2.0 -I$(COREDIR) -I$(DUMPDIR) -I$(PRINTERDIR) -I$(KNOWNDIR) $(GLIB_FLAG)
STDLIBS += -lglib-2.0 -lpcap


SUBDIRS = $(COREDIR) $(PRINTERDIR) $(DUMPDIR) 
ALLOBJS = $(OBJS_MAIN) $(COREDIR)/core.o $(DUMPDIR)/dump.o $(PRINTERDIR)/printer.o $(PRINTERDIR)/known.o $(PRINTERDIR)/tprint.o

CC = gcc
CFLAGS += -g -Werror -Wall
# supporting dump files larger than 4GB
CFLAGS += -D_FILE_OFFSET_BITS=64 -D__USE_LARGEFILE
RM = rm -f


# Default Target
all: makefolder $(BIN_NAME)

makefolder:
	@echo 
	@echo "#######################################" 
	@echo "###       BUILDING ALL TARGETS      ###" 
	@echo "#######################################" 
	@echo 
	for i in $(SUBDIRS) ; do \
	( cd $$i ; make ) ; \
	done
 
$(BIN_NAME):  $(OBJS_MAIN)
	$(CC) $(CFLAGS) $(INCLUDES) $(ALLOBJS) $(STDLIBS) -o $(BIN_NAME) 
 
$(OBJS_MAIN):	$(SRCS_MAIN)
	$(CC) $(CFLAGS) -c $(INCLUDES) $(SRCS_MAIN)
 
clean:
	for i in $(SUBDIRS) ; do \
	( cd $$i ; make clean) ; \
	done
	@echo "* Cleaning main folder..."
	$(RM) *.o
	$(RM) $(BIN_NAME)
 
