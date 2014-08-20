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

SRCS_KNOWS = known.c 
HDRS_KNOWS = known.h
OBJS_KNOWN = known.o

SRCS_TPRINT = tprint.c 
HDRS_TPRINT = tprint.h 
OBJS_TPRINT = tprint.o

SRCS_PRINTER = printer.c 
HDRS_PRINTER = printer.h 
OBJS_PRINTER = printer.o

GLIB_FLAG = `pkg-config --cflags glib-2.0`

OBJS = $(OBJS_KNOWN) $(OBJS_TPRINT) $(OBJS_PRINTER)

INCLUDES += -I../CMpub/lib/libcore.a -I/usr/lib/glib-2.0/include -I/usr/include/glib-2.0 -I../core/ -I../known $(GLIB_FLAG)

CC = gcc
CFLAGS = -g -Wall -c -D_FILE_OFFSET_BITS=64 -D__USE_LARGEFILE
RM=rm

# Default Target
all: $(OBJS)

$(OBJS_KNOWN):	$(SRCS_KNOWS) $(HDRS_KNOWS)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS_KNOWS)

$(OBJS_TPRINT):	$(SRCS_TPRINT) $(HDRS_TPRINT)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS_TPRINT)
	
$(OBJS_PRINTER):	$(SRCS_PRINTER) $(HDRS_PRINTER)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS_PRINTER)
	
	
clean: 
	@echo "* Cleaning printer folder..." 
	$(RM) -f *.o