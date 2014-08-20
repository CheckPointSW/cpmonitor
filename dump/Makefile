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

SRCS = dump.c 
HSRD = dump.h
OBJS = dump.o 

GLIB_FLAG = `pkg-config --cflags glib-2.0`

INC= -I/usr/lib/glib-2.0/include -I/usr/include/glib-2.0 -I../core -I../known -I../printer $(GLIB_FLAG)

CC=gcc
RM=rm
CFLAGS=-g -Wall -c -D_FILE_OFFSET_BITS=64 -D__USE_LARGEFILE

all: $(OBJS)

$(OBJS):	$(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(INC) $(SRCS)

clean:
	@echo "* Cleaning dump folder..."
	$(RM) -f *.o
	
