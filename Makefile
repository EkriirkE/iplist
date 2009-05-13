#
#	iplist - List based packet handler
#	Copyright (C) 2009 Serkan Sakar <uljanow@users.sourceforge.net>
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; either version 2 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  
#	02110-1301, USA
#

CPP = g++
FLAGS= -Wall -Wextra -std=c++98 -D_REENTRANT
#CPPFLAGS = ${FLAGS} -g -DDEBUG
#CPPFLAGS = ${FLAGS} -g -pg -DDEBUG
CPPFLAGS = -O2 ${FLAGS} -DNDEBUG

HEADERDIR = include
SRCDIR = src
INCLUDE = -I $(HEADERDIR)
SOURCES = list.cc main.cc nfq.cc iplist.cc log.cc range.cc
OBJECTS = $(SOURCES:.cc=.o)
VPATH = $(SRCDIR) $(HEADERDIR)
vpath %.cc $(SRCDIR)
vpath %.h $(HEADERDIR)

LIBS = -lnetfilter_queue -lnfnetlink -lpthread -lz
FILENAME := iplist

all: $(FILENAME)

$(FILENAME): $(OBJECTS)
	$(CPP) $(CPPFLAGS) $(INCLUDE) $(OBJECTS) $(LIBS) -o $(FILENAME)
	strip $@

%.o: %.cc
	$(CPP) $(CPPFLAGS) $(INCLUDE) -c $<

list.o: list.h range.h
main.o: iplist.h range.h nfq.h log.h
nfq.o: nfq.h range.h log.h iplist.h
iplist.o: iplist.h range.h list.h log.h
range.o: range.h
log.o: log.h nfq.h range.h iplist.h

install:
	install -D -p -m 755 $(FILENAME) $(DESTDIR)/usr/sbin/${FILENAME}
	install -D -p -m 755 ipblock $(DESTDIR)/usr/sbin/ipblock
	install -D -p -m 644 ipblockUI.jar $(DESTDIR)/usr/share/java/ipblockUI.jar

deb:
	dpkg-buildpackage -rfakeroot -tc -D -us -uc

tags:
	ctags -R .

clean:
	rm -f ${OBJECTS} ${FILENAME} core* tags

.PHONY: all clean install tags deb

