/*
	iplist - List based packet handler
	Copyright (C) 2010 Serkan Sakar <uljanow@users.sourceforge.net>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  
	02110-1301, USA
*/

#ifndef _LOG_H_
#define _LOG_H_

#include <string>

#define LOG_NONE	0x01
#define LOG_MATCH	0x02
#define LOG_ALL		0x04
#define LOG_VERBOSE	0x08

namespace log {
	extern std::string logfile;
	extern uint8_t loglevel;
	
	extern void* logger_start(void*);
}
#endif // _LOG_H_
