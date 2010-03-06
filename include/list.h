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

#ifndef _LIST_H_
#define _LIST_H_

#include <string.h>

#include "range.h"

namespace list {
	extern int strict_ip;

	enum file_t {
		IPL_v1 = 1,
		IPL, 
		DAT, 
		P2P, 
		CSV, 
		ERR 
	}; 

	struct file_fmt {
		const char* reg_exp[2];
		bool number;
		uint8_t match_size, 
				start,		// cols
				end,
				target,		// optional 
				name;		// optional
	};

	void read_fmt(const file_fmt&, std::istream&, range::range_set_t*, int8_t, bool);

	void read_dat(std::istream&, range::range_set_t*, int8_t, bool);
	void read_p2p(std::istream&, range::range_set_t*, int8_t, bool);
	void read_csv(std::istream&, range::range_set_t*, int8_t, bool);
	void read_ipl(std::istream&, range::range_set_t*, int8_t, bool);

	file_t get_file_t(std::istream&) throw();

	extern void read_file(const char*, range::range_set_t*, int8_t, bool);
	extern void write_file(const char*, file_t, const range::range_set_t*);

	void write_ipl(std::ostream&, const range::range_set_t*);
	void write_p2p(std::ostream&, const range::range_set_t*);
	void write_dat(std::ostream&, const range::range_set_t*);

	extern void copy_file(const char*, const char*);

	uint32_t str2ip(const std::string&);
	std::string ip2str(uint32_t);
}
#endif // _LIST_H_
