/*
	iplist - List based packet handler
	Copyright (C) 2009 Serkan Sakar <uljanow@users.sourceforge.net>

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

#ifndef _RANGE_H_
#define _RANGE_H_

#include <tr1/memory>
#include <string>
#include <set>

extern "C" {
#include <linux/types.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
}

#define TARGET	NF_DROP

namespace range {

	struct range {
		std::pair<in_addr_t, in_addr_t> addr;
		int8_t target;
		std::string name;

		range(): target(TARGET) {}
		range(in_addr_t);
		range(in_addr_t, in_addr_t);
		range(in_addr_t, in_addr_t, const std::string&);
		~range() {}

		// assumption: non-overlapping ranges 
		bool operator<(const range&) const;
		bool operator==(const range&) const;
 		bool contains(const range&) const; 
	};

	class range_cmp : public std::binary_function<range, range, bool> {
	public:
	 	bool operator()(const range&, const range&) const;
	}; 

	class range_set : public std::set<range, range_cmp> {
	public:
		uint16_t nfq_num;
		int8_t policy;
		uint32_t policy_mark, 
				 target_mark;

		range_set() {}
		range_set(uint16_t, uint16_t, uint32_t, uint32_t);
		~range_set() {}

		std::pair<iterator, bool> insert(const range&);
	};

	typedef range_set range_set_t;
	typedef std::tr1::shared_ptr<range_set_t> range_set_ptr;
}
#endif // _RANGE_H_
