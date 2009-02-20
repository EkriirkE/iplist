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

#include <stdexcept>
#include <cassert>

#include "range.h"

range::range::range(in_addr_t ip):
	addr(std::make_pair(ip, ip)), target(TARGET)
{}

range::range::range(in_addr_t s, in_addr_t e):
	addr(std::make_pair(s, e)), target(TARGET)
{}

range::range::range(in_addr_t s, in_addr_t e, const std::string& n):
	addr(std::make_pair(s, e)), target(TARGET), name(n)
{}

inline bool range::range::operator<(const range& rhs) const
{ 
	return addr.first < rhs.addr.first; 
} 

inline bool range::range::operator==(const range& rhs) const
{ 
	return contains(rhs) || rhs.contains(*this);
} 

inline bool range::range::contains(const range& rhs) const 
{ 
	return addr.first <= rhs.addr.first && addr.second >= rhs.addr.second; 
} 

// stl_set equal : if (!(range_cmp(lhs,rhs) || range_cmp(rhs,lhs)))
bool range::range_cmp::operator()(const range::range& lhs, const range::range& rhs) const
{ // strict weak ordering
	return (lhs == rhs) ? false : lhs < rhs;
}

range::range_set::range_set(uint16_t n, uint16_t p, uint32_t pm, uint32_t tm):
	nfq_num(n), policy(p), policy_mark(pm), target_mark(tm)
{}

std::pair<range::range_set::iterator, bool> range::range_set::insert(const range& rhs)
{
	iterator i;
	range r = rhs;

	if (r.addr.first > r.addr.second) 
		std::swap(r.addr.first, r.addr.second);

	if ((i = find(r.addr.first)) != end()) {
		if (r.addr.second <= i->addr.second) 
			return make_pair(end(), false);
		r.addr.first = i->addr.second + 1;
	} 
	if ((i = find(r.addr.second)) != end()) { 
	 	if (r.addr.first >= i->addr.first)
			return make_pair(end(), false);
		r.addr.second = i->addr.first - 1;
	}
	std::set<range, range_cmp>::erase(lower_bound(r.addr.first), 
			upper_bound(r.addr.second));
	// unique?
	assert(lower_bound(r.addr.first) == end() || 
			r.addr.second < lower_bound(r.addr.first)->addr.first);

	return std::set<range, range_cmp>::insert(r);
}

