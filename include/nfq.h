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

#ifndef _NFQ_H_
#define _NFQ_H_

#include <iostream>
#include <set>
#include <map>
#include <memory>
#include <csignal>

extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
}

#include "range.h"

namespace nfq {

	class nfq_hook {
		const int BUF_SIZE;
		nfq_handle* h;
		nfq_q_handle* qh;
		nfnl_handle* nh;
		int fd, rv;
		std::auto_ptr<char> buf;
		uint16_t queue_num;

		static void print_pkt(std::string, int8_t, nfq_data*, nfqnl_msg_packet_hdr*);
		static int cb(nfq_q_handle*, nfgenmsg*, nfq_data*, void*);
	public:
		nfq_hook();
		~nfq_hook();

		void init(range::range_set_t*);
		void listen();
	};

	const size_t NAME_SIZE = 50;

	struct packet_msg {
 		long mtype;
		char name[NAME_SIZE];
		timeval tv;
		int8_t hook,
			   target;
		uint16_t src_port, 
				 dst_port;
		in_addr src_ip, 
				dst_ip;
		int len;
		uint32_t mark,
				 id,
				 proto,
				 hw_proto,
				 indev, 
				 physindev, 
				 outdev, 
				 physoutdev;
	};

	extern void* nfq_start(void*);
}
#endif // _NFQ_H_
