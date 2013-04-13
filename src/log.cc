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

#include <algorithm>
#include <stdexcept>
#include <iomanip>
#include <fstream>
#include <map>
#include <string.h>

#include <syslog.h>

extern "C" {
#include <arpa/inet.h>
#include <netdb.h>
}

#include "log.h"
#include "nfq.h"
#include "iplist.h"

std::string log::logfile;
uint8_t log::loglevel = 0;

void* ::log::logger_start(void*)
{
	try {
		std::ofstream os(logfile.c_str(), std::ios::app);

		if (!os)
			throw std::ios_base::failure("can't open " + logfile);

		syslog(LOG_INFO, "thread[%lu]: info: logging to %s\n", pthread_self(), 
				logfile.c_str());

		os.setf(std::ios::left);

		std::map<int8_t, std::string> chain, target;
		std::map<std::string, u_long> hits;

		chain[NF_IP_PRE_ROUTING]	= " PREROUTING:";
		chain[NF_IP_LOCAL_IN]		= " INPUT:";
		chain[NF_IP_LOCAL_OUT]		= " OUTPUT:";
		chain[NF_IP_POST_ROUTING]	= " POSTROUTING:";
		chain[NF_IP_FORWARD]		= " FORWARD:";

		target[NF_DROP]		= " Target=DROP";
		target[NF_ACCEPT]	= " Target=ACCEPT";
		target[NF_QUEUE]	= " Target=QUEUE";
		target[NF_REPEAT]	= " Target=REPEAT";

		while (1) {
			nfq::packet_msg pkt;
			char time_string[20];
	
			if (msgrcv(iplist::ps.msqid, &pkt, MSGSIZE(nfq::packet_msg), 
						iplist::PACKET, 0) == -1)
				continue;

			strftime(time_string, sizeof(time_string), "%T", localtime(&pkt.tv.tv_sec));

			os << time_string;

			if (log::loglevel & LOG_VERBOSE)
				os << "." << std::setw(6) << std::setfill('0') << pkt.tv.tv_usec;

			os << chain[pkt.hook];

			if (strncmp(pkt.name, "", 1))
				os << pkt.name << " Hits=" << ++hits[pkt.name];

			os << target[pkt.target];

			protoent* proto = getprotobynumber(pkt.proto);

			// inet_ntoa returns static buffer
			if (pkt.proto == IPPROTO_TCP || pkt.proto == IPPROTO_UDP) {
				os << " SRC=" << inet_ntoa(pkt.src_ip) << ":" << pkt.src_port;
				os << " DST=" << inet_ntoa(pkt.dst_ip) << ":" << pkt.dst_port;
			} else {
				os << " SRC=" << inet_ntoa(pkt.src_ip);
				os << " DST=" << inet_ntoa(pkt.dst_ip);
			}
			std::transform(proto->p_name, proto->p_name + strlen(proto->p_name),
					proto->p_name, (int(*)(int))toupper);
			os << " Proto=" << proto->p_name;

			if (log::loglevel & LOG_VERBOSE) { 
				os	<< " HW_PROTO=0x" << pkt.hw_proto 
					<< " LEN=" << pkt.len 
					<< " ID=" << pkt.id;
				if (pkt.mark) os << " MARK=" << pkt.mark;
				if (pkt.indev) os << " INDEV=" << pkt.indev;
				if (pkt.physindev) os << " PHYS_INDEV=" << pkt.physindev;
				if (pkt.outdev) os << " OUTDEV=" << pkt.outdev;
				if (pkt.physoutdev) os << " PHYS_OUTDEV=" << pkt.physoutdev;
			}
			os << std::endl;
		}
	} catch (const std::exception& e) {
		syslog(LOG_ERR, "thread[%lu]: error: %s\n", pthread_self(), e.what());
	}
	return NULL;
}

