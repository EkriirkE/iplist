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

#ifndef _IPLIST_H_
#define _IPLIST_H_

#include <map>
#include <csignal>
#include <limits.h>
#include <unistd.h>

#include <sys/msg.h>

extern "C" {
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
}

#include "range.h"

#define VERSION "0.30"

#define MSGSIZE(msg) (sizeof(msg)-sizeof(long))

#define NFQ_NUM		0
#define POLICY		NF_ACCEPT
#define POLICY_MARK 0
#define TARGET_MARK 0

namespace iplist {
	extern volatile std::sig_atomic_t quit;
	extern int daemon_flag;
	extern int verbose_flag;
	extern int quiet_flag;

	extern void* sighandler_start(void*);

	extern sigset_t mask;
	extern pthread_mutex_t lock;
	extern pthread_cond_t wait;

	extern void parse_cmdline(int, char**);
	
	const size_t MAX_FILE = 32, 
				 FILE_LENGTH = 100;

	enum msg_t {
		JOB = 1,
		PACKET
	};

	enum request_t {
		INSERT,
		DELETE,
		WRITE,
		NONE
	};	

	struct job {
		long mtype;
		request_t req;	

		char file[MAX_FILE][FILE_LENGTH];
		int8_t target[MAX_FILE];
		uint8_t file_count;

		uint16_t nfq_num;
		int8_t policy;
		uint32_t policy_mark,
				 target_mark,
				 range_size,
				 ipcount;
		pthread_t tid;	// worker_th
		pid_t pid;		// pid of sender

		job(); 
		~job() {}

		void add_file(const job&);
		void add_file(const char* file, int8_t target);
		void read_files(range::range_set_t*, bool = false) const;
		std::string to_string() const;
	};
	
	typedef std::tr1::shared_ptr<job> job_ptr;

	class process {
		int pid_fd;
		key_t key;
	public:
		process();
		~process();

		pid_t pid;
		int msqid;
		std::string pid_file;
		std::string fifo;


		void create_msq(key_t);
		void daemonize();

		void write_pid();

		bool lock_file(const std::string&, int, short, off_t = 0, off_t = 0);
		pid_t lock_test(const std::string&, short, off_t = 0, off_t = 0);

	} extern ps;
}
#endif // _IPLIST_H_
