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

#include <stdexcept>
#include <cerrno>
#include <cassert>

#include <string.h>
#include <cstdlib>
#include <syslog.h>
#include <fcntl.h>
#include <pthread.h>
#include <bits/local_lim.h>

#include "iplist.h"
#include "nfq.h"
#include "log.h"

static void pthread_terminate(pthread_t tid)
{
	pthread_cancel(tid);
	if (pthread_join(tid, NULL))
		throw std::runtime_error("can't join thread");
}

int main(int argc, char** argv)
{
	int err = EXIT_SUCCESS;
	try {
 		openlog("iplist", LOG_PERROR | LOG_PID, LOG_USER);
		setlogmask(LOG_UPTO(LOG_NOTICE));

		if (geteuid())
			iplist::ps.pid_file = "/tmp/iplist.pid";

		iplist::ps.create_msq(ftok(iplist::ps.fifo.c_str(), 'I'));

		iplist::parse_cmdline(argc, argv);

		if (geteuid())
			throw std::runtime_error("iplist needs to be run as root");

		if (iplist::daemon_flag)
			iplist::ps.daemonize();
		
		if (iplist::ps.lock_file(iplist::ps.pid_file, F_SETLK, F_WRLCK, 0, 1))
			iplist::ps.write_pid();
		else
			throw std::runtime_error("iplist is already running."
					" Try --insert (-i) option.");

		sigset_t oldmask;
		pthread_t tid;
		pthread_attr_t attr;

		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

		sigemptyset(&iplist::mask);
		sigaddset(&iplist::mask, SIGINT);
		sigaddset(&iplist::mask, SIGQUIT);
		sigaddset(&iplist::mask, SIGTERM);
		sigaddset(&iplist::mask, SIGUSR1);
		sigaddset(&iplist::mask, SIGUSR2);

		if (pthread_sigmask(SIG_BLOCK, &iplist::mask, &oldmask))
			throw std::runtime_error("can't block signals");

	 	if (pthread_create(&tid, &attr, iplist::sighandler_start, NULL))
			throw std::runtime_error("can't create sighandler thread");

		pthread_attr_setstacksize(&attr, 1024*1024);

		if (!(log::loglevel & LOG_NONE))
			if (pthread_create(&tid, &attr, log::logger_start, NULL))
				throw std::runtime_error("can't create log thread");

		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

		typedef std::map<uint16_t, range::range_set_ptr> range_map_t;
		typedef std::map<uint16_t, iplist::job_ptr> job_map_t;
		range_map_t range_map;
		job_map_t job_map;

		pthread_mutex_lock(&iplist::lock);
		while (!iplist::quit) {
			if (!iplist::ps.lock_file(iplist::ps.pid_file, F_SETLKW, F_WRLCK, 1, 1))
				throw std::runtime_error("can't lock request byte\n");

			iplist::job_ptr j(new iplist::job);
			if (msgrcv(iplist::ps.msqid, j.get(), MSGSIZE(iplist::job), 
						iplist::JOB, IPC_NOWAIT) == -1) {
				if (errno == ENOMSG)
					j->req = iplist::NONE;
				else
					throw std::runtime_error("can't receive job from msq");
			}

			assert(job_map.size() == range_map.size());

			if (j->pid && j->pid != iplist::ps.lock_test(iplist::ps.pid_file, F_WRLCK, 2, 1)) {
				syslog(LOG_DEBUG, "debug: request from dead client[%lu] received\n", long(j->pid));
				j->req = iplist::request_t(4);
			}
			job_map_t::iterator i;
			switch (j->req) {
			case iplist::INSERT:
				if ((i = job_map.find(j->nfq_num)) == job_map.end()) {
					range::range_set_ptr rset(new range::range_set_t(
								j->nfq_num,
								j->policy,
								j->policy_mark,
								j->target_mark));
					j->read_files(rset.get(), log::loglevel & LOG_NONE);
					j->range_size = rset->size();
					j->ipcount = rset->get_ipcount();
					range_map[j->nfq_num] = rset;
					job_map[j->nfq_num] = j;
				} else {
					pthread_terminate(i->second->tid);

					j->read_files(range_map[j->nfq_num].get(), log::loglevel & LOG_NONE);
					i->second->range_size = range_map[j->nfq_num]->size();
					i->second->add_file(*j);
				}
				if (pthread_create(&tid, &attr, nfq::nfq_start, (void*)&range_map[j->nfq_num]))
					throw std::runtime_error("can't create nfq hook thread");
				job_map[j->nfq_num]->tid = tid;
				break;
			case iplist::DELETE:
				if ((i = job_map.find(j->nfq_num)) != job_map.end()) {
					pthread_terminate(i->second->tid);
					range_map.erase(i->first);
					job_map.erase(i);
				} else
					syslog(LOG_INFO, "info: queue %d does not exist\n", j->nfq_num);
				break;
			case iplist::WRITE: {
				int fd = open(iplist::ps.fifo.c_str(), O_WRONLY);
				if (fd == -1)
					throw std::ios_base::failure("can't open pipe write-only");

				std::string head = (job_map.empty()) ? "No queues inserted\n" : 
						"Queue\tPolicy (mark)\tIP count\tRanges\tTarget (mark)\tFile\n";

				if (write(fd, head.c_str(), head.size()) == -1)
					throw std::ios_base::failure(strerror(errno));
				for (job_map_t::const_iterator i = job_map.begin(); i != job_map.end(); i++) {
					std::string tmp = i->second->to_string();
					if (write(fd, tmp.c_str(), tmp.size()) == -1)
						throw std::ios_base::failure(strerror(errno));
				}
				close(fd);
				break;
			}
			case iplist::NONE:
			default: break;
			}
			if (!iplist::ps.lock_file(iplist::ps.pid_file, F_SETLK, F_UNLCK, 1, 1))
				throw std::runtime_error("[server] can't unlock request byte");
			
			if (j->req == iplist::NONE)
				pthread_cond_wait(&iplist::wait, &iplist::lock);
		}
		pthread_mutex_unlock(&iplist::lock);
		pthread_attr_destroy(&attr);

		if (pthread_sigmask(SIG_SETMASK, &oldmask, NULL))
			throw std::runtime_error("can't reset signal mask");

		for (job_map_t::const_iterator i = job_map.begin(); i != job_map.end(); i++)
			pthread_terminate(i->second->tid);

	} catch (const std::exception& e) {
 		syslog(LOG_ERR, "error: %s\n", e.what());
		err++;
	}
	return err;
}

