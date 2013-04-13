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

#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <map>
#include <fstream>
#include <cerrno>
#include <sstream>
#include <cstdlib>
#include <cerrno>
#include <string.h>

#include <regex.h>
#include <getopt.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/types.h> 
#include <sys/stat.h> 

#include "iplist.h"
#include "list.h"
#include "log.h"

volatile std::sig_atomic_t iplist::quit = 0;
int iplist::daemon_flag = 0;
int iplist::verbose_flag = 0;
int iplist::quiet_flag = 0;

sigset_t iplist::mask;
pthread_mutex_t iplist::lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t iplist::wait = PTHREAD_COND_INITIALIZER;

iplist::process iplist::ps;

const char* LISTDIR = "IPLIST_LISTDIR";
const mode_t MODE = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

static std::ostream& print_version(std::ostream& os)
{
	return os << "iplist " << VERSION << 
		"\nCopyright (C) 2010 Serkan Sakar <uljanow@users.sourceforge.net>" 
		<< std::endl;
}

static void print_usage(std::ostream& os, int exit_status)
{
	int width = 35;
 	os.setf(std::ios::left);
	print_version(os) <<
		"\nUsage: \n\n " <<
		"iplist [options] [<file>...]\n " << 
		"iplist --show\n " << 
		"iplist --kill\n " << 
		"iplist --delete --queue-num=<0-65535>\n " << 
		"\nOptions: \n\n" << std::setw(width) << 
		" -p, --policy=accept|drop|repeat" << "default action for packets\n" << std::setw(width) << 
		" -P, --policy-mark=<value[/mask]>" << "mark packets with a non-zero value\n" << std::setw(width) << 
		" -t, --target=accept|drop|repeat" << "target for packets that match rule\n" << std::setw(width) << 
		" -T, --target-mark=<value[/mask]>" << "mark packets with a non-zero value\n\n" << std::setw(width) << 

		" -n, --queue-num=<0-65535>" << "iptables queue number\n" << std::setw(width) << 
		" -i, --insert" << "insert a new queue\n" << std::setw(width) << 
		" -d, --delete" << "delete an existing queue by number\n" << std::setw(width) << 
		" -s, --show" << "show current queues and exit\n\n" << std::setw(width) << 

		"     --stdout" << "log to terminal\n" << std::setw(width) << 
		" -f, --log-file=<file>" << "network traffic related output\n" << std::setw(width) << 
		" -l, --log-level=all|match|none" << "specify network traffic log level \n\n" << std::setw(width) << 

		"     --strict-ip" << "IP-addresses can be in hex, oct and dec\n" << std::setw(width) << 
		" -r, --pid-file=<file>" << "specify PID file location\n" << std::setw(width) << 
		" -o, --output=<file>" << "convert files to another format and exit\n" << std::setw(width) << 
		" -O, --output-fmt=ipl|dat|p2p" << "specify output format\n" << std::setw(width) << 
		" -b, --daemon" << "start as daemon in background\n" << std::setw(width) << 
		" -k, --kill" << "kill running iplist instance and exit\n" << std::setw(width) << 
		" -v, --verbose" << "increase verbosity\n" << std::setw(width) << 
		" -q, --quiet" << "suppress non-error messages\n" << std::setw(width) << 
		" -h, --help" << "display this help and exit\n" << std::setw(width) <<
		" -V, --version" << "output version information and exit\n" << std::setw(width) <<
		"\nSupported file formats are p2p, dat, csv and ipl. Use \"-\" to read from stdin."
		"\nFiles can optionally be compressed with gzip."  << std::endl;
	exit(exit_status);
}

iplist::process::process():
	pid_fd(-1), key(0), pid(0), msqid(0),
	pid_file("/var/run/iplist.pid"), fifo("/tmp/.iplist")
{
	if (mkfifo(fifo.c_str(), S_IRUSR | S_IWUSR) == -1)
		if (errno != EEXIST)
			throw std::runtime_error("can't create fifo");
}

iplist::process::~process()
{
	if (pid) return; 

	if (!lock_test(pid_file, F_WRLCK, 0, 1)) {
		close(pid_fd);
		unlink(pid_file.c_str());
		unlink(fifo.c_str());
		msgctl(msqid, IPC_RMID, NULL);
	}
}

void iplist::process::daemonize()
{
	int fd0, fd1, fd2;
	rlimit rl;

 	umask(0);

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		throw std::runtime_error("can't get file descriptor limit");

	if ((pid = fork()) < 0)
		throw std::runtime_error("can't fork");
	else if (pid)
		exit(EXIT_SUCCESS);

	setsid();

	if (std::signal(SIGHUP, SIG_IGN) == SIG_ERR)
		throw std::runtime_error("can't ignore SIGHUB");

	if ((pid = fork()) < 0)
		throw std::runtime_error("can't fork");
    else if (pid)
		exit(EXIT_SUCCESS);

	if (chdir("/") < 0)
		throw std::runtime_error("can't change directory to /");

	if (rl.rlim_max == RLIM_INFINITY) 
		rl.rlim_max = 1024;
	for (u_int i = 0; i < rl.rlim_max; i++) close(i);

	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);

	if (fd0 != 0 || fd1 != 1 || fd2 != 2)
		throw std::runtime_error("unexpected file descriptors");
}

bool iplist::process::lock_file(const std::string& file, int cmd,
		short l_type, off_t l_start, off_t l_len)
{
	int fd;
	flock fl;
	fl.l_type = l_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = l_start;
	fl.l_len = l_len;

	if ((fd = open(file.c_str(), O_RDWR | O_CREAT, MODE)) == -1)
		throw std::ios_base::failure("can't open " + file);

	if (fcntl(fd, cmd, &fl) == -1) {
		if (errno == EACCES || errno == EAGAIN)
			return false;
		else
			throw std::ios_base::failure("can't lock " + file);
	}

	return true;
}

void iplist::process::write_pid()
{
	std::ostringstream is;
	is << (long)getpid() << "\n";

	if ((pid_fd = open(pid_file.c_str(), O_RDWR | O_CREAT, MODE)) == -1)
		throw std::ios_base::failure("can't open " + pid_file);

	if (ftruncate(pid_fd, 0))
		throw std::ios_base::failure(strerror(errno));

	if (!write(pid_fd, is.str().c_str(), is.str().size())) 
		throw std::ios_base::failure("can't write PID to " + pid_file);
}

pid_t iplist::process::lock_test(const std::string& file, short l_type,
		off_t l_start, off_t l_len)
{
	int fd;
	flock fl;
	fl.l_type = l_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = l_start;
	fl.l_len = l_len;

	if ((fd = open(file.c_str(), O_RDONLY, MODE)) == -1)
		return 0;

    if (fcntl(fd, F_GETLK, &fl) == -1)
		throw std::ios_base::failure("can't get lock of " + file);

    return (fl.l_type == F_UNLCK) ? 0 : fl.l_pid;
}

void iplist::process::create_msq(key_t k)
{
	msqid = msgget((key = k), IPC_CREAT | 0600);
}

void iplist::parse_cmdline(int argc, char** argv)
{ 
	const char* short_opt = "p:P:t:T:n:idsr:f:l:o:O:bkvqhV";	
	const option long_opt[] = {
		{"policy", required_argument, NULL, 'p'},
		{"policy-mark", required_argument, NULL, 'P'},
		{"target", required_argument, NULL, 't'},
		{"target-mark", required_argument, NULL, 'T'},
		{"queue-num", required_argument, NULL, 'n'},
		{"insert", no_argument, NULL, 'i'},
		{"delete", no_argument, NULL, 'd'},
		{"show", no_argument, NULL, 's'},
		{"pid-file", required_argument, NULL, 'r'},
		{"stdout", no_argument, NULL, '1'},
		{"log-file", required_argument, NULL, 'f'},
		{"log-level", required_argument, NULL, 'l'},
		{"strict-ip", no_argument, &list::strict_ip, 1},
		{"output", required_argument, NULL, 'o'},
		{"output-fmt", required_argument, NULL, 'O'},
		{"daemon", no_argument, &iplist::daemon_flag, 1},
		{"kill", no_argument, NULL, 'k'},
		{"verbose", no_argument, &iplist::verbose_flag, 1},
		{"quiet", no_argument, &iplist::quiet_flag, 1},
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'V'},
		{NULL, 0, NULL, 0}
	};
	bool client = false;
	std::pair<std::string, list::file_t> output("", list::IPL);
	int opt;
	int8_t target = -1;
	job_ptr j(new job);
	const size_t BUF_SIZE = 100;
	std::auto_ptr<char> buf(new char[BUF_SIZE]);

	if (!getcwd(buf.get(), BUF_SIZE))
		throw std::runtime_error("can't get working directory");

	std::string wd(buf.get());
	wd += "/";

	while ((opt = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1) {
		switch (opt) {
		case 'p':
			if (!strcasecmp(optarg, "repeat"))
				j->policy = NF_REPEAT;
			else if (!strcasecmp(optarg, "accept"))
				j->policy = NF_ACCEPT;
			else if (!strcasecmp(optarg, "drop"))
				j->policy = NF_DROP;
			else if (!strcasecmp(optarg, "queue"))
				j->policy = NF_QUEUE;
			else
				throw std::invalid_argument("invalid policy argument " 
						+ std::string(optarg));
			break;
		case 'P': 
			strncpy(buf.get(), optarg, BUF_SIZE);
			j->policy_mark = strtoul(strtok(buf.get(), "/"), NULL, 0); 

			if (char* mask = strtok(NULL, "/"))	
				j->policy_mark &= strtoul(mask, NULL, 0); 
			break;
		case 't':
			if (!strcasecmp(optarg, "drop"))
				target = NF_DROP;
			else if (!strcasecmp(optarg, "accept"))
				target = NF_ACCEPT;
			else if (!strcasecmp(optarg, "repeat"))
				target = NF_REPEAT;
			else if (!strcasecmp(optarg, "queue"))
				target = NF_QUEUE;
			else
				throw std::invalid_argument("invalid target argument " 
						+ std::string(optarg));
			break;
		case 'T':
			strncpy(buf.get(), optarg, BUF_SIZE);
			j->target_mark = strtoul(strtok(buf.get(), "/"), NULL, 0); 

			if (char* mask = strtok(NULL, "/"))	
				j->target_mark &= strtoul(mask, NULL, 0); 
			break;
		case 'n':
			j->nfq_num = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			if (!ps.lock_test(ps.pid_file, F_WRLCK, 0, 1)) 
				daemon_flag = 1;
			else
				client = true;
			break;
		case 'd':
			j->req = DELETE;
			client = true;
			break;
		case 's':
			j->req = WRITE;
			client = true;
			j->pid = getpid();
			break;
		case '1':
			log::logfile = "/dev/stdout"; 
			break;
		case 'f':
			log::logfile = (!strncmp(optarg, "/", 1)) ? optarg : wd + optarg; 
			break;
		case 'l':
			if (!strcasecmp(optarg, "none"))
				log::loglevel |= LOG_NONE;
			else if (!strcasecmp(optarg, "match"))
				log::loglevel |= LOG_MATCH;
			else if (!strcasecmp(optarg, "all"))
				log::loglevel |= LOG_ALL;
			else
				throw std::invalid_argument("invalid loglevel argument "
						+ std::string(optarg));
			break;
		case 'o':
			output.first = optarg;
			break;
		case 'O':
			if (!strcasecmp(optarg, "ipl"))
				output.second = list::IPL;
			else if (!strcasecmp(optarg, "dat"))
				output.second = list::DAT;
			else if (!strcasecmp(optarg, "p2p"))
				output.second = list::P2P;
			else
				throw std::invalid_argument("invalid output format "
						+ std::string(optarg));
			break;
		case 'b':
			daemon_flag = 1; 
			break;
		case 'k': 
			if (pid_t pid = ps.lock_test(ps.pid_file, F_WRLCK, 0, 1))
				exit(kill(pid, SIGTERM));

			throw std::runtime_error("no running iplist instance found");
		case 'r':
			ps.pid_file = (!strncmp(optarg, "/", 1)) ? optarg : wd + optarg; 
			break;
		case 'v':
			verbose_flag = 1; 
			break;
		case 'q':
			quiet_flag = 1; 
			break;
		case 'V': 
			print_version(std::cout);
			exit(EXIT_SUCCESS);
		case 0: break;
		case 'h':
			print_usage(std::cout, EXIT_SUCCESS);
		case '?':
		default:
			print_usage(std::cerr, EXIT_FAILURE);
		}
	}
	if (verbose_flag) {
		setlogmask(LOG_UPTO(LOG_DEBUG));
		log::loglevel |= LOG_VERBOSE;
	} else if (quiet_flag) 
		setlogmask(LOG_UPTO(LOG_ERR));

	if (log::logfile.empty()) 
		log::loglevel = LOG_NONE;

	if (!argv[optind] && j->req == INSERT)
		j->req = NONE;

	if (argv[optind]) {
		if (!strncmp(argv[optind], "-", 1))
			if (client) {
				j->pid = getpid();
				j->add_file(ps.fifo.c_str(), target);
			} else
				j->add_file("/dev/stdin", target);
		else {
			std::string listd;
			
			if (char* env = getenv(LISTDIR))
				listd = env + std::string("/");

			for (u_int i = optind; argv[i]; i++) {
				std::string file;
				
				if (!access(argv[i], R_OK))
					file = (!strncmp(argv[i], "/", 1)) ? argv[i] : wd + argv[i];
				else {
					file = listd + argv[i];
					if (access(file.c_str(), R_OK) == -1)
						throw std::runtime_error("can't find " + std::string(argv[i]));
				}
				j->add_file(file.c_str(), target);
			}
		}
		if (!output.first.empty()) {
			range::range_set_ptr rset(new range::range_set_t);
			j->read_files(rset.get());
			list::write_file(output.first.c_str(), output.second, rset.get());
			exit(EXIT_SUCCESS);
		}
	}
	if (client) {
		if (!ps.lock_file(ps.pid_file, F_SETLKW, F_WRLCK, 1, 2))
			throw std::runtime_error("can't lock client range\n");

		if (msgsnd(ps.msqid, j.get(), MSGSIZE(job), 0) == -1)
			throw std::runtime_error("can't send job to msq");

		if (pid_t pid = ps.lock_test(ps.pid_file, F_WRLCK, 0, 1)) {
			if (kill(pid, SIGUSR1) == -1) 
				throw std::runtime_error("can't send signal to iplist\n");
		} else
			throw std::runtime_error("no running iplist instance found");

		if (!ps.lock_file(ps.pid_file, F_SETLK, F_UNLCK, 1, 1))
			throw std::runtime_error("[client] can't unlock request byte\n");

		if (j->req == WRITE)
			list::copy_file(iplist::ps.fifo.c_str(), "/dev/stdout");
		else if (j->req == INSERT && !strncmp(argv[optind], "-", 1))
			list::copy_file("/dev/stdin", iplist::ps.fifo.c_str());

		exit(EXIT_SUCCESS);
	}
	if (msgsnd(ps.msqid, j.get(), MSGSIZE(job), 0) == -1)
		throw std::runtime_error("can't send job to msq");

}

void* iplist::sighandler_start(void*)
{
	int err = EXIT_SUCCESS;
	try {
		int signo;

		for (int ret = 0; !ret;) {
			sigwait(&mask, &signo);

			syslog(LOG_INFO, "info: %s signal caught\n", strsignal(signo));

			pthread_mutex_lock(&lock);
			switch (signo) {
			case SIGINT:
			case SIGQUIT:
			case SIGTERM:
				ret = quit = signo;
			case SIGUSR1:
			case SIGUSR2:
				pthread_cond_signal(&wait);
				break;
			default:
				err++;
			}
			pthread_mutex_unlock(&lock);
		}
		return NULL;

	} catch (const std::exception& e) {
		syslog(LOG_ERR, "thread[%lu]: error: %s\n", pthread_self(), e.what());
		err++;
	}
	exit(err);
}

iplist::job::job():
	mtype(JOB), req(INSERT), file_count(0), nfq_num(NFQ_NUM), 
	policy(POLICY), policy_mark(POLICY_MARK), target_mark(TARGET_MARK),
	range_size(0), ipcount(0), tid(0), pid(0)
{}

void iplist::job::add_file(const char* f, int8_t t) 
{ 
	if (file_count == MAX_FILE) {
		syslog(LOG_WARNING, "warning: too many files, ignoring %s\n", f);
		return;
	}
	strncpy(file[file_count], f, FILE_LENGTH);
	target[file_count++] = t;
}

void iplist::job::add_file(const job& rhs)
{
	for (uint8_t i = 0; i < rhs.file_count; i++)
		this->add_file(rhs.file[i], rhs.target[i]);
}

void iplist::job::read_files(range::range_set_t* rset, bool short_format) const
{
	for (uint8_t i = 0; i < file_count; i++)
		list::read_file(file[i] , rset, target[i], short_format);
}

std::string iplist::job::to_string() const
{
	std::ostringstream os;
	std::map<int8_t, std::string> target_str;

	target_str[-1] = "DEFAULT";
	target_str[NF_DROP] = "DROP";
	target_str[NF_ACCEPT] = "ACCEPT";
	target_str[NF_QUEUE] = "QUEUE";
	target_str[NF_REPEAT] = "REPEAT";

	os << nfq_num << "\t" << target_str[policy] << " (" 
		<< uint32_t(policy_mark) << ")\t" << ipcount << "\t" << range_size << "\t";

	if (file_count > 0)
		os << target_str[target[0]] << " (" << uint32_t(target_mark) 
			<< ")\t" << file[0] << "\n";

	for (uint8_t i = 1; i < file_count; i++)
		os << "\t\t\t\t\t\t" << target_str[target[i]] << " (" 
			<< uint32_t(target_mark) << ")\t" << file[i] << "\n";

	return os.str();
}

