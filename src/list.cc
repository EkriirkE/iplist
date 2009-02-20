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

#include <string>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <cassert>
#include <algorithm>
#include <cerrno>
#include <tr1/unordered_map>

#include <syslog.h>
#include <regex.h>
#include <zlib.h>
#include <fcntl.h>

extern "C" {
#include <arpa/inet.h>
}
#include "list.h"

#define REG_SIZE(match) ((match.rm_eo)-(match.rm_so))

const size_t BUF_SIZE = 8192,
			 MAX_MATCH_SIZE = 6;

int list::strict_ip = 0;

const list::file_fmt dat_file = {
	{"^([0-9.]+)[-|,]([0-9.]+)[,]([0-9]+)[,](.*)$", 
		"^([a-fA-F0-9xX.]+)[-|,]([a-fA-F0-9xX.]+)[,]([0-9]+)[,](.*)$"},
	false, 5, 1, 2, 3, 4
};

const list::file_fmt p2p_file = {
	{"^(.*)[:]([0-9.]+)[-]([0-9.]+)$",
		"^(.*)[:]([a-fA-F0-9xX.]+)[-]([a-fA-F0-9xX.]+)$"},
	false, 4, 2, 3, 0, 1
};

const list::file_fmt csv_file = {
	{"^\"([0-9]+)\"[,]\"([0-9]+)\"[,]\"(.*)\"[,]\"(.*)\"[,]\"(.*)\"$",
		"^\"([a-fA-F0-9xX]+)\"[,]\"([a-fA-F0-9xX]+)\"[,]\"(.*)\"[,]\"(.*)\"[,]\"(.*)\"$"},
	true, 6, 1, 2, 0, 5
};

void list::read_fmt(const file_fmt& file, std::istream& is, 
		range::range_set_t* rset, int8_t tgt, bool short_fmt)
{
	regex_t reg_exp;
	regmatch_t reg_match[MAX_MATCH_SIZE];
	std::string buffer;
	u_long counter = 0;

	assert(rset);

	if (!is) 
		throw std::ios_base::failure("can't read from stream");

	regcomp(&reg_exp, file.reg_exp[strict_ip], REG_EXTENDED);

	for (u_long line = 1; (std::getline(is, buffer)); line++) {
 		buffer.erase(std::remove_if(buffer.begin(), buffer.end(), isspace), buffer.end());

		if (regexec(&reg_exp, buffer.c_str(), file.match_size, reg_match, 0)) 
			continue;

		range::range r;
		if (file.number)
			r.addr = std::make_pair(
					strtoul(buffer.substr(reg_match[file.start].rm_so, 
							REG_SIZE(reg_match[file.start])).c_str(), NULL, 0),
					strtoul(buffer.substr(reg_match[file.end].rm_so,
							REG_SIZE(reg_match[file.end])).c_str(), NULL, 0));
		else if (strict_ip) // inet_addr supports different bases
			r.addr = std::make_pair(
					ntohl(inet_addr(buffer.substr(reg_match[file.start].rm_so, 
								REG_SIZE(reg_match[file.start])).c_str())), 
					ntohl(inet_addr(buffer.substr(reg_match[file.end].rm_so, 
								REG_SIZE(reg_match[file.end])).c_str())));
		else
			r.addr = std::make_pair(
					str2ip(buffer.substr(reg_match[file.start].rm_so, 
							REG_SIZE(reg_match[file.start]))),
					str2ip(buffer.substr(reg_match[file.end].rm_so, 
							REG_SIZE(reg_match[file.end]))));

		if (file.name && !short_fmt)
			r.name = buffer.substr(reg_match[file.name].rm_so, 
					REG_SIZE(reg_match[file.name]));

		if (r.addr.first > r.addr.second)
			syslog(LOG_INFO, "info: swapping ips at line %lu", line);

		if (file.target && tgt < 0) {
			uint8_t t = atoi(buffer.substr(reg_match[file.target].rm_so, 
						REG_SIZE(reg_match[file.target])).c_str());
			r.target = (t < 127) ? NF_DROP : NF_ACCEPT;
		} else if (tgt >= 0)
			r.target = tgt;

		if (rset->insert(r).second) counter++;
	}
	regfree(&reg_exp);
	syslog(LOG_NOTICE, "info: %lu ip ranges inserted\n", counter);
}

void list::read_dat(std::istream& is, range::range_set_t* rset, 
		int8_t tgt, bool short_fmt)
{
	read_fmt(dat_file, is, rset, tgt, short_fmt);
}

void list::read_p2p(std::istream& is, range::range_set_t* rset, 
		int8_t tgt, bool short_fmt)
{
	read_fmt(p2p_file, is, rset, tgt, short_fmt);
}

void list::read_csv(std::istream& is, range::range_set_t* rset, 
		int8_t tgt, bool short_fmt)
{
	read_fmt(csv_file, is, rset, tgt, short_fmt);
}

void list::read_ipl(std::istream& is, range::range_set_t* rset, 
		int8_t tgt, bool short_fmt)
{
	char buf[7];
	char version = 0;
	u_long counter = 0;

	assert(rset);

	if (!is)
		throw std::ios_base::failure("can't read from stream");

	if (!is.read(buf, sizeof(buf)) || !is.read((char*)&version, sizeof(version)))
		throw std::ios_base::failure("can't read ipl file header");

	if (strncmp(buf, "\xFF\xFF\xFF\xFFIPL", sizeof(buf)) || version != IPL_v1)
		throw std::ios_base::failure("invalid ipl file");

	uint32_t name_size;
	if (!is.read((char*)&name_size, sizeof(name_size)))
		throw std::ios_base::failure("can't read name size in ipl file");
	name_size = ntohl(name_size);

	std::vector<std::string> names(name_size);

	for (uint32_t i = 0; i < name_size; i++) {
		std::string n;
		if (!std::getline(is, n, '\0'))
			throw std::ios_base::failure("can't read names in ipl file");
		names[i] = n;
	}
	uint32_t range_size;
	if (!is.read((char*)&range_size, sizeof(range_size)))
		throw std::ios_base::failure("can't read range size in ipl file");
	range_size = ntohl(range_size);

	for (uint32_t i = 0; i < range_size; i++) {
		uint32_t start, end, index;
		int8_t target;

		if (!is.read((char*)&start, sizeof(start)) || 
				!is.read((char*)&end, sizeof(end)) || 
				!is.read((char*)&index, sizeof(index)) ||
				!is.read((char*)&target, sizeof(target)))
			throw std::ios_base::failure("can't read ranges in ipl file");

		range::range r(ntohl(start), ntohl(end));
		r.target = (tgt < 0) ? target : tgt;

		if (!short_fmt)
			r.name = names[ntohl(index)];

		if (rset->insert(r).second) counter++;
	}
	syslog(LOG_NOTICE, "info: %lu ip ranges inserted\n", counter);
	if (!is.eof() && get_file_t(is) == IPL)
		read_ipl(is, rset, tgt, short_fmt);
}

list::file_t list::get_file_t(std::istream& is) throw()
{
	char buf[7];

	if (!is) return ERR;

	std::istream::pos_type pos = is.tellg();

	if (!is.read(buf, sizeof(buf))) return ERR;

	is.seekg(pos);

	if (!strncmp(buf, "\xFF\xFF\xFF\xFFIPL", sizeof(buf)))
		return IPL;
	
	file_t ftype = ERR;
	std::string buffer;
	regex_t reg_dat, 
			reg_p2p, 
			reg_csv;
	regmatch_t reg_match[MAX_MATCH_SIZE];

	regcomp(&reg_dat, dat_file.reg_exp[strict_ip], REG_EXTENDED);
	regcomp(&reg_p2p, p2p_file.reg_exp[strict_ip], REG_EXTENDED);
	regcomp(&reg_csv, csv_file.reg_exp[strict_ip], REG_EXTENDED);
		
	while (ftype == ERR && std::getline(is, buffer)) {
		buffer.erase(std::remove_if(buffer.begin(), buffer.end(), isspace), buffer.end());

		if (!regexec(&reg_dat, buffer.c_str(), dat_file.match_size, reg_match, 0)) 
			ftype = DAT;
		else if (!regexec(&reg_p2p, buffer.c_str(), p2p_file.match_size, reg_match, 0)) 
			ftype = P2P;
		else if (!regexec(&reg_csv, buffer.c_str(), csv_file.match_size, reg_match, 0)) 
			ftype = CSV;
	}
	regfree(&reg_dat);
	regfree(&reg_p2p);
	regfree(&reg_csv);

	is.seekg(pos);
	
	return ftype;
}

void list::read_file(const char* path, range::range_set_t* rset, 
		int8_t tgt, bool short_fmt)
{
	std::auto_ptr<std::stringstream> ss(new std::stringstream);
	gzFile file = gzopen(path, "r");

	if (!file)
		throw std::ios_base::failure("can't read " + std::string(path));

	std::auto_ptr<char> buf(new char[BUF_SIZE]);

	int count;
	while ((count = gzread(file, buf.get(), BUF_SIZE)) > 0)
		ss->write(buf.get(), count);

	gzclose(file);

	void (*read_fp)(std::istream&, range::range_set_t*, int8_t, bool);

	switch (get_file_t(*ss)) {
	case IPL: 
		read_fp = read_ipl; break;
	case DAT:
		read_fp = read_dat; break;
	case P2P:
		read_fp = read_p2p; break;
	case CSV:
		read_fp = read_csv; break;
	case ERR:
	default:	
//		throw std::runtime_error("unsupported input file type");
		syslog(LOG_ERR, "error: %s is of unsupported file type\n", path);
		return;
	}
	read_fp(*ss, rset, tgt, short_fmt);
}

void list::write_file(const char* path, file_t type, const range::range_set_t* rset)
{
	std::auto_ptr<std::stringstream> ss(new std::stringstream);
	void (*write_fp)(std::ostream&, const range::range_set_t*);

	switch (type) {
	case IPL: 
		write_fp = write_ipl; break;
	case DAT:
		write_fp = write_dat; break;
	case P2P: 
		write_fp = write_p2p; break;
	case CSV:
	case ERR:
	default:	
		throw std::runtime_error("unsupported output file type");
	}
	write_fp(*ss, rset);

	std::auto_ptr<char> buf(new char[BUF_SIZE]);
	gzFile file = gzopen(path, "wb6");

	if (!file)
		throw std::ios_base::failure("can't write " + std::string(path));

	while (*ss) {
		ss->read(buf.get(), BUF_SIZE);
		gzwrite(file, buf.get(), ss->gcount());
	}
	gzclose(file);
}

void list::write_ipl(std::ostream& os, const range::range_set_t* rset)
{
	assert(rset);

	if (!os) 
		throw std::ios_base::failure("can't write to stream");
	// standard header
	os.write("\xFF\xFF\xFF\xFFIPL\x01", 8);

	uint32_t j = 0;
	std::tr1::unordered_map<std::string, uint32_t> names_ind;
	std::vector<std::string> names;

	for (range::range_set_t::const_iterator i = rset->begin();
			i != rset->end(); i++)
		if (names_ind.find(i->name) == names_ind.end()) {
			names_ind[i->name] = j++;
			names.push_back(i->name);
		}
	// the amount of names that follow
	j = htonl(j);
	os.write((const char*)&j, sizeof(j));
	// null-terminated names
	for (std::vector<std::string>::size_type i = 0; i < names.size(); i++)
		os.write(names.at(i).c_str(), (std::streamsize)names.at(i).size()+1);
	// the amount of ip ranges that follow
	j=htonl(rset->size());
	os.write((const char*)&j, sizeof(j));
	// ip ranges
	for (range::range_set_t::const_iterator i = rset->begin();
			i != rset->end(); i++) {
		uint32_t start = htonl(i->addr.first), 
				 end = htonl(i->addr.second), 
				 index = htonl(names_ind[i->name]);

		os.write((const char*)&start, sizeof(start)); 
		os.write((const char*)&end, sizeof(end));
		os.write((const char*)&index, sizeof(index));
		os.write((const char*)&i->target, sizeof(i->target));
	}
	if (os.bad())
		throw std::ios_base::failure("fatal error occured during writing");
}

void list::copy_file(const char* from, const char* to) {
	std::auto_ptr<char> buf(new char[BUF_SIZE]);
	int in = open(from, O_RDONLY),
		out = open(to, O_WRONLY);

	if (in == -1 || out == -1)
		throw std::ios_base::failure("can't copy " + std::string(from));

	int count;
	while ((count = read(in, buf.get(), BUF_SIZE)) > 0)
		if (write(out, buf.get(), count) == -1)
			throw std::ios_base::failure(strerror(errno));

	close(in);
	close(out);
}

/* 
void copy_file(const std::string& from, const std::string& to) {
	std::ifstream in(from.c_str());
	std::ofstream out(to.c_str());

	if (!in || !out)
		throw std::ios_base::failure("can't copy " + from);

	std::copy(std::istreambuf_iterator<char>(in),
			std::istreambuf_iterator<char>(), 
			std::ostreambuf_iterator<char>(out));
}
*/

void list::write_p2p(std::ostream& os, const range::range_set_t* rset)
{
	if (!os) 
		throw std::ios_base::failure("can't write to stream");

	for (range::range_set_t::const_iterator i = rset->begin();
			i != rset->end(); i++) {
		in_addr start = {htonl(i->addr.first)}, 
				end = {htonl(i->addr.second)};
		os << i->name << ":" << inet_ntoa(start);
		os << "-" << inet_ntoa(end) << "\n";
	}
}

void list::write_dat(std::ostream& os, const range::range_set_t* rset)
{
	if (!os) 
		throw std::ios_base::failure("can't write to stream");

	for (range::range_set_t::const_iterator i = rset->begin();
			i != rset->end(); i++) {
		in_addr start = {htonl(i->addr.first)}, 
				end = {htonl(i->addr.second)};
		uint8_t target = (i->target == NF_ACCEPT) ? 255 : 0;

		os << inet_ntoa(start) << "-";
		os << inet_ntoa(end) << "," << int(target) 
			<< "," << i->name << "\n";
	}
}

std::string list::ip2str(uint32_t ip)
{
	std::ostringstream os;
	os	<< int((ip >> 24) & 0xff) << "."
		<< int((ip >> 16) & 0xff) << "."
		<< int((ip >> 8) & 0xff) << "."
		<< int(ip & 0xff);
	return os.str();
}

uint32_t list::str2ip(const std::string& str)
{
	uint16_t a, b, c, d;

	if (sscanf(str.c_str(), "%hu.%hu.%hu.%hu", &a, &b, &c, &d) != 4 || 
			a > 255 || b > 255 || c > 255 || d > 255)
		throw std::runtime_error("can't convert " + str);

	return a << 24 | b << 16 | c << 8 | d;
}

