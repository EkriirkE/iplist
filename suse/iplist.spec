Summary: List based packet handler
Name: iplist
Vendor: Serkan Sakar <uljanow@users.sourceforge.net>
Packager: Serkan Sakar <uljanow@users.sourceforge.net>
Version: 0.26
Release: 0.suse%{suse_version}
Source0: %{name}-%{version}.tar.gz
License: GPLv2+
Group: Applications/Internet
URL: http://iplist.sourceforge.net
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}
#Requires: libnfnetlink
#Requires: libnetfilter_queue
Requires: java >= 1.6
Requires: sysconfig
Requires: cron
BuildRequires: gcc-c++
BuildRequires: zlib-devel
BuildRequires: libnfnetlink0-devel
BuildRequires: libnetfilter_queue1-devel
BuildRequires: update-desktop-files
BuildRequires: fastjar
BuildRequires: sysconfig
#BuildRequires: java-devel >= 1.6

%description
iplist is a list based packet handler which uses
the netfilter netlink-queue library (kernel 2.6.14 or 
later). It filters by IP-address and is optimized for 
thousands of IP-address ranges.

%prep
%setup -q

%build
make

%install
rm -rf $RPM_BUILD_ROOT

install -D -p -m 644 ipblock.conf \
	${RPM_BUILD_ROOT}/%{_sysconfdir}/ipblock.conf
install -D -p -m 644 ipblock.lists \
	${RPM_BUILD_ROOT}/%{_sysconfdir}/ipblock.lists
install -D -p -m 755 suse/ipblock.init \
	${RPM_BUILD_ROOT}/%{_initrddir}/ipblock
install -D -p -m 755 debian/ipblock.cron.daily \
	${RPM_BUILD_ROOT}/%{_sysconfdir}/cron.daily/ipblock
install -D -p -m 755 suse/Z-ipblock \
	${RPM_BUILD_ROOT}/%{_sysconfdir}/sysconfig/network/if-up.d/Z-ipblock
#install -D -p -m 644 suse/ipblock.desktop \
#	${RPM_BUILD_ROOT}/usr/share/applications/ipblock.desktop
install -D -p -m 644 ipblock.png \
	${RPM_BUILD_ROOT}/usr/share/pixmaps/ipblock.png

mkdir -p ${RPM_BUILD_ROOT}/usr/share/applications/
%suse_update_desktop_file -c ipblock IPblock "IP Blocker" "/usr/sbin/ipblock gui" ipblock System Monitor GTK System Network

export NO_BRP_CHECK_BYTECODE_VERSION=true

install -D -p -m 644 iplist.8 ${RPM_BUILD_ROOT}/%{_mandir}/man8/iplist.8
install -D -p -m 644 ipblock.8 ${RPM_BUILD_ROOT}/%{_mandir}/man8/ipblock.8
install -D -p -m 644 allow.p2p ${RPM_BUILD_ROOT}/var/cache/iplist/allow.p2p

make DESTDIR=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT

%post
#update-desktop-database -q
%fillup_and_insserv -fy network
chkconfig --add ipblock

%preun
%stop_on_removal ipblock
chkconfig --del ipblock

%postun
#update-desktop-database -q
%insserv_cleanup

%files
%defattr(-,root,root)
%doc debian/copyright changelog ipblock.lists allow.p2p ipblock.conf
%attr(0755, root, root) /usr/sbin/iplist
%attr(0755, root, root) /usr/sbin/ipblock
%attr(0644, root, root) %{_mandir}/man8/iplist.8*
%attr(0644, root, root) %{_mandir}/man8/ipblock.8*
%attr(0755, root, root) %dir /var/cache/iplist
%attr(0644, root, root) /var/cache/iplist/allow.p2p
%attr(0644, root, root) %config  %{_sysconfdir}/ipblock.conf
%attr(0644, root, root) %config  %{_sysconfdir}/ipblock.lists
%attr(0755, root, root) %{_sysconfdir}/cron.daily/ipblock
%attr(0755, root, root) %{_sysconfdir}/sysconfig/network/if-up.d/Z-ipblock
%attr(0755, root, root) %{_initrddir}/ipblock
%attr(0644, root, root) /usr/share/java/ipblockUI.jar
%attr(0644, root, root) /usr/share/applications/ipblock.desktop
%attr(0644, root, root) /usr/share/pixmaps/ipblock.png

%changelog
* Fri Nov 07 2008 Serkan Sakar <uljanow@users.sourceforge.net> 1.0
- 

