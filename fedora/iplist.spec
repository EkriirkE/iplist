Summary: List based packet handler
Name: iplist
Vendor: Serkan Sakar <uljanow@users.sourceforge.net>
Packager: Serkan Sakar <uljanow@users.sourceforge.net>
Version: 0.25
Release: 0.fedora10
Source0: %{name}-%{version}.tar.gz
License: GPLv2+
Group: Applications/Internet
URL: http://iplist.sourceforge.net
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}
#Requires: libnfnetlink
#Requires: libnetfilter_queue
Requires: java >= 1.6
BuildRequires: gcc-c++
BuildRequires: zlib-devel
BuildRequires: libnfnetlink-devel
BuildRequires: libnetfilter_queue-devel
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

mkdir -p ${RPM_BUILD_ROOT}/usr/sbin/
mkdir -p ${RPM_BUILD_ROOT}/usr/bin/
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/cron.daily/
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/pam.d/
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/security/console.apps/
mkdir -p ${RPM_BUILD_ROOT}/%{_initrddir}/
mkdir -p ${RPM_BUILD_ROOT}/usr/share/java/
mkdir -p ${RPM_BUILD_ROOT}/usr/share/applications/
mkdir -p ${RPM_BUILD_ROOT}/usr/share/pixmaps/
mkdir -p ${RPM_BUILD_ROOT}/%{_mandir}/man8/
mkdir -p ${RPM_BUILD_ROOT}/var/cache/iplist/

ln -s /usr/bin/consolehelper ${RPM_BUILD_ROOT}/usr/bin/ipblock

install -p -m 644 ipblock.conf \
	${RPM_BUILD_ROOT}/%{_sysconfdir}/ipblock.conf
install -p -m 644 ipblock.lists \
	${RPM_BUILD_ROOT}/%{_sysconfdir}/ipblock.lists
install -p -m 644 fedora/ipblock.pam \
	${RPM_BUILD_ROOT}/%{_sysconfdir}/pam.d/ipblock
install -p -m 644 fedora/ipblock.security \
	${RPM_BUILD_ROOT}/%{_sysconfdir}/security/console.apps/ipblock
install -p -m 755 fedora/ipblock.init \
	${RPM_BUILD_ROOT}/%{_initrddir}/ipblock
install -p -m 755 debian/ipblock.cron.daily \
	${RPM_BUILD_ROOT}/%{_sysconfdir}/cron.daily/ipblock
install -p -m 644 fedora/ipblock.desktop \
	${RPM_BUILD_ROOT}/usr/share/applications/ipblock.desktop
install -p -m 644 ipblock.png \
	${RPM_BUILD_ROOT}/usr/share/pixmaps/ipblock.png

install -p -m 644 iplist.8 ${RPM_BUILD_ROOT}/%{_mandir}/man8/
install -p -m 644 ipblock.8 ${RPM_BUILD_ROOT}/%{_mandir}/man8/
install -p -m 644 allow.p2p ${RPM_BUILD_ROOT}/var/cache/iplist/

make DESTDIR=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT

%post
update-desktop-database -q
chkconfig --add ipblock

%preun
chkconfig --del ipblock

%postun
update-desktop-database -q

%files
%defattr(-,root,root)
%doc debian/copyright changelog ipblock.lists allow.p2p ipblock.conf
%attr(0755, root, root) /usr/sbin/iplist
%attr(0755, root, root) /usr/sbin/ipblock
%attr(0755, root, root) /usr/bin/ipblock
%attr(0644, root, root) %{_mandir}/man8/iplist.8*
%attr(0644, root, root) %{_mandir}/man8/ipblock.8*
%attr(0755, root, root) %dir /var/cache/iplist
%attr(0644, root, root) /var/cache/iplist/allow.p2p
%attr(0644, root, root) %config  %{_sysconfdir}/ipblock.conf
%attr(0644, root, root) %config  %{_sysconfdir}/ipblock.lists
%attr(0644, root, root) %{_sysconfdir}/pam.d/ipblock
%attr(0644, root, root) %{_sysconfdir}/security/console.apps/ipblock
%attr(0755, root, root) %{_sysconfdir}/cron.daily/ipblock
%attr(0755, root, root) %{_initrddir}/ipblock
%attr(0644, root, root) /usr/share/java/ipblockUI.jar
%attr(0644, root, root) /usr/share/applications/ipblock.desktop
%attr(0644, root, root) /usr/share/pixmaps/ipblock.png

%changelog
* Fri Nov 07 2008 Serkan Sakar <uljanow@users.sourceforge.net> 1.0
- fixed rpmlint errors

