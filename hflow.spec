Summary:  Hflow data Coalsesing 
Name: hflow
Version: 1.99.26
Release: 2
License: GPL
Group:   Applications/Honeynet
URL:     http://project.honeynet.org/tools/download/walleye-%{version}-%{release}.tar.gz 
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: snort
Requires: p0f 
Requires: libstdc++
Requires: libdbi >= 0.8
Requires: libdbi-dbd-mysql
Requires: pcre
Requires: libpcap
Requires: mysql-server >= 4.0
Requires: snort  >= 2.4
BuildRequires: autoconf, automake, pcre-devel,libstdc++-devel,libdbi-devel


%description
Hflow is a Data coalesing engine. It 
Walleye is a web-based Honeynet data analysis interface.  Hflow is
used to populated the database, Walleye is used to examine this data.
Walleye provides cross data source views of intrusion events that
we attempt to make workflow centric.

%define bindir    /usr/bin/
%define confdir	  /etc/hflow/
%define etcdir    /etc/
#%define walleye   /var/www/html/walleye
#%define perldir   /usr/lib/perl5/vendor_perl

%prep
%setup -n  %{name}-%{version}

%build
%configure --prefix=/usr --sysconfdir=/etc  --target=%{_target}
%{__make}

%install
rm -rf %{buildroot}
#make install 	basedir=%{buildroot}
#make install
#rm -rf $RPM_BUILD_ROOT
#mkdir -p $RPM_BUILD_ROOT%{etcdir}/hflow
#mkdir -p $RPM_BUILD_ROOT%{bindir}
#mkdir -p $RPM_BUILD_ROOT%{confdir}/misc

%{__install} -Dp -m0755 hflow	            %{buildroot}%{_bindir}/hflow
%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/hflow/
%{__install} -p -m0644  snort.conf          %{buildroot}%{_sysconfdir}/hflow/
%{__install} -m0444  hflowd.schema       %{buildroot}%{_sysconfdir}/hflow/
%{__install} -m0444  pcre.rules          %{buildroot}%{_sysconfdir}/hflow/
%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/hflow/misc/
%{__install} -m0444  misc/*  		 %{buildroot}%{confdir}/misc/
%{__install} -m0755  misc/*.pl              %{buildroot}%{confdir}/misc/
%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/init.d/
%{__install} -m0554 init.d/hflow %{buildroot}%{_sysconfdir}/init.d

#log and pid dirs
%{__install} -d -m0755 %{buildroot}%{_var}/run/hflow
%{__install} -d -m0755 %{buildroot}%{_var}/lib/hflow
%{__install} -d -m0755 %{buildroot}%{_var}/lib/hflow/snort

#install -m 0444  misc/snort-2.6.0-spo_unified.c.patch  $RPM_BUILD_ROOT%{confdir}/misc
#install -m 0444  misc/snort-2.6.1.5-spo_unified.c.patch  $RPM_BUILD_ROOT%{confdir}/misc


#echo "Do not forget to install the hflowd schema. "
#echo "To install: "
#echo "  >mysql -u DB_ROOT_USER -p < /etc/hflow/hlowd.schema"

#rm -rf $RPM_BUILD_ROOT              
#mkdir -p $RPM_BUILD_ROOT%{etcdir}/walleye
#mkdir -p $RPM_BUILD_ROOT%{etcdir}/init.d
#mkdir -p $RPM_BUILD_ROOT%{walleye}
#mkdir -p $RPM_BUILD_ROOT%{walleye}/icons
#mkdir -p $RPM_BUILD_ROOT%{walleye}/images
#mkdir -p $RPM_BUILD_ROOT%{walleye}/admin/templates/img
#mkdir -p $RPM_BUILD_ROOT%{perldir}/Walleye


#install -m 0550 -o root -g root httpd.conf        $RPM_BUILD_ROOT%{etcdir}/walleye
#install -m 0550 -o root -g root walleye-httpd     $RPM_BUILD_ROOT%{etcdir}/init.d

#install -m 0550 -o apache -g apache *.pl              $RPM_BUILD_ROOT%{walleye}
#ln $RPM_BUILD_ROOT%{walleye}/walleye.pl $RPM_BUILD_ROOT%{walleye}/index.pl
#install -m 0550 -o apache -g apache  admin/*.pl       $RPM_BUILD_ROOT%{walleye}/admin

#install -m 0550 -o apache -g apache  admin/templates/*.*       $RPM_BUILD_ROOT%{walleye}/admin/templates/
#install -m 0550 -o apache -g apache  admin/templates/img/*.*       $RPM_BUILD_ROOT%{walleye}/admin/templates/img/

#install -m 0444 -o root   -g root modules/Walleye/*.pm $RPM_BUILD_ROOT%{perldir}/Walleye

#install -m 0440 -o apache -g apache *.css             $RPM_BUILD_ROOT%{walleye}
#install -m 0440 -o apache -g apache *.jpg             $RPM_BUILD_ROOT%{walleye}
#install -m 0440 -o apache -g apache *.png             $RPM_BUILD_ROOT%{walleye}
#install -m 0440 -o apache -g apache *.gif             $RPM_BUILD_ROOT%{walleye}
#install -m 0440 -o apache -g apache *.ico             $RPM_BUILD_ROOT%{walleye}
#install -m 0440 -o apache -g apache icons/*.png       $RPM_BUILD_ROOT%{walleye}/icons

%clean
#rm -rf $RPM_BUILD_ROOT
rm -rf %{buildroot}


%files
%defattr(-,root,root,0755)
%{bindir}/hflow
%{_sysconfdir}/hflow/hflowd.schema 
%{_sysconfdir}/hflow/snort.conf 
#%{confdir}/misc/snort-2.4.5-spo_unified.c.patch 
#%{confdir}/misc/snort-2.6.0-spo_unified.c.patch
#%{confdir}/misc/snort-2.6.1.5-spo_unified.c.patch
%{_sysconfdir}/hflow/misc/*
%{_sysconfdir}/hflow/pcre.rules
#%{etcdir}/walleye/httpd.conf
#%{etcdir}/init.d/walleye-httpd
%{_sysconfdir}/init.d/hflow

%attr(0755,root,root) %dir %{_sysconfdir}/hflow
%attr(0755,root,root) %dir %{_sysconfdir}/hflow/misc

#%{perldir}/Walleye/*.pm
#%{walleye}/*.pl
#%{walleye}/*.css
#%{walleye}/*.png
#%{walleye}/*.jpg
#%{walleye}/*.gif
#%{walleye}/*.ico
#%{walleye}/icons/*.png
#%{walleye}/images
#%{walleye}/admin/*.pl
#%{walleye}/admin/templates/*.*
#%{walleye}/admin/templates/img/*.*

%post

if [ $1 -eq 1 ]; then
        #--- install
#        /usr/bin/openssl genrsa 1024 > /etc/walleye/server.key
#	chmod go-rwx /etc/walleye/server.key 
#	openssl req -new -key /etc/walleye/server.key -x509 -days 365 -out /etc/walleye/server.crt -batch -set_serial `date +%s`
#	chown apache %{walleye}/images
#	ln -s /usr/lib/httpd/modules /etc/walleye/modules
#	/sbin/chkconfig --add walleye-httpd	
 
  #add the hflow user
  /usr/sbin/groupadd _hflow 
  /usr/sbin/useradd  -m  -c "Hflow" -d /var/log/hflow -s /dev/null -g _hflow _hflow 

  #the next is very wrong!
  mkdir %{_var}/lib/hflow
  mkdir %{_var}/lib/hflow/snort
  mkdir %{_var}/run/hflow

  chown -R _hflow /var/lib/hflow
  chown -R _hflow /var/run/hflow  

  echo "Do not forget to install the hflowd schema and populate the snort signatures "
  echo "To install the schema: "
  echo "  >mysql -u DB_ROOT_USER -p < /etc/hflow/hlowd.schema"
  echo "To populate the snort signature data (using RH locations):"
  echo "  >/etc/hflow/misc/sid_map_upload.pl -r /etc/snort/rules/sid-msg.map"
fi


if [ $1 -ge 2 ]; then
        #--- upgrade 
	if [ -e "/var/run/hflow/hflow.pid" ]
	then
		/etc/init.d/hflow restart
	fi
fi

%postun
if [ $1 = 0 ] ; then
        /usr/sbin/userdel _hflow 2>/dev/null
fi



