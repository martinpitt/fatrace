Name:		fatrace
Version:	0
Release:	%autorelease
Summary:	Reports file access events from all running processes

License:	GPL-3.0-or-later
URL:		https://github.com/martinpitt/fatrace
Source0:        https://github.com/martinpitt/fatrace/archive/refs/tags/%{version}.tar.gz
BuildRequires:  gcc
BuildRequires: make

%description
fatrace reports file access events from all running processes.

Its main purpose is to find processes which keep waking up the disk
unnecessarily and thus prevent some power saving.

%prep
%autosetup

%build
export CFLAGS="%{optflags}"
make %{?_smp_mflags}

%install
export PREFIX=%{_prefix}
make install DESTDIR=%{buildroot}
# move /sbin to /bin
mv %{buildroot}%{_prefix}/sbin %{buildroot}%{_bindir}

%files
%doc COPYING
%{_bindir}/fatrace
%{_bindir}/power-usage-report
%{_mandir}/man*/*

%changelog
%autochangelog
