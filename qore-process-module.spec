%define module_api %(qore --module-api 2>/dev/null)
%define module_dir %{_libdir}/qore-modules

%if 0%{?sles_version}

%define dist .sles%{?sles_version}

%else
%if 0%{?suse_version}

# get *suse release major version
%define os_maj %(echo %suse_version|rev|cut -b3-|rev)
# get *suse release minor version without trailing zeros
%define os_min %(echo %suse_version|rev|cut -b-2|rev|sed s/0*$//)

%if %suse_version
%define dist .opensuse%{os_maj}_%{os_min}
%endif

%endif
%endif

# see if we can determine the distribution type
%if 0%{!?dist:1}
%define rh_dist %(if [ -f /etc/redhat-release ];then cat /etc/redhat-release|sed "s/[^0-9.]*//"|cut -f1 -d.;fi)
%if 0%{?rh_dist}
%define dist .rhel%{rh_dist}
%else
%define dist .unknown
%endif
%endif

Summary: process module for Qore
Name: qore-process-module
Version: 1.0.5
Release: 1%{dist}
License: LGPL-2.1-or-later
Group: Development/Languages/Other
URL: http://www.qore.org
Source: https://github.com/qorelanguage/module-process/releases/download/release-%{version}/%{name}-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: /usr/bin/env
Requires: qore-module-api-%{module_api}
BuildRequires: cmake >= 3.5
BuildRequires: gcc-c++
BuildRequires: qore-devel >= 1.12.4
BuildRequires: qore-stdlib >= 1.12.4
BuildRequires: qore >= 1.12.4
BuildRequires: openssl-devel
BuildRequires: doxygen
%if 0%{?el7}
BuildRequires:  devtoolset-7-gcc-c++
%endif

%description
process API module for the Qore Programming Language.

%if 0%{?suse_version}
%debug_package
%endif

%prep
%setup -q

%build
%if 0%{?el7}
# enable devtoolset7
. /opt/rh/devtoolset-7/enable
%endif
export CXXFLAGS="%{?optflags}"
cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} -DCMAKE_BUILD_TYPE=RELWITHDEBINFO -DCMAKE_SKIP_RPATH=1 -DCMAKE_SKIP_INSTALL_RPATH=1 -DCMAKE_SKIP_BUILD_RPATH=1 -DCMAKE_PREFIX_PATH=${_prefix}/lib64/cmake/Qore .
make %{?_smp_mflags}
make %{?_smp_mflags} docs
sed -i 's/#!\/usr\/bin\/env qore/#!\/usr\/bin\/qore/' test/*.qtest

%install
make DESTDIR=%{buildroot} install %{?_smp_mflags}

%check
qore -l ./process-api-1.3.qmod test/process.qtest -v

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{module_dir}
%doc COPYING README test/process.qtest test/test_cwd.q test/test_env.q test/test_false.q test/test_io.q test/test_output.q test/test_sleep.q test/test_true.q test/test_utf8.q

%package doc
Summary: Documentation and examples for the Qore process module
Group: Development/Languages/Other

%description doc
This package contains the HTML documentation and example programs for the Qore
process module.

%files doc
%defattr(-,root,root,-)
%doc docs/process test

%changelog
* Mon Dec 19 2022 David Nichols <david.nichols@qoretechnologies.com>
- updated to version 1.0.5

* Mon Jan 10 2022 David Nichols <david.nichols@qoretechnologies.com>
- updated to version 1.0.4

* Mon Dec 27 2021 David Nichols <david.nichols@qoretechnologies.com>
- updated to version 1.0.3

* Fri Sep 17 2021 David Nichols <david.nichols@qoretechnologies.com>
- initial spec file
