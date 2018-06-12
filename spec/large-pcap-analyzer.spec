Name:           large-pcap-analyzer
Version:        3.5.1
Release:        1%{?dist}
Summary:        A command-line utility program to process PCAP captures

License:        GPL
URL:            https://github.com/f18m/large-pcap-analyzer
Source0:        https://github.com/f18m/large-pcap-analyzer/archive/3.5.1.tar.gz

BuildRequires:  gcc-c++, libpcap-devel, make

%description
A command-line utility program that performs some simple operations on .PCAP files very quickly.
This allows you to manipulate also very large PCAP files that cannot be easily handled with other
software like Wireshark (or tshark). Supports filtering encapsulated GTPu frames.
Supports simple per-TCP-stream filtering. Easily extendible.

%prep
%autosetup

%build
%configure
%make_build

%install
rm -rf %{buildroot}
%make_install

%files
%{_bindir}/large_pcap_analyzer
