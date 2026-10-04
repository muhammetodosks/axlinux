%global selinux_policy_name axlinux

# AXlinux RPM paketi.
#
# Debian tarafindaki .deb ile AYNI dosya duzenini kurar; testler
# (tests/test_install_guard.py) her iki yolun ayrilmasini
# engelliyor.
#
# Fedora'ya ozgu olanlar:
#   - SELinux modulu (enforcing varsayilan, modul olmadan
#     bpf() syscall'u reddedilir)
#   - daemon ayri bir alana (axlinux_daemon_t) tasinir
#   - rpm tabanli yaşam dongusu: %pre/%post/%preun/%postun

Name:           axlinux
Version:        1.0.0
Release:        1%{?dist}
Summary:        Mandatory access control with a YAML policy language

License:        MIT
URL:            https://github.com/axlinux/axlinux
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.21
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  bpftool
BuildRequires:  make
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  selinux-policy-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  gcc
BuildRequires:  go-bindata

Requires:       python3 >= 3.9
Requires:       python3-click
Requires:       python3-rich
Requires:       python3-yaml
Requires:       kernel-core
Recommends:     bpftool

%description
AXlinux, YAML tabanli bir politika diliyle Linux icin zorunlu
erisim denetimi (MAC) saglar.

Dogrulama eBPF LSM zincirine zincirlenir: beceri kancalari
file.read, file.write, file.execute, net.connect, net.bind ve
process.exec uzerine baglanir. Politika BPF haritalarina
derlenir ve kernel tarafinda uygulanir; politika degistirilene
kadar surecler kirpilamaz.

Bu paket Fedora'da SELinux enforcing ile calisir. Politika
modulu (axlinux) bpf() syscall yetkisini yalnizca axdaemon
alanina verir; sistem geneline acik degildir.

%prep
%autosetup

%build
# Uretilen ikililer rpm'e gomulur; kullanici makinesinde
# derleme araci gerekmez.
make all

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

# CLI giris noktasi: paket dizininden yukler
install -m 0755 packaging/axctl %{buildroot}%{_bindir}/axctl

# Ornek politikalar zaten /etc/axlinux altina kuruluyor

# systemd birimleri ve tmpfiles
install -m 0644 packaging/axdaemon.service \
    %{buildroot}%{_unitdir}/axdaemon.service
install -m 0644 packaging/axlog.service \
    %{buildroot}%{_unitdir}/axlog.service
install -m 0644 packaging/axlinux-tmpfiles.conf \
    %{buildroot}%{_prefix}/lib/tmpfiles.d/axlinux.conf

# SELinux drop-in: NoNewPrivileges, kendi alanina gecisi
# engelliyordu (status=203/EXEC). Gerekce 10-selinux.conf
# icinde.
install -d %{buildroot}%{_unitdir}/axdaemon.service.d
install -m 0644 packaging/fedora/axdaemon.service.d/10-selinux.conf \
    %{buildroot}%{_unitdir}/axdaemon.service.d/10-selinux.conf
install -d %{buildroot}%{_unitdir}/axlog.service.d
install -m 0644 packaging/fedora/axlog.service.d/10-selinux.conf \
    %{buildroot}%{_unitdir}/axlog.service.d/10-selinux.conf

# Belgeler
install -d %{buildroot}%{_docdir}/%{name}/docs
cp docs/*.md %{buildroot}%{_docdir}/%{name}/docs/ 2>/dev/null || :
install -m 0644 README.md DAGITIM.md CHANGELOG.md \
    %{buildroot}%{_docdir}/%{name}/ 2>/dev/null || :

# --- SELinux ---
# Politika + dosya baglamlari. install.sh ile AYNI betik
# kullanilir; iki kurulum yolunun farkli sonuc vermemesi icin
# tek dogruluk kaynagi.
%{__semanage} -f %{selinux_policy_name} -i \
    %{_datadir}/selinux/packages/%{selinux_policy_name}.pp 2>/dev/null || :

install -m 0755 packaging/fedora/selinux-setup.sh \
    %{buildroot}%{_prefix}/share/axlinux/selinux-setup.sh

# --- ldconfig / systemd ---
%ldconfig

%pre
# Kurulum oncesi: eski surumden kalma servisleri durdur
%systemd_preun axdaemon.service

%post
%systemd_post axdaemon.service
%systemd_post axlog.service

# tmpfiles: paylasilan /run/axlinux dizinini olusturur.
# systemd bunu ayrica yapmaz; iki servis bu dizini paylasir ve
# biri RuntimeDirectory tanimlarsa digerinin soketini siler.
%tmpfiles_create axlinux.conf

# SELinux: modul + dosya baglamlari.
if [ -x %{_prefix}/share/axlinux/selinux-setup.sh ]; then
    %{_prefix}/share/axlinux/selinux-setup.sh || \
        echo "AXlinux: SELinux kurulumu basarisiz; enforcement etkisiz."
fi

# Servislerin hazir olmasini bekle. eBPF yukleme ve 5 kanca
# baglama ~2 saniye suruyor; kurulumdan hemen sonra
# "axctl status" soketi bulamayip "calismiyor" diyordu.
i=0
while [ $i -lt 30 ]; do
    if [ -S /run/axlinux/axdaemon.sock ] && \
       [ -S /run/axlinux/axlog.sock ]; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
if [ $i -ge 30 ]; then
    echo "AXlinux: DIKKAT - servisler 30 saniyede hazir olmadi."
    echo "  'journalctl -u axdaemon' ile inceleyin."
fi

%preun
%systemd_preun axdaemon.service
%systemd_preun axlog.service

# Kaldirmadan ONCE veri yedeklenmeli. Politika ve audit
# KULLANICI VERISIDIR ve rpm tarafindan silinmez (her iki
# konum da %ghost degil, hicbir %files girdisinde degil),
# ama operatora acikca soyleniyor.
if [ $1 -eq 0 ]; then
    echo "AXlinux: kaldiriliyor."
    echo "  Politika ve audit KORUNUYOR:"
    echo "    ~/.axlinux, \$AXLINUX_HOME, /var/log/axlinux"
    echo "  Tam silmek icin bu dizinleri elle kaldirin."
fi

%postun
%systemd_postun_with_restart axdaemon.service
%systemd_postun_with_restart axlog.service

# Politika ve audit KALICI: kullanici verisidir. Silinmez.
# Servisler durdurulur, socket dosyalari ve __pycache__
# temizlenir.
rm -rf /usr/lib/axlinux/axctl/__pycache__ 2>/dev/null || :
rmdir /usr/lib/axlinux/axctl /usr/lib/axlinux 2>/dev/null || :

# SELinux modulunu kaldir
if [ $1 -eq 0 ] && command -v semanage >/dev/null 2>&1; then
    semanage module -r axlinux 2>/dev/null || :
    semanage delete -a axlinux_daemon_t 2>/dev/null || :
fi

%files
%license LICENSE
%doc README.md
%doc DAGITIM.md
%doc CHANGELOG.md
%doc %{_docdir}/%{name}/docs
%{_bindir}/axdaemon
%{_bindir}/axlog
%{_bindir}/axctl
%{_prefix}/lib/axlinux/axbpf.o
%{_prefix}/lib/axlinux/axctl/
%dir %{_sysconfdir}/axlinux
%config(noreplace) %{_sysconfdir}/axlinux/*.yaml
%{_unitdir}/axdaemon.service
%{_unitdir}/axlog.service
%{_prefix}/lib/tmpfiles.d/axlinux.conf

# SELinux modulu
%{_datadir}/selinux/packages/%{selinux_policy_name}.pp
%{_datadir}/selinux/%{selinux_policy_name}.pp
%{_datadir}/selinux/devel/include/%{selinux_policy_name}.if
%{_datadir}/selinux/%{selinux_policy_name}.fc

%changelog
* Thu Oct 02 2026 AXlinux Team <dev@axlinux.local> - 1.0.0-1
- Ilk RPM paketi. SELinux enforcing Fedora'da calisir.
- axdaemon ayri SELinux alanina tasindi; bpf() yetkisi
  yalnizca bu alana verilir.
- .deb ile ayni dosya duzeni.
