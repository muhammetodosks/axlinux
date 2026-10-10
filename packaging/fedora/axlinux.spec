%global selinux_policy_name axlinux

# Go ikilileri GNU build-id URETMEZ. rpm'in find-debuginfo adimi
# "No build ID note found" ile hata verip yuzde-yuzde-install
# bolumunu DUSURUYORDU. Ayri debuginfo alt paketi uretilmesin.
# Go ikilileri strip edilmedigi icin DWARF bilgisi ikilinin icinde
# kalir; sembol bilgisi kaybolmaz.
%global debug_package %{nil}

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
Version:        1.2.0
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
# rpm-sign: rpmsign komutunu icerir. Fedora 44'te ayri paket;
# imzalama yapilacaksa kurulu olmali.
BuildRequires:  rpm-sign
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  selinux-policy-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  gcc

Requires:       python3 >= 3.9
Requires:       python3-click
Requires:       python3-rich
Requires:       python3-yaml
Requires:       kernel-core
# AXlinux'in SELinux KORUMASI bu pakete baglidir; bu olmadan
# paket sessizce yarim kurulur.
#
# GERCEK HATA: `selinux-setup.sh` dosya baglamlarini
# `semanage fcontext -a` ile yaziyor, ama semanage bu pakette
# gelir. Fedora 44 cloud imajinda tesadufen KURULU oldugu icin
# orada calisiyordu; Fedora 43 cloud imajinda KURULU DEGIL.
#
# Sonuc Fedora 43'te olculdu: `set_fcontext` sessizce basarisiz
# oluyor, `/usr/bin/axdaemon` bin_t olarak kaliyor ve daemon
# UNCONFINED alanda calisiyor. Yani SELinux korumasi hic yok -
# ama kurulum "basarili" gorunuyor. deep_verify bunu yakaladi:
#   FAIL axdaemon unconfined alanda; SELinux korumasi YOK
Requires:       policycoreutils-python-utils
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
# `make bpf go`, `make all` DEGIL.
#
# `all = bpf go python` ve python hedefi CALISMA ZAMANI
# bagimliliklarini (click/rich/yaml) kontrol eder. Bunlar RPM
# kurulduktan SONRA gerekir; derleme aninda gerekmez.
#
# Dogrulanmis olarak ortaya cikti: Fedora 41, 42 ve 43
# konteynerlerinin UCUNDE de gerekli tum derleme paketleri
# kurulu olmasina ragmen %build "eksik Python bagimliliklari"
# ile basarisiz oldu. Yani rpmbuild'de paketlemek icin Python
# modullerine ihtiyac yok.
#
# click/rich/yaml zaten `Requires:` altinda bildiriliyor.
make bpf go

%install
rm -rf %{buildroot}
make install PREFIX=%{_prefix} DESTDIR=%{buildroot}

# CLI giris noktasi: paket dizininden yukler
install -Dm 0755 packaging/axctl %{buildroot}%{_bindir}/axctl

# Ornek politikalar zaten /etc/axlinux altina kuruluyor

# systemd birimleri ve tmpfiles
install -Dm 0644 packaging/axdaemon.service \
    %{buildroot}%{_unitdir}/axdaemon.service
install -Dm 0644 packaging/axlog.service \
    %{buildroot}%{_unitdir}/axlog.service
# tmpfiles dosyasi MUTLAKA /usr/lib/tmpfiles.d altinda olmali.
# systemd yalnizca /etc, /run ve /usr/lib tmpfiles dizinlerini okur;
# /usr/share/tmpfiles.d okunmaz ve paylasilan /run/axlinux dizini
# olusmadigi icin servisler acilamiyordu.
install -Dm 0644 packaging/axlinux-tmpfiles.conf \
    %{buildroot}%{_prefix}/lib/tmpfiles.d/axlinux.conf

# SELinux drop-in: NoNewPrivileges, kendi alanina gecisi
# engelliyordu (status=203/EXEC). Gerekce 10-selinux.conf
# icinde.
install -Dm 0644 packaging/fedora/axdaemon.service.d/10-selinux.conf \
    %{buildroot}%{_unitdir}/axdaemon.service.d/10-selinux.conf
install -Dm 0644 packaging/fedora/axlog.service.d/10-selinux.conf \
    %{buildroot}%{_unitdir}/axlog.service.d/10-selinux.conf

# Belgeler
install -d %{buildroot}%{_docdir}/%{name}/docs
cp docs/*.md %{buildroot}%{_docdir}/%{name}/docs/ 2>/dev/null || :
install -Dm 0644 README.md DAGITIM.md CHANGELOG.md \
    %{buildroot}%{_docdir}/%{name}/ 2>/dev/null || :

# --- Sistem geneli politika dizini ---
# Boot aninda axdaemon buradaki *.yaml dosyalarini okuyup map'lere
# yazar. Once bu dizin HIC YOKTU: politika yalnizca axctl API'si
# uzerinden yukleniyordu, reboot sonrasi tum kurallar kayboluyordu.
# journald ust siniri (drop-in).
#
# journald varsayilani kotu dosya sisteminin %10'u (en fazla 4G);
# 20 GB'lik bir Workstation kurulumunda 2 GB. AXlinux'in kendi audit
# logu sinirli olsa bile isletim sistemi gunlugu sinirsiz kalirsa
# o sinir anlamsizlasir. Ana journald.conf DEGISTIRILMEZ; standart
# drop-in dizini kullanilir, yonetici dosyayi silerek geri alabilir.
install -Dm 0644 packaging/journald/10-axlinux.conf \
    %{buildroot}%{_sysconfdir}/systemd/journald.conf.d/10-axlinux.conf

install -d -m 0750 %{buildroot}%{_sysconfdir}/axlinux/policies.d
install -Dm 0644 packaging/fedora/axlinux-sample-workstation.yaml \
    %{buildroot}%{_sysconfdir}/axlinux/policies.d/00-sample-workstation.yaml

# --- SELinux ---
# Politika modulunun KURULMASI burada yapilmaz; kurulum sonrasi
# betiginde (selinux-setup.sh) yapilir. install.sh ile ayni betik.
#
# Burada ONCEDEN __semanage ile modul kuruluyordu. Fedora 44 rpm'inde
# o makro TANIMSIZ; rpm onu genisletemeden betige ham yaziyor ve
# "command not found" ile kurulum bolumunu dusuruyordu.
install -Dm 0755 packaging/fedora/selinux-setup.sh \
    %{buildroot}%{_prefix}/share/axlinux/selinux-setup.sh

# Modul + gelistirme dosyalari. Dosya listesi bunlari sayiyordu
# ama hic kurulmuyordu; rpm "File not found" ile basarisiz oluyordu.
install -Dm 0644 packaging/fedora/axlinux.pp \
    %{buildroot}%{_datadir}/selinux/packages/%{selinux_policy_name}.pp
install -Dm 0644 packaging/fedora/axlinux.fc \
    %{buildroot}%{_datadir}/selinux/%{selinux_policy_name}.fc
install -Dm 0644 packaging/fedora/axlinux.if \
    %{buildroot}%{_datadir}/selinux/devel/include/%{selinux_policy_name}.if

# --- systemd ---
# ldconfig cagrisi kaldirildi: paket paylasilabilir kutuphane icermiyor.

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
#
# ONCEDEN servisler burada hic baslatilmiyordu; %post yalnizca
# soketleri bekliyordu. Bu bir paketleme hatasi: rpm ile kurulan
# sistemde enforcement hic baslamiyor, kullanici elle
# "systemctl enable --now" demek zorunda kaliyordu.
if [ -x %{_prefix}/share/axlinux/selinux-setup.sh ]; then
    PREFIX=%{_prefix} %{_prefix}/share/axlinux/selinux-setup.sh || \
        echo "AXlinux: SELinux kurulumu basarisiz; enforcement etkisiz."
fi

# journald ust sinirini uygula.
#
# Burada sessizce sistem ayari degistirilmiyor: drop-in dosyasi
# paketle gelir, %config(noreplace) ile etiketlidir, operator
# gormesi icin mesal basildi ve istedigi an dosyayi silebilir.
if [ -f /etc/systemd/journald.conf.d/10-axlinux.conf ]; then
    systemctl restart systemd-journald 2>/dev/null || true
    echo "AXlinux: journald ust siniri etkin (200M / 1G bos birak)."
    echo "  geri almak icin: rm /etc/systemd/journald.conf.d/10-axlinux.conf"
fi

# Servisleri etkinlestir ve BASLAT. Sira onemli: SELinux modulu
# Once kurulmali, yoksa bpf() syscall'u reddedilir ve daemon
# LSM kancalarini baglayamaz.
# %systemd_enable yerine acik systemctl enable.
# Fedora macrosu "systemctl preset" calistirir; preset yalnizca
# systemd preset politikasinda varsayilan-acik isaretlenen
# birimleri etkinlestirir. Ozel birimlerimiz o listede olmadigi
# icin rpm ile kurulan sistemde servisler DISABLED kaliyordu ve
# yeniden baslatmada enforcement KAYBOLUYORDU.
#
# Bu bir zorunluluk: enforcement araci, boot sirasinda etkin
# olmak zorunda; aksi halde kural ihlalleri sessizce korumasiz
# kalir.
systemctl enable axdaemon.service
systemctl enable axlog.service
systemctl start axlog.service
systemctl start axdaemon.service

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
else
    echo "AXlinux: enforcement aktif, soketler hazir."
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

    # SIRA KRITIK - olculerek bulundu:
    #
    #   1) /usr/bin/axdaemon, axlog, axctl icin YEREL fcontext
    #      kayitlari silinir. Bunlari selinux-setup.sh uretir:
    #        set_fcontext axlinux_daemon_exec_t "$PREFIX/bin/axdaemon"
    #   2) semodule -r calistirilir.
    #
    # TERS SIRA CALISMIYOR. `semodule -r` modul tiplerini kaldirirken
    # KALAN yerel kayitlari dogrular. /usr/bin/axdaemon kaydi
    # axlinux_daemon_exec_t tipine bagli oldugu icin tipOnce
    # tanimsizlasiyor ve dogrulama basarisiz oluyor:
    #
    #   type axlinux_daemon_exec_t is not defined
    #     -> validate_handler: invalid context ... for /usr/bin/axdaemon
    #
    # Sonuc: modul KALIR, 3 fcontext kaydi SIZAR, 10 tip tanimli kalir.
    #
    # ESLESTIRME TUM SATIRA UYGULANIR, SADECE YOLA DEGIL.
    #
    # `awk '$1 ~ /axlinux/'` yalnizca YOL alanina bakar. Oysa
    # /usr/bin/axdaemon yolunda "axlinux" YOKTUR:
    #
    #   /usr/bin/axdaemon  all files  system_u:object_r:axlinux_daemon_exec_t:s0
    #                       ^^^^^^^^                              ^^^^^^
    #                       eslesmez                             eslesir
    #
    # Sonuc: en kritik uc yerel kayit hic listelenmiyor, silinmiyor ve
    # `semodule -r` onlar yuzunden basarisiz oluyor.
    #
    # Olcum (8 kayittan yalnizca 5'i yakalandi):
    #   yakalanan: /etc/axlinux, /run/axlinux, /usr/lib/axlinux/axbpf.o,
    #              /var/lib/axlinux, /var/log/axlinux
    #   KACIRILAN: /usr/bin/axctl, /usr/bin/axdaemon, /usr/bin/axlog
    if command -v semanage >/dev/null 2>&1; then
        semanage fcontext -l 2>/dev/null \
            | awk '/axlinux/ { print $1 }' \
            | while read -r _re; do
                  [ -n "$_re" ] && semanage fcontext -d "$_re" 2>/dev/null || :
              done
    fi
    command -v semodule >/dev/null 2>&1 && semodule -r axlinux 2>/dev/null || :
    command -v semanage >/dev/null 2>&1 && semanage module -r axlinux 2>/dev/null || :
fi

%postun
%systemd_postun_with_restart axdaemon.service
%systemd_postun_with_restart axlog.service

# Politika ve audit KALICI: kullanici verisidir. Silinmez.
# Servisler durdurulur, socket dosyalari ve __pycache__
# temizlenir.
rm -rf /usr/lib/axlinux/axctl/__pycache__ 2>/dev/null || :
rmdir /usr/lib/axlinux/axctl /usr/lib/axlinux 2>/dev/null || :

%files
%license LICENSE
%doc README.md
%doc DAGITIM.md
%doc CHANGELOG.md
%doc %{_docdir}/%{name}/docs
%{_bindir}/axdaemon
%{_bindir}/axlog
%{_bindir}/axctl
%{_usr}/lib/axlinux/axbpf.o
%{_usr}/lib/axlinux/axctl/
%dir %{_sysconfdir}/axlinux
%config(noreplace) %{_sysconfdir}/axlinux/*.yaml
# Politika dizini ve ornek. %config(noreplace): yonetici
# duzenlediginde rpm guncellemesi dosyayi EZMEZ.
%dir %{_sysconfdir}/systemd/journald.conf.d
%config(noreplace) %{_sysconfdir}/systemd/journald.conf.d/10-axlinux.conf
%dir %{_sysconfdir}/axlinux/policies.d
%config(noreplace) %{_sysconfdir}/axlinux/policies.d/*.yaml
%{_unitdir}/axdaemon.service
%{_unitdir}/axlog.service
%{_unitdir}/axdaemon.service.d/10-selinux.conf
%{_unitdir}/axlog.service.d/10-selinux.conf
%{_prefix}/lib/tmpfiles.d/axlinux.conf
%{_prefix}/share/axlinux/selinux-setup.sh

# SELinux modulu + gelistirme dosyalari
%{_datadir}/selinux/packages/%{selinux_policy_name}.pp
%{_datadir}/selinux/devel/include/%{selinux_policy_name}.if
%{_datadir}/selinux/%{selinux_policy_name}.fc

%changelog
* Fri Oct 02 2026 AXlinux Team <dev@axlinux.local> - 1.1.0-1
- Ilk RPM paketi. SELinux enforcing Fedora'da calisir.
- axdaemon ayri SELinux alanina tasindi; bpf() yetkisi
  yalnizca bu alana verilir.
- .deb ile ayni dosya duzeni.
