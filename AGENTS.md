# AXlinux — Çalışma Standardı

Bu dosya, bu depoda çalışırken uyulacak **kalıcı** kuralları içerir.
Bir sonraki oturum bunları okumalı ve aynı standardı uygulamalıdır.

---

## 1. Hatasız, eksiksiz, engelsiz

Bu projede varsayılan kabul edilemez:

- **Bir hata bırakma.** Bir hata bulursan kapat, sonra kanıtını göster.
  "Kullanıcı şunu da dener" diye bırakma.
- **Eksik bırakma.** Yarım uygulama, "TODO", "Manuel yapılacak" notu kabul edilemez.
  Ya düzeltilir ya da iddia metinden çıkarılır.
- **Engel diye bir şey bırakma.** Zor, pahalı veya zahmetli olan bir adım için
  "bu engeldir" deme. Her adım için yol bul; bulamıyorsan daha derin ara.
- **Kalıcı düzelt.** Yüzeysel yamalar değil, kök nedeni kapat.
  Bir hatayı iki kez düzeltme ihtiyacı doğuyorsa ilk düzeltme yanlıştır.

## 2. Her iddia kanıt ister

Belgeye yazılan her sayı, her "çalışıyor", her "destekleniyor" ifadesi
**ölçülmüş** olmak zorundadır.

- Belgede **"doğrulanmadı"** yazan bir kalem kalmayacak.
- Kanıt üretemediğin bir şeyi iddia etme; iddiayı kaldır.
- Test yazdıysan **gerçekten koş**. Yazılmış test koşulmamış test değildir.
- CI'a yazdığın işi **lokal olarak da koş**. CI'ın çalıştığına güvenme —
  bu projede tam da öyle bir hata yakalandı (aşağıda).

## 3. Doğrulama yöntemi

Sıralama her zaman: **ölç → kök nedeni bul → düzelt → yeniden ölç.**

- Teorik cevap yerine **deney**. Varsayım doğrulama değildir.
- Üretim kodundan gözlemle bulunan hatalar en değerlisidir; yazılmış
  testlerden çok daha fazla gerçek hata çıkar.
- Bir sayı "bekleniyor" diyorsa, ölçüm sonucunu **beklenen** ile karşılaştır.
  Ölçüm mantığı yanlışsa üretim kodunda da hata olabilir.
- Bir çelişki görürsen (iki belge birbirini tutmuyorsa) belgelerden birini
  seçme — **üçüncüyü ölç**: hangisi doğru?

## 4. Ortam kısıtı

- Ana makinede (`/dev/sdb1`) AXlinux **çalıştırılmayacak**.
- Her enforcement testi `/mnt/anka` altındaki VM'de yapılacak.
- Konteyner içinde BPF LSM çalışmaz; içerik doğrulaması (`deep_verify.sh`)
  sanal makine gerektirir. Bu sınır bilinçlidir ve CI çıktısında
  `::warning::` ile belirtilmelidir.

## 5. Raporlama

- Ne ölçüldü, ne değişti, nerede doğrulandı — üçünü de yaz.
- Bir şeyin doğrulanmadığını **açıkça** yaz. Doğrulanmadığını saklayan
  rapor, doğrulanmış gibi davranan rapordan daha kötüdür.
- Kullanıcının "her şey tamam mı?" sorusu bir kalem doğrulanmamışsa
  cevap "evet" değildir; önce doğrula.

---

## 6. Bu depada öğrenilen somut dersler

Bunlar kalıcıdır; tekrar etme.

| Ders | Nerede |
|------|--------|
| `__builtin_memset` 256 bayttan büyük yapılarda BPF libcall'e düşer ve program yüklenmez | `axbpf.h` → `ax_event_clear()` |
| Olay boyutu büyürse per-CPU perf tamponu yetmez, kernel **sessizce** kayıt düşürür | `perf.NewReader(em, 65536)` + `LostSamples` |
| Olay yapısı C ve Go'da elle yazılır; sapma **sessizdir** | `TestEventLayoutMatchesC` her koşuda ölçer |
| `axbpf.o` RPM'de ayrı dosyadır; Go ikilisi ile **birlikte** güncellenmeli | ayrı ölçüm kapısı |
| `semanage delete` geçerli alt komut **değildir** | `axlinux.spec` %preun |
| `semanage fcontext -l` çıktısı TAB değil **boşlukla** hizalıdır | `awk '$1 ~ /axlinux/'` → `awk '/axlinux/'` |
| RPM paket dosyalarını `%postun`'dan **önce** siler; modül kaldırma `%preun`'da olmalı | `axlinux.spec` |
| `fcontext -l` doğrulama yapar ve geçersiz kayıtları **atlar** | ham liste kullan |
| SELinux modül kaldırmada sıra: fcontext kayıtları **önce**, modül sonra | ters sıra çalışmaz |
| `parse_args()` tanımlıydı ama **hiç çağrılmıyordu**; tüm bayraklar sessizce yok sayılıyordu | `install.sh` |
| `make rpm` çalışma zamanı Python modüllerini gereksiz yere arıyordu | `rpm: bpf go`, spec `%build: make bpf go` |
| Kod yazıp koşmamak en pahalı hatadır; CI işini lokal koş | `packaging` matrisi |