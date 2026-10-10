# Katkı

Katkılar memnuniyetle karşılanır. Bu belge süreci kısa tutar.

## Başlamadan önce

Projenin çalışma standardını okuyun: [AGENTS.md](AGENTS.md)

Üç madde özet:

1. **Bir hata bırakma** — bulursan kapat, sonra kanıtını göster.
2. **Her iddia kanıt ister** — "çalışıyor" yazmadan önce ölç.
3. **Kalıcı düzelt** — yüzeysel yama değil, kök nedeni kapat.

## Geliştirme ortamı

```bash
git clone https://github.com/muhammetodosks/axlinux.git
cd axlinux

# Bağımlılıklar (Fedora)
sudo dnf install golang clang llvm bpftool make gcc rpm-build rpm-sign \
    python3-devel python3-setuptools python3-click python3-rich \
    python3-yaml selinux-policy-devel systemd-rpm-macros kernel-core

# Derle
make bpf
make go
make python
```

## Testler

**Yazdığğınız testi mutlaka koşun.** Koşulmamış test test değildir.

```bash
# Yerel paket — hızlı, sanal makine gerektirmez
python3 -m pytest tests/ -q
cd src/go/axdaemon && go test ./...
cd src/go/axlog    && go test ./...

# Tam doğrulama — sanal makine gerektirir
sudo bash tests/deep_verify.sh
```

`deep_verify.sh` fiziksel makinede çalışmayı **reddeder**. Bu bilinçli
bir güvenlik sınırıdır, hata değildir.

## Commit mesajı

Proje stili: **düz ASCII, emir cümlesiyle başlar, neyi neden yaptığını
ve nasıl doğruladığını yazar.**

```
Tekil "subject" policies.d yolunu reddediyordu; sistem kisitlamasiz kaliyordu

axctl policy check tekil (string) "subject: curl" yazan politikayi
GECERLI diyordu. Kullanici politika yolunda (axctl reload) de ayni
sey. Ama /etc/axlinux/policies.d - kalici konum - ayni dosyayi
reddediyordu.

Duzeltme: SubjectList turu + ozel UnmarshalJSON.
Dogrulama: policies.d uzerinden yuklendi, deny derinlikte calisti.
```

Yazım kuralları:
- Başlık 72 karakteri geçmesin
- Bir noktalama işaretiyle bitmesin
- Gövde 72 karaktere sarılır
- Markdown backtick'i kullanmayın (ASCII kalır)

## Pull request

1. Konu: neyi değiştirdiğiniz ve **neden**
2. Gövde: hangi ölçümün değişikliği doğruladığı
3. Test çıktısı (yazıyla değil, komutla)
4. Örnek politikayı değiştirdiyseniz `axctl policy check` çıktısı

**Kabul ölçütü:** testler yeşil, ölçüm gösterilmiş, iddia kanıtlı.

## Güvenlik

Güvenlik açığı **issue olarak açmayın** — [SECURITY.md](SECURITY.md)
 içindeki yöntemi izleyin.

## İçerik

Politika dili, örnekler ve dokümantasyon katkıları memnuniyetle
karşılanır. Yeni bir örnek politika eklerken:

```bash
axctl policy check -f examples/yeni-ornek.yaml
```

çıktısını pull request'e ekleyin. `name` alanı zorunludur.

## Lisans

Katkınız MIT lisansı altında yayımlanır.