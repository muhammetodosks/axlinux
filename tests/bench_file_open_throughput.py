import os, time, sys

# Gercekci masaustu is yuku: kucuk dosyalari tekrarli acma.
# GNOME bir oturum acilirken yuzlerce, Firefox acilirken binlerce
# dosya acar. 50.000 acma, agir bir tarayici acilisini temsil eder.
N = 50000
src = open("/etc/hostname","rb").read()

tmp = "/tmp/axbench-data.bin"
with open(tmp,"wb") as f: f.write(src)

t0 = time.perf_counter()
for _ in range(N):
    fd = os.open(tmp, os.O_RDONLY)
    os.close(fd)
el = time.perf_counter() - t0
os.unlink(tmp)
print("      %6d acma toplam %7.3f sn  -> %8.2f us/acma  (%9.0f acma/sn)"
      % (N, el, el/N*1e6, N/el))
