import os, time, statistics

N = 400
files = ["/etc/hostname", "/etc/hosts", "/etc/passwd", "/etc/group", "/etc/os-release"]

def bench(label):
    # isinma
    for f in files:
        for _ in range(20):
            open(f, "rb").read(1)
    per_open = []
    for f in files:
        lat = []
        for _ in range(N // len(files)):
            t0 = time.perf_counter_ns()
            with open(f, "rb") as fh:
                fh.read(1)
            lat.append((time.perf_counter_ns() - t0) / 1000.0)  # mikrosaniye
        per_open.append(statistics.mean(lat))
    overall = sum(per_open) / len(per_open)
    print("  %-22s ortalama %8.1f us/acma   medyan %8.1f us   (n=%d acma/dosya)"
          % (label, overall, statistics.median(per_open), N // len(files)))
    return overall

on = bench("LSM KANCALARI ACIK")
