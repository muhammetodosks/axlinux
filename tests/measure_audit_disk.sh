#!/bin/bash
# Dizin 0750 root:root; "ax" okuyamaz. Bu yuzden glob ROOT olarak
# genisletilmeli: sudo sh -c 'rm -f /var/log/axlinux/audit-*'
sudo systemctl stop axlog
sudo sh -c 'rm -f /var/log/axlinux/audit-*'
sudo systemctl start axlog
sleep 2
echo "  temiz baslangic:"
sudo ls -la /var/log/axlinux/ | grep audit | sed 's/^/    /' || echo "    (dizin bos)"
E="XDG_RUNTIME_DIR=/run/user/1001 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus"
B=$(sudo du -sb /var/log/axlinux | cut -f1)
echo "    taban: $B bayt"
echo
run() {
  label="$1"; n="$2"; shift 2
  for i in $(seq 1 "$n"); do "$@" >/dev/null 2>&1; done
  sleep 2
  A=$(sudo du -sb /var/log/axlinux | cut -f1)
  D=$((A-B))
  if [ "$D" -gt 0 ]; then
    printf "    %-26s %4d islem -> %8d bayt  (%6.1f bayt/islemin)\n" "$label" "$n" "$D" "$(python3 -c "print($D/$n)")"
  else
    printf "    %-26s %4d islem -> %8d bayt  (kayit YOK)\n" "$label" "$n" "$D"
  fi
  B=$A
}
echo "  --- olcum ---"
run "izinli okuma"       200 sudo -u axdesktop env $E head -c 100 /etc/hostname
run "ENGELLENEN okuma"    50 sudo -u axdesktop env $E cat /home/axdesktop/.gnupg/secret.gpg
run "engelli exec"        25 sudo -u axdesktop env $E md5sum /etc/hostname
run "izinli exec"         50 sudo -u axdesktop env $E /bin/true
echo
echo "  --- son dosyalar (rotasyon kaniti) ---"
sudo ls -la /var/log/axlinux/ | grep audit | awk '{printf "    %-32s %9d bayt\n", $NF, $5}'
echo "    TOPLAM: $(sudo du -sh /var/log/axlinux | cut -f1)"
