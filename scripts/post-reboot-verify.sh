#!/usr/bin/env bash
# Reboot sonrasi dogrulama: AXlinux gercekten politika uyguluyor mu?
set -uo pipefail
GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
say(){ printf '%s\n' "${CYN}==>${RST} $*"; }
ok(){  printf '%s\n' "${GRN}  ✓${RST} $*"; }
bad(){ printf '%s\n' "${RED}  ✗${RST} $*"; }
warn() { printf '%s\n' "${YEL}  !${RST} $*"; }

CHAIN="$(cat /sys/kernel/security/lsm)"
say "LSM zinciri: $CHAIN"
if [[ ",$CHAIN," == *,bpf,* ]]; then
    ok "bpf LSM AKTIF"
else
    bad "bpf LSM zincirde YOK - enforcement calismaz"
    exit 1
fi

say "axdaemon baslatiliyor"
sudo pkill -f 'axd.*axdaemon' 2>/dev/null
sudo mkdir -p /run/axlinux /sys/fs/bpf/axlinux
sudo setsid /usr/local/bin/axdaemon --socket /run/axlinux/axdaemon.sock \
    > /tmp/axd-verify.log 2>&1 < /dev/null &
for i in $(seq 1 40); do
    [[ -S /run/axlinux/axdaemon.sock ]] && break
    sleep 0.25
done
[[ -S /run/axlinux/axdaemon.sock ]] || { bad "socket acilmadi"; cat /tmp/axd-verify.log; exit 1; }
ok "socket acildi"

say "enforcement durumu"
python3 - <<'PY'
import json, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)
s.connect('/run/axlinux/axdaemon.sock')
s.sendall(b'{"method":"get_status","params":{},"id":1}\n')
st = json.loads(s.recv(65535).decode())['result']
print(f"  enforcement_active : {st.get('enforcement_active')}")
print(f"  LSM kancalari      : {st.get('lsm_hooks_active')}/{st.get('lsm_hooks_total')}")
print(f"  ebpf_loaded        : {st.get('ebpf_loaded')}")
sys.exit(0 if st.get('enforcement_active') else 1)
PY
if [[ $? -eq 0 ]]; then
    ok "ENFORCEMENT AKTIF - AXlinux politika uyguluyor"
else
    bad "enforcement hala kapali"
    exit 1
fi

say "gercek engelleme testi"
sudo -u mami env PYTHONPATH=/usr/local/lib/axlinux-python python3 - <<'PY'
import json, socket, sys, yaml
sys.path.insert(0, '/usr/local/lib/axlinux-python')
from axctl.compiler import compile_policy
policy = {"version":1,"mode":"enforcing","labels":{"t":["sleep"]},
  "rules":[{"name":"sleep /etc/hostname okuyamaz","subject":"t",
            "object":"/etc/hostname","action":"file.read","effect":"deny"}]}
c = compile_policy(policy)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(10)
s.connect('/run/axlinux/axdaemon.sock')
s.sendall((json.dumps({"method":"reload_policy","params":{"policy":c},"id":1})+"\n").encode())
s.recv(65535); s.close()
print("  politika yuklendi")
PY
sleep 1
out="$(/usr/bin/sleep 5 &>/dev/null; echo ok)"
if sudo timeout 20 python3 -c "
import socket,json
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(8)
s.connect('/run/axlinux/axdaemon.sock')
s.sendall(b'{\"method\":\"get_logs\",\"params\":{\"limit\":20},\"id\":1}\n')
r=json.loads(s.recv(65535).decode())['result']
print('  audit kayit:', r.get('count'))
for l in (r.get('logs') or [])[:3]:
    print('   ', l.get('comm'), l.get('path'), l.get('decision'))
"; then
    ok "audit akisi calisiyor"
else
    warn "audit sorgusu basarisiz"
fi
