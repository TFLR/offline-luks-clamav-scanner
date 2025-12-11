#!/usr/bin/env bash
set -euo pipefail

# ===== SCAN (freshclam -> isolate net -> LUKS RO -> mount RO -> clamscan) =====
# Default: HARD isolation (links down), NO network restore at the end.
# Options:
#   --device /dev/XXX       (obligatoire) partition LUKS
#   --path /dir             chemin relatif à la racine montée (def: /)
#   --map-name NAME         nom du mapping LUKS (def: luksroot)
#   --keyfile /path/key     keyfile LUKS (sinon passphrase)
#   --no-freshclam          ne pas télécharger les signatures
#   --isolation hard|soft   hard = liens réseau DOWN (def), soft = iptables DROP
#   --restore-net           réactive le réseau à la fin (par défaut: NON)
#   --max-filesize 200M     taille max fichier (def)
#   --max-scansize 400M     taille max scan (def)
#   --logdir /path          def: /tmp/clam-reports

DEVICE=""
SCAN_SUBPATH="/"
MAP_NAME="luksroot"
KEYFILE=""
NO_FRESHCLAM=0
ISOLATION="hard"
RESTORE_NET=0
MAX_FILESIZE="200M"
MAX_SCANSIZE="400M"
LOGDIR="/tmp/clam-reports"
MOUNT_BASE="/mnt/target"

die(){ echo "[x] $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "commande manquante: $1"; }
ts(){ date +%Y%m%d-%H%M%S; }

while [ $# -gt 0 ]; do
  case "$1" in
	--device) DEVICE="${2:-}"; shift 2;;
	--path) SCAN_SUBPATH="${2:-/}"; shift 2;;
	--map-name) MAP_NAME="${2:-luksroot}"; shift 2;;
	--keyfile) KEYFILE="${2:-}"; shift 2;;
	--no-freshclam) NO_FRESHCLAM=1; shift;;
	--isolation) ISOLATION="${2:-hard}"; shift 2;;
	--restore-net) RESTORE_NET=1; shift;;
	--max-filesize) MAX_FILESIZE="${2:-200M}"; shift 2;;
	--max-scansize) MAX_SCANSIZE="${2:-400M}"; shift 2;;
	--logdir) LOGDIR="${2:-/tmp/clam-reports}"; shift 2;;
	-h|--help)
	  cat <<EOF
Usage: $0 --device /dev/nvme0n1p3 [--path /home] [--map-name luksroot] [--keyfile file]
			 [--no-freshclam] [--isolation hard|soft] [--restore-net]
			 [--max-filesize 200M] [--max-scansize 400M] [--logdir /path]
EOF
	  exit 0;;
	*) die "option inconnue: $1";;
  esac
done

[ -n "$DEVICE" ] || die "--device est obligatoire"
need cryptsetup; need lsblk; need blkid; need mount; need umount; need clamscan
mkdir -p "$LOGDIR" "$MOUNT_BASE"

if [ "$NO_FRESHCLAM" -eq 0 ] && command -v freshclam >/dev/null 2>&1; then
  echo "[*] Mise à jour des signatures (freshclam)…"
  for i in 1 2 3; do
	if freshclam --verbose; then echo "[OK] freshclam"; break; fi
	echo "[WARN] tentative $i échouée, retry…"; sleep 2
  done
else
  echo "[*] freshclam SKIPPED (offline ou --no-freshclam)."
fi

IFLIST_FILE="/tmp/ifaces-$(ts).txt"
IPT_BACKUP="/tmp/iptables-$(ts).rules"

cleanup_net() {
  if [ "$ISOLATION" = "soft" ]; then
	[ -f "$IPT_BACKUP" ] && iptables-restore < "$IPT_BACKUP" || true
	rm -f "$IPT_BACKUP" || true
  elif [ "$ISOLATION" = "hard" ] && [ "$RESTORE_NET" -eq 1 ]; then
	if [ -f "$IFLIST_FILE" ]; then
	  while read -r IFACE; do
		[ -n "$IFACE" ] && ip link set dev "$IFACE" up || true
	  done < "$IFLIST_FILE"
	  rm -f "$IFLIST_FILE"
	fi
	sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
	sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
  fi
}

trap 'echo "[*] Nettoyage réseau..."; cleanup_net' EXIT

if [ "$ISOLATION" = "soft" ]; then
  need iptables
  echo "[*] Isolation SOFT: DROP INPUT/OUTPUT (lo autorisé)."
  iptables-save > "$IPT_BACKUP"
  iptables -I INPUT 1 -i lo -j ACCEPT
  iptables -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -I INPUT 3 -m conntrack --ctstate NEW -j DROP
  iptables -I OUTPUT 1 -o lo -j ACCEPT
  iptables -I OUTPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -I OUTPUT 3 -j DROP
else
  echo "[*] Isolation HARD: down de toutes les interfaces NON-lo + IPv6 off."
  # disable IPv6 runtime
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
  # list non-lo interfaces up
  ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' > "$IFLIST_FILE"
  while read -r IFACE; do
	[ -n "$IFACE" ] && ip link set dev "$IFACE" down || true
  done < "$IFLIST_FILE"
fi

echo "[*] Ouverture LUKS $DEVICE -> $MAP_NAME (readonly)…"
if [ -n "$KEYFILE" ]; then
  [ -f "$KEYFILE" ] || die "keyfile introuvable: $KEYFILE"
  cryptsetup luksOpen "$DEVICE" "$MAP_NAME" --key-file "$KEYFILE" --readonly
else
  cryptsetup luksOpen "$DEVICE" "$MAP_NAME" --readonly
fi

command -v vgchange >/dev/null 2>&1 && vgchange -ay || true

MOUNT_POINT=""
while read -r dev fstype; do
  case "$fstype" in
	ext2|ext3|ext4|xfs|btrfs)
	  mp="${MOUNT_BASE}/$(basename "$dev")"
	  mkdir -p "$mp"
	  if mount -o ro,noexec,nodev,nosuid "$dev" "$mp" 2>/dev/null; then
		MOUNT_POINT="$mp"
		echo "[OK] Monté $dev ($fstype) sur $mp"
		break
	  fi
	  ;;
  esac
done < <(lsblk -ln -o PATH,FSTYPE | awk '/mapper/ {print $1, $2}')

[ -n "$MOUNT_POINT" ] || { echo "[x] aucun FS Linux monté"; vgchange -an >/dev/null 2>&1 || true; cryptsetup luksClose "$MAP_NAME" || true; exit 5; }

TARGET="${MOUNT_POINT}${SCAN_SUBPATH%/}"
[ -e "$TARGET" ] || { echo "[x] chemin introuvable: $TARGET"; umount "$MOUNT_POINT" || true; vgchange -an >/dev/null 2>&1 || true; cryptsetup luksClose "$MAP_NAME" || true; exit 6; }

mkdir -p "$LOGDIR"
LOGFILE="${LOGDIR}/scan-$(basename "$DEVICE")-$(ts).log"
echo "[*] ClamAV va scanner: $TARGET"
clamscan -r -i \
  --algorithmic-detection=yes --heuristic-alerts=yes --detect-pua=yes \
  --max-filesize="$MAX_FILESIZE" --max-scansize="$MAX_SCANSIZE" \
  --cross-fs=no --exclude-dir="^${MOUNT_POINT}/(proc|sys|dev|run|tmp|var/tmp)($|/)" \
  "$TARGET" | tee "$LOGFILE"
RET=${PIPESTATUS[0]:-0}

INF="${LOGDIR}/infected-$(ts).txt"
awk -F: '/FOUND$/ {print $1}' "$LOGFILE" > "$INF" || true
[ -s "$INF" ] && echo "[ALERT] $(wc -l < "$INF") fichier(s) infecté(s) — liste: $INF" || echo "[OK] Aucun fichier infecté"

echo "[*] Démontage & fermeture LUKS…"
umount "$MOUNT_POINT" || true
vgchange -an >/dev/null 2>&1 || true
cryptsetup luksClose "$MAP_NAME" || true

if [ "$RESTORE_NET" -eq 1 ]; then
  echo "[*] Restauration réseau (mode $ISOLATION)…"
fi
echo "[DONE] Log: $LOGFILE"
exit "$RET"
