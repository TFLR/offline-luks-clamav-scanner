#!/usr/bin/env bash
set -euo pipefail

# Offline LUKS + ClamAV scan:
# 1) optional freshclam
# 2) isolate network (hard=links down+IPv6 off, soft=iptables DROP)
# 3) open LUKS read-only, mount read-only
# 4) clamscan
# Default: hard isolation, no network restore at the end.

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
need(){ command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
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
		*) die "unknown option: $1";;
	esac
done

[ -n "$DEVICE" ] || die "--device is required"
need cryptsetup; need lsblk; need blkid; need mount; need umount; need clamscan
mkdir -p "$LOGDIR" "$MOUNT_BASE"

if [ "$NO_FRESHCLAM" -eq 0 ] && command -v freshclam >/dev/null 2>&1; then
	echo "[*] Updating signatures (freshclam)..."
	for i in 1 2 3; do
		if freshclam --verbose; then echo "[OK] freshclam"; break; fi
		echo "[WARN] attempt $i failed, retrying..."; sleep 2
	done
else
	echo "[*] freshclam skipped (offline or --no-freshclam)."
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

trap 'echo "[*] Cleaning up network..."; cleanup_net' EXIT

if [ "$ISOLATION" = "soft" ]; then
	need iptables
	echo "[*] Isolation SOFT: DROP INPUT/OUTPUT (lo allowed)."
	iptables-save > "$IPT_BACKUP"
	iptables -I INPUT 1 -i lo -j ACCEPT
	iptables -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	iptables -I INPUT 3 -m conntrack --ctstate NEW -j DROP
	iptables -I OUTPUT 1 -o lo -j ACCEPT
	iptables -I OUTPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	iptables -I OUTPUT 3 -j DROP
else
	echo "[*] Isolation HARD: down all non-lo interfaces + disable IPv6."
	sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
	sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
	ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' > "$IFLIST_FILE"
	while read -r IFACE; do
		[ -n "$IFACE" ] && ip link set dev "$IFACE" down || true
	done < "$IFLIST_FILE"
fi

echo "[*] Opening LUKS $DEVICE -> $MAP_NAME (readonly)..."
if [ -n "$KEYFILE" ]; then
	[ -f "$KEYFILE" ] || die "keyfile not found: $KEYFILE"
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
				echo "[OK] Mounted $dev ($fstype) on $mp"
				break
			fi
			;;
	esac
done < <(lsblk -ln -o PATH,FSTYPE | awk '/mapper/ {print $1, $2}')

[ -n "$MOUNT_POINT" ] || { echo "[x] no Linux FS mounted"; vgchange -an >/dev/null 2>&1 || true; cryptsetup luksClose "$MAP_NAME" || true; exit 5; }

TARGET="${MOUNT_POINT}${SCAN_SUBPATH%/}"
[ -e "$TARGET" ] || { echo "[x] path not found: $TARGET"; umount "$MOUNT_POINT" || true; vgchange -an >/dev/null 2>&1 || true; cryptsetup luksClose "$MAP_NAME" || true; exit 6; }

mkdir -p "$LOGDIR"
LOGFILE="${LOGDIR}/scan-$(basename "$DEVICE")-$(ts).log"
echo "[*] ClamAV scanning: $TARGET"
clamscan -r -i \
	--algorithmic-detection=yes --heuristic-alerts=yes --detect-pua=yes \
	--max-filesize="$MAX_FILESIZE" --max-scansize="$MAX_SCANSIZE" \
	--cross-fs=no --exclude-dir="^${MOUNT_POINT}/(proc|sys|dev|run|tmp|var/tmp)($|/)" \
	"$TARGET" | tee "$LOGFILE"
RET=${PIPESTATUS[0]:-0}

INF="${LOGDIR}/infected-$(ts).txt"
awk -F: '/FOUND$/ {print $1}' "$LOGFILE" > "$INF" || true
[ -s "$INF" ] && echo "[ALERT] $(wc -l < "$INF") infected file(s) — list: $INF" || echo "[OK] No infected file detected"

echo "[*] Unmounting & closing LUKS..."
umount "$MOUNT_POINT" || true
vgchange -an >/dev/null 2>&1 || true
cryptsetup luksClose "$MAP_NAME" || true

if [ "$RESTORE_NET" -eq 1 ]; then
	echo "[*] Restoring network (mode $ISOLATION)..."
fi
echo "[DONE] Log: $LOGFILE"
exit "$RET"
