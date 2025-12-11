# Usage examples – offline-luks-clamav-scanner

This document shows **practical scenarios** for using `offline-luks-clamav-scanner.sh`.

The goal of the script is to:

1. Isolate the machine from the network (HARD or SOFT mode)
2. Open a **LUKS-encrypted partition** in **read-only**
3. Mount the filesystem in **read-only + noexec + nodev + nosuid**
4. Run **ClamAV** (`clamscan`) on a target path
5. Save a detailed log + list of infected files
6. Unmount, close LUKS, and optionally restore network

---

## 1. Basic workflow

Typical incident-response style usage:

1. Identify the LUKS partition you want to scan:
   ```bash
   lsblk -f


Example: `/dev/nvme0n1p3`

2. Make sure you have:

   * `cryptsetup`
   * `clamscan` (+ optional `freshclam`)
   * `lsblk`, `mount`, `umount`
   * Optional: `lvm2` (`vgchange`), `iptables`

3. Run the script as **root**:

   ```bash
   sudo ./offline-luks-clamav-scanner.sh --device /dev/nvme0n1p3
   ```

4. At the end, you get:

   * A **ClamAV log** file in `/tmp/clam-reports/scan-*.log`
   * A **list of infected files** in `/tmp/clam-reports/infected-*.txt`

> ⚠️ This script is meant for **defensive / IR use**.
> Use it only on systems and disks you are allowed to analyze.

---

## 2. Full “HARD” isolation + full filesystem scan

This is the “maximum paranoia” mode:

* All non-loopback interfaces go **down**
* IPv6 is disabled
* The LUKS partition is opened **read-only**
* The first Linux filesystem found is mounted **read-only** under `/mnt/target/...`
* ClamAV scans the whole filesystem (`/`)
* Network is restored at the end (`--restore-net`)

Example:

```bash
sudo ./offline-luks-clamav-scanner.sh \
  --device /dev/nvme0n1p3 \
  --isolation hard \
  --restore-net
```

What happens:

* `freshclam` runs (unless you use `--no-freshclam`)
* All non-`lo` interfaces are brought down
* LUKS is opened as `/dev/mapper/luksroot` (by default)
* First Linux FS (ext4/xfs/btrfs) inside is mounted read-only under `/mnt/target/<dev>`
* `clamscan` recursively scans the whole filesystem
* Infected files are listed in `infected-*.txt`
* FS is unmounted, LUKS is closed
* Network interfaces are brought back up

---

## 3. SOFT isolation (iptables DROP) + scan only `/home`

In some situations, you might want to keep the network technically up but blocked via iptables, and scan only a subset of the filesystem (for speed).

Example:

```bash
sudo ./offline-luks-clamav-scanner.sh \
  --device /dev/sda3 \
  --isolation soft \
  --path /home \
  --max-filesize 300M \
  --max-scansize 600M \
  --restore-net
```

Details:

* **SOFT isolation**:

  * `iptables` rules are inserted to DROP almost everything except `lo` and established connections
  * The original ruleset is saved and restored at the end
* Only `/home` (inside the mounted filesystem) is scanned
* Files larger than `300M` or exceeding `600M` of scan size are skipped

---

## 4. Offline scan (no freshclam), no network restore

On a machine with **no internet access** or where you **don’t want** to change signatures, you can skip `freshclam`.

Example:

```bash
sudo ./offline-luks-clamav-scanner.sh \
  --device /dev/mapper/cryptroot \
  --no-freshclam \
  --isolation hard
```

Notes:

* `freshclam` is **not** executed
* Network is isolated (interfaces down, IPv6 disabled)
* At the end, network is **not** restored automatically (since `--restore-net` is not used)

You can manually bring interfaces back up later if needed.

---

## 5. Using a LUKS keyfile

If your LUKS partition uses a **keyfile** instead of an interactive passphrase, you can pass it with `--keyfile`.

Example:

```bash
sudo ./offline-luks-clamav-scanner.sh \
  --device /dev/nvme0n1p3 \
  --keyfile /root/keys/luks-root.key \
  --isolation hard \
  --restore-net
```

The script will use:

```bash
cryptsetup luksOpen /dev/nvme0n1p3 luksroot --key-file /root/keys/luks-root.key --readonly
```

---

## 6. Log files and infected list

By default:

* Logs are stored under:
  `LOGDIR = /tmp/clam-reports`

You will typically see:

* `scan-<device>-<timestamp>.log`
  Full ClamAV output (paths, FOUND, etc.)

* `infected-<timestamp>.txt`
  Only the **list of infected file paths**, one per line.

Example:

```bash
ls -1 /tmp/clam-reports
# scan-nvme0n1p3-20250102-101500.log
# infected-20250102-101500.txt

cat /tmp/clam-reports/infected-20250102-101500.txt
# /mnt/target/nvme0n1p3/home/user/suspicious.exe
# /mnt/target/nvme0n1p3/var/tmp/malware.bin
```

You can change the log directory with:

```bash
--logdir /path/to/logs
```

---

## 7. Summary of useful options

* `--device /dev/...`
  **Mandatory**. LUKS partition/block device.

* `--path /subdir`
  Path **inside** the mounted filesystem to scan (default: `/`).

* `--map-name NAME`
  Name for the LUKS mapping (default: `luksroot`).

* `--keyfile /path/key`
  Use this file as the LUKS key instead of asking for a passphrase.

* `--no-freshclam`
  Do not run `freshclam` (no signature update).

* `--isolation hard|soft`

  * `hard` = bring interfaces down + disable IPv6
  * `soft` = use iptables DROP with minimal allow rules

* `--restore-net`
  Try to restore network config at the end (interfaces or iptables, depending on mode).

* `--max-filesize 200M`
  Max file size for ClamAV (default: `200M`).

* `--max-scansize 400M`
  Max data scanned per file by ClamAV (default: `400M`).

* `--logdir /path`
  Where to store logs (default: `/tmp/clam-reports`).

---

## 8. Safety notes

* The script **opens LUKS in read-only** and mounts the filesystem as:

  * `ro,noexec,nodev,nosuid`
* Network isolation is designed to avoid:

  * backdoors calling home during analysis,
  * lateral movement while you inspect a compromised system.
* Still, you should always:

  * Work from a trusted IR / analysis machine
  * Keep copies / images if you need full forensics
  * Treat infected systems as **untrusted** even after cleaning

Use at your own risk, and adapt the parameters (`--isolation`, `--no-freshclam`, paths) to your environment and procedures.
