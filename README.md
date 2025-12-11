# offline-luks-clamav-scanner

`offline-luks-clamav-scanner.sh` is a Bash script to safely scan a **LUKS-encrypted Linux partition** for malware using **ClamAV**, in a controlled and mostly offline way.

Typical use case: **incident response / forensics** on a compromised system or disk.

The script:

- isolates the machine from the network (HARD or SOFT mode),
- opens the LUKS device **read-only**,
- mounts the filesystem **read-only + noexec + nodev + nosuid**,
- runs `clamscan` on a chosen path,
- writes logs and a list of infected files,
- unmounts and closes the LUKS mapping,
- optionally restores network configuration.

---

## Features

- 🔐 **LUKS read-only mount**
  - Uses `cryptsetup luksOpen` with `--readonly`
  - Optional keyfile support (`--keyfile`)
  - LVM activation (`vgchange -ay`) if needed

- 🌐 **Network isolation**
  - `--isolation hard`
    - brings all non-loopback interfaces **down**
    - temporarily disables IPv6
  - `--isolation soft`
    - uses `iptables` to DROP almost all traffic, keeping only `lo` and established connections
  - `--restore-net` to bring network back at the end (interfaces or iptables rules)

- 📁 **Safe filesystem mount**
  - Mounts the first Linux filesystem found (ext4/xfs/btrfs) as:
    - `ro,noexec,nodev,nosuid`
  - Mount point under `/mnt/target/<device>`

- 🦠 **ClamAV scanning**
  - Optional signature update via `freshclam` (can be skipped with `--no-freshclam`)
  - Recursive `clamscan` on the selected path
  - Extra options:
    - `--algorithmic-detection`
    - `--heuristic-alerts`
    - `--detect-pua`
    - `--max-filesize` and `--max-scansize`
    - basic cross-fs and tmp dirs exclusions

- 📝 **Reports**
  - Full ClamAV output written to a log file
  - Flat list of infected files extracted to `infected-*.txt`
  - Log directory configurable (`--logdir`)

---

## Requirements

You should run this script as **root**.

Dependencies:

- `bash`
- `cryptsetup`
- `lsblk`
- `blkid`
- `mount` / `umount`
- `clamscan` (ClamAV)
- `freshclam` (optional, for signature updates)
- `ip` / `ip link`
- `sysctl`
- `iptables` (for `--isolation soft`)
- `vgchange` (optional, for LVM volumes)

The script is meant to run on a **Linux** incident-response / admin host with these tools installed.

---

## Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/<your-user>/offline-luks-clamav-scanner.git
cd offline-luks-clamav-scanner

chmod +x offline-luks-clamav-scanner.sh
````

You can then run it from this directory or copy it into a directory in your `$PATH`.

---

## Basic usage

### Minimal example (HARD isolation, full FS scan)

```bash
sudo ./offline-luks-clamav-scanner.sh \
  --device /dev/nvme0n1p3 \
  --isolation hard \
  --restore-net
```

This will:

1. (Optionally) run `freshclam` to update signatures.
2. Apply **HARD** isolation:

   * bring non-loopback interfaces down
   * disable IPv6 during the scan
3. Open `/dev/nvme0n1p3` as a LUKS device in **read-only**.
4. Mount the first Linux filesystem (ext4/xfs/btrfs) found in **RO + noexec + nodev + nosuid**.
5. Run `clamscan` recursively on the whole filesystem.
6. Write:

   * a log file: `scan-<device>-<timestamp>.log`
   * a list of infected files: `infected-<timestamp>.txt`
7. Unmount, close LUKS, deactivate LVM and **restore network**.

### Scan only a subpath (e.g. `/home`) with SOFT isolation

```bash
sudo ./offline-luks-clamav-scanner.sh \
  --device /dev/sda3 \
  --path /home \
  --isolation soft \
  --restore-net
```

* Uses iptables-based isolation (INPUT/OUTPUT DROP, `lo` allowed).
* Only `/home` inside the mounted filesystem is scanned.

### Offline / air-gapped scan (no freshclam)

```bash
sudo ./offline-luks-clamav-scanner.sh \
  --device /dev/mapper/cryptroot \
  --no-freshclam \
  --isolation hard
```

* Skips signature update.
* HARD isolation.
* Does **not** restore network unless `--restore-net` is specified.

---

## Command-line options

From `--help`:

```text
--device /dev/XXX       (required) LUKS partition or block device
--path /dir             path inside the mounted filesystem (default: /)
--map-name NAME         LUKS mapping name (default: luksroot)
--keyfile /path/key     LUKS keyfile (otherwise passphrase is prompted)
--no-freshclam          do not run freshclam (no signature updates)
--isolation hard|soft   hard = bring interfaces down (default), soft = iptables DROP
--restore-net           try to restore network at the end
--max-filesize 200M     max file size for clamscan (default: 200M)
--max-scansize 400M     max scan size per file (default: 400M)
--logdir /path          log directory (default: /tmp/clam-reports)
-h, --help              show help
```

---

## Logs & infected files

By default, logs are stored in:

```text
/tmp/clam-reports
```

You will typically get:

* `scan-<device>-<timestamp>.log`
  → full ClamAV output

* `infected-<timestamp>.txt`
  → list of infected files (one path per line)

You can change the log directory with:

```bash
--logdir /path/to/logs
```

---

## Examples

More concrete usage examples are available in:

```text
examples/usage.md
```

---

## Safety notes & disclaimer

* The script opens the LUKS device **read-only** and mounts with:

  * `ro,noexec,nodev,nosuid`
* It is designed for **defensive / incident response** purposes, not for offensive use.
* Always work from a **trusted** machine when analyzing a compromised disk.
* Use it only on systems and disks you are **authorized** to access.
* Even after cleaning, a compromised system should still be treated as **untrusted** until fully reinstalled or properly remediated.
