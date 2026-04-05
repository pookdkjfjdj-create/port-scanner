<p align="center">
  <strong><code>port-scanner</code></strong><br>
  <em>Fast TCP port scanner with service detection -- multi-threaded, zero deps.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python_3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-2ea44f?style=for-the-badge&logo=opensourceinitiative" alt="License">
  <img src="https://img.shields.io/badge/Dependencies-None-ff69b4?style=for-the-badge" alt="Zero deps">
</p>

---

## What It Does

Scans a host for open TCP ports. Detects 26 common services by name, attempts banner grabbing on unknown ports. Multi-threaded for speed.

## Quick Start

### Scan common ports

```bash
python -m port_scanner 192.168.1.1 --top
```

```
Scanning 192.168.1.1...

PORT     SERVICE
-------- --------------------
  22       SSH
  80       HTTP
  443      HTTPS
  3306     MySQL

4 open port(s)
Scan took 0.8s
```

### Full port range

```bash
python -m port_scanner 10.0.0.1 --range 1-65535
```

### Specific ports

```bash
python -m port_scanner myserver.com --ports 22,80,443,3000,8080
```

## Features

- 26 common ports pre-mapped to service names
- Banner grabbing on unknown open ports
- Multi-threaded (100 workers)
- Configurable range
- Zero dependencies

## License

MIT

<p align="center">
  <a href="https://github.com/pookdkjfjdj-create">@pookdkjfjdj-create</a>
</p>
