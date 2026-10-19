# ABYSS 🛡️
### Enterprise-Grade Hardware & Kernel Auditing Suite

> *"The gates of hell are open."*

**ABYSS** is an advanced security engineering framework written in pure **C**, tailored for security researchers and systems engineers. It is designed to inspect, analyze, and stress-test deep operating system and hardware components (Bare-Metal Firmware, Kernel Drivers, ACPI Tables, and KVM Hypervisors).

---

## 🏗️ Architecture & Core Modules

The system features a high-performance modular architecture:

1. **`main.c`**: Advanced CLI manager, global configuration handler, and daemon mode support.
2. **`fuzz.c`**: Driver IOCTL fuzzing engine with process sandboxing (`setrlimit`) and crash detection.
3. **`hyper.c`**: Lightweight Type-2 KVM-based hypervisor for VM-Exit interception, MSR, and PCI monitoring.
4. **`acpi.c`**: ACPI table parser and AML bytecode mutation engine for firmware vulnerability discovery.
5. **`ipc.c` / `shm_ipc_log.c`**: Atomic ring-buffer IPC and logging system via shared memory.
6. **`report.c`**: Comprehensive telemetry report generator supporting **JSON** and **HTML** formats.

---

## ⚙️ Prerequisites & Dependencies

To build and run the suite, a modern Linux environment with root/privilege capabilities and the following packages is required:
* **GCC** (C99 or newer)
* **Make**
* **KVM Kernel Support** (`/dev/kvm` available)

---

## 🛠️ Build & Installation

The project includes an enterprise-grade Makefile supporting multiple build profiles:

* **Build Release Version (Default):**
  ```bash
  make
  ```

* **Build Debug Version with symbols:**
  ```bash
  make debug
  ```

* **Build with Sanitizers (ASan & UBSan):**
  ```bash
  make sanitize
  ```

* **Install System-wide:**
  ```bash
  sudo make install
  ```

* **Uninstall:**
  ```bash
  sudo make uninstall
  ```

---

## 🚀 Usage & Command Line Options

Run the suite entirely or target specific modules:

```bash
./abyss [options]
```

### Options Guide:
* `-h, --help` : Show help message and exit.
* `-v, --verbose` : Enable verbose debugging logs.
* `-c, --config FILE` : Load an external configuration file.
* `-o, --output DIR` : Set output directory for reports (default: `./abyss_report`).
* `-f, --format FMT` : Report formats like `json,html`.
* `-d, --daemon` : Run the suite as a background daemon.
* `--hyper` : Enable hypervisor module only.
* `--acpi` : Enable ACPI engine module only.
* `--fuzz` : Enable driver fuzzer module only.
* `--all` : Enable all system modules sequentially.
* `--iter N` : Fuzzing iterations per IOCTL (default: 1000).
* `--timeout MS` : Child process timeout in milliseconds (default: 2000).
* `--shm NAME` : Shared memory segment name (default: `abyss_shm`).

### Examples:
1. **Run full audit with verbose logging:**
   ```bash
   ./abyss --all --verbose
   ```
2. **Run driver fuzzer only with 5000 iterations:**
   ```bash
   ./abyss --fuzz --iter 5000 -o /tmp/fuzz_results
   ```

---

## 🧪 Testing & Quality Assurance

Run smoke tests to verify output integrity:
```bash
make test
```

Check for memory leaks using Valgrind:
```bash
make valgrind
```

---

## 📄 License
This project is intended for scientific research, advanced penetration testing, and operating system auditing purposes only.