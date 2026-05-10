# chain_guard

## 🛡 Features

- **Import Interception:** Blocks unauthorized access to sensitive environment variables (e.g., `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`) during package initialization.
- **File System Guard:** Prevents third-party packages from reading sensitive files like `~/.ssh/id_rsa` or `~/.aws/credentials`.
- **OS-level Telemetry & Execution Prevention:** Uses Python's native Audit Hooks (PEP 578) to actively block remote code execution (`os.system`, `subprocess`) and reverse shell network connections (`socket.connect`) at the moment a suspicious package is imported.


Запуск
> python3 -m venv venv

> source venv/bin/activate

> pip install -e .

установка тестовых пакетов

> pip install -e test_package/clean_pkg

> pip install -e test_package/malware_pkg

> pip install -e test_package/sheep_package #имеет зависимость от 'вредоносного' wolf_package
