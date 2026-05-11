# supply_chain_guard https://pypi.org/project/supply-chain-guard/

## 🛡 Features

- **Import Interception:** Blocks unauthorized access to sensitive environment variables (e.g., `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`) during package initialization.
- **File System Guard:** Prevents third-party packages from reading sensitive files like `~/.ssh/id_rsa` or `~/.aws/credentials`.
- **OS-level Telemetry & Execution Prevention:** Uses Python's native Audit Hooks (PEP 578) to actively block remote code execution (`os.system`, `subprocess`) and reverse shell network connections (`socket.connect`) at the moment a suspicious package is imported.

## 🚀 Installation

Install the package via pip:
```bash
pip install supply-chain-guard
```
## 🛡️ Usage

### Option 1: Direct Import
Import the guard at the very first line of your entry point script (main.py, app.py, etc.) to protect your application:

```python
import supply_chain_guard  # Protection starts here
import requests
# ... your other imports
```

### Option 2: Protect Environment
1. Run in your environment 'setup_protection.sh' it will make your repository protected as long as you use this (virtual) environment
```bash
chmod +x ./setup_protection.sh
```
2. Execute setup_protection.sh
```bash
./setup_protection.sh
``` 


### Option 3: Protecting Jupyter Notebook Servers

If you manage a Jupyter server for students or a team, you can enforce security globally. This ensures that every notebook is protected, even if users try to install malicious packages themselves.

#### Steps for Administrator:

1. Install the package in the Python environment used by your Jupyter server:
   ```bash
   pip install supply-chain-guard
   ```

2. Get the startup directory for IPython Notebook
   ```bash
   python -c "from IPython import get_ipython; print(get_ipython().profile_dir.startup_dir)"
   ```

3. Create '0_force_imports.py' 
   ```python
    # ~/.ipython/profile_default/startup/force_imports.py
    try:
        import supply_chain_guard
        print("✅ Supply Chain Guard installed")
    except ImportError as e:
        print(f"⚠️  Import Not implemented: {e}") 
   ```
4. Restart IPyhton Notebook Server and it will force 'supply_chain_guard' to all kernels of Jupyter


## Installation by hand
> python3 -m venv venv

> source venv/bin/activate

> pip install -e .

установка тестовых пакетов

> pip install -e test_package/clean_pkg

> pip install -e test_package/malware_pkg

> pip install -e test_package/sheep_package #имеет зависимость от 'вредоносного' wolf_package
