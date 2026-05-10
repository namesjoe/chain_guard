import sys
import os
import importlib.util
from pathlib import Path

DANGEROUS_ENV_VARS = {
	'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID',
	'GITHUB_TOKEN', 'GITHUB_PAT',
	'OPENAI_API_KEY', 'STRIPE_API_KEY',
	'DATABASE_PASSWORD', 'DATABASE_URL',
	'PRIVATE_KEY', 'SECRET_KEY',
	'ENCRYPTION_KEY', 'JWT_SECRET',
}

DANGEROUS_PATHS = {
	'/.ssh', '/.aws', '/.config/gcloud',
	'/.github', '/.kube',
	'/root/.ssh', '/root/.aws',
}


class SafeImportHook:
	"""Мониторит импорты и их зависимости"""

	def __init__(self):
		self.depth = 0
		self.top_level_module = None
		self.detected_in_chain = []

	def audit_hook(self, event, args):
		"""
		Нативный перехват системных вызовов ОС (PEP 578).
		Срабатывает только во время инициализации стороннего модуля.
		"""
		if not self.top_level_module:
			return

		# Перехват запуска подозрительных процессов
		if event in ("os.system", "subprocess.Popen"):
			command = args[0]
			self.detected_in_chain.append(f"process execution ({command})")
			# БЛОКИРУЕМ выполнение на уровне интерпретатора!
			raise PermissionError(f"ChainGuard: OS command execution blocked: {command}")

		# Перехват исходящих сетевых соединений
		elif event == "socket.connect":
			address = args[1] if len(args) > 1 else args[0]
			self.detected_in_chain.append(f"network connection to {address}")
			# БЛОКИРУЕМ выполнение сети!
			raise PermissionError(f"ChainGuard: Network connection blocked to {address}")

	def find_spec(self, fullname, path=None, target=None):
		if fullname.startswith('_') or fullname in sys.builtin_module_names:
			return None

		if fullname == 'supply_chain_guard' or fullname.startswith('supply_chain_guard.'):
			return None

		if fullname.startswith('pip') or fullname.startswith('setuptools'):
			return None

		# Только top-level модули
		if '.' in fullname:
			return None

		self.depth += 1

		try:
			# Находим spec
			spec = None
			for finder in sys.meta_path:
				if finder is self:
					continue
				if hasattr(finder, 'find_spec'):
					spec = finder.find_spec(fullname, path, target)
					if spec:
						break

			if spec is None or spec.origin is None:
				return None

			origin = spec.origin
			is_stdlib = (
						            '/lib/python' in origin or '/Framework/Python' in origin or 'lib\\python' in origin.lower()) and 'site-packages' not in origin

			# Только third-party пакеты на уровне 1 (прямой импорт)
			if self.depth == 1 and not is_stdlib:
				print(f"🔍 Checking: {fullname}")
				self.top_level_module = fullname
				self.detected_in_chain = []

				# Мониторим
				self._monitor_import(fullname, spec)

				if self.detected_in_chain:
					msg = " + ".join(self.detected_in_chain)
					raise ImportError(f"⛔ {fullname} blocked!\n   {msg}")

				print(f"   ✅ Safe\n")
				self.top_level_module = None

			return None
		finally:
			self.depth -= 1

	def _monitor_import(self, fullname, spec):
		"""Мониторим весь импорт и зависимости"""
		original_environ_get = os.environ.get
		original_environ_getitem = os.environ.__getitem__
		original_open = open

		def safe_environ_get(key, *args, **kwargs):
			if key in DANGEROUS_ENV_VARS and self.top_level_module:
				self.detected_in_chain.append(f"read env {key}")
			return original_environ_get(key, *args, **kwargs)

		def safe_environ_getitem(key):
			if key in DANGEROUS_ENV_VARS and self.top_level_module:
				self.detected_in_chain.append(f"read env {key}")
			return original_environ_getitem(key)

		def safe_open(path, *args, **kwargs):
			path_str = str(path) if not isinstance(path, str) else path
			path_str = os.path.expanduser(path_str)

			for danger in DANGEROUS_PATHS:
				if danger in path_str:
					self.detected_in_chain.append(f"read file {path_str}")
					break
			return original_open(path, *args, **kwargs)

		os.environ.get = safe_environ_get
		os.environ.__getitem__ = safe_environ_getitem
		import builtins
		builtins.open = safe_open

		try:
			module = importlib.util.module_from_spec(spec)
			sys.modules[fullname] = module
			spec.loader.exec_module(module)
		finally:
			os.environ.get = original_environ_get
			os.environ.__getitem__ = original_environ_getitem
			builtins.open = original_open


def install():
	hook = SafeImportHook()
	if not any(isinstance(h, SafeImportHook) for h in sys.meta_path):
		sys.meta_path.insert(0, hook)

		# Активируем хук безопасности на уровне ОС
		sys.addaudithook(hook.audit_hook)

		print("✅ Supply Chain Guard installed")


install()