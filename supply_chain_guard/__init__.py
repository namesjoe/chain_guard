import sys
import os
import importlib.util
from pathlib import Path

_guard_installed = False

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


class SafeLoader:
	"""Обертка над стандартным загрузчиком модулей (PEP 451)"""

	def __init__(self, real_loader, hook, fullname):
		self.real_loader = real_loader
		self.hook = hook
		self.fullname = fullname

	def __getattr__(self, name):
		return getattr(self.real_loader, name)

	def create_module(self, spec):
		if hasattr(self.real_loader, 'create_module'):
			return self.real_loader.create_module(spec)
		return None

	def exec_module(self, module):
		# Проверяем, это начало загрузки нового стороннего пакета или его под-модуль
		is_top_level = (self.hook.exec_depth == 0)
		self.hook.exec_depth += 1

		if is_top_level:
			self.hook.top_level_module = self.fullname
			self.hook.detected_in_chain = []
			sys.__stdout__.write(f"🔍 Checking: {self.fullname}")
			sys.__stdout__.flush()

			# Сохраняем оригиналы для манки-патчинга
			original_environ_get = os.environ.get
			original_environ_getitem = os.environ.__getitem__
			original_open = open

			def safe_environ_get(key, *args, **kwargs):
				if key in DANGEROUS_ENV_VARS and self.hook.top_level_module:
					self.hook.detected_in_chain.append(f"read env {key}")
				return original_environ_get(key, *args, **kwargs)

			def safe_environ_getitem(key):
				if key in DANGEROUS_ENV_VARS and self.hook.top_level_module:
					self.hook.detected_in_chain.append(f"read env {key}")
				return original_environ_getitem(key)

			def safe_open(path, *args, **kwargs):
				path_str = str(path) if not isinstance(path, str) else path
				path_str = os.path.expanduser(path_str)
				for danger in DANGEROUS_PATHS:
					if danger in path_str:
						self.hook.detected_in_chain.append(f"read file {path_str}")
						break
				return original_open(path, *args, **kwargs)

			# Применяем патчи
			os.environ.get = safe_environ_get
			os.environ.__getitem__ = safe_environ_getitem
			import builtins
			builtins.open = safe_open

		try:
			# Делегируем реальную загрузку модулю Python
			self.real_loader.exec_module(module)
		finally:
			self.hook.exec_depth -= 1
			if is_top_level:
				# Откатываем патчи
				os.environ.get = original_environ_get
				os.environ.__getitem__ = original_environ_getitem
				import builtins
				builtins.open = original_open
				self.hook.top_level_module = None

				# Если поймали малварь — выбрасываем исключение
				if self.hook.detected_in_chain:
					msg = " + ".join(self.hook.detected_in_chain)
					raise ImportError(f"⛔ {self.fullname} blocked!\n   {msg}")
				else:
					sys.__stdout__.write(f"   ✅ Safe\n")
					sys.__stdout__.flush()


class SafeImportHook:
	def __init__(self):
		self.exec_depth = 0
		self.top_level_module = None
		self.detected_in_chain = []

	def audit_hook(self, event, args):
		if not self.top_level_module:
			return

		if event in ("os.system", "subprocess.Popen"):
			command = args[0]
			self.detected_in_chain.append(f"process execution ({command})")
			raise PermissionError(f"ChainGuard: OS command execution blocked: {command}")

		elif event == "socket.connect":
			address = args[1] if len(args) > 1 else args[0]
			self.detected_in_chain.append(f"network connection to {address}")
			raise PermissionError(f"ChainGuard: Network connection blocked to {address}")

	def find_spec(self, fullname, path=None, target=None):
		if fullname.startswith('_') or fullname in sys.builtin_module_names:
			return None
		if fullname == 'supply_chain_guard' or fullname.startswith('supply_chain_guard.'):
			return None
		if fullname.startswith('pip') or fullname.startswith('setuptools'):
			return None

		spec = None
		# Проходим по всем остальным хукам и ищем спецификацию
		for finder in sys.meta_path:
			if finder is self:
				continue
			if hasattr(finder, 'find_spec'):
				spec = finder.find_spec(fullname, path, target)
				if spec:
					break

		if spec is None or spec.origin is None or getattr(spec, 'loader', None) is None:
			return None

		origin = spec.origin
		is_stdlib = (
					            '/lib/python' in origin or '/Framework/Python' in origin or 'lib\\python' in origin.lower()) and 'site-packages' not in origin

		# Для всех сторонних пакетов возвращаем нашу безопасную обертку (Custom Loader)
		if not is_stdlib:
			spec.loader = SafeLoader(spec.loader, self, fullname)
			return spec

		return None


def install():
	global _guard_installed
	if _guard_installed:
		return

	# Отключение защиты для служебных утилит (twine, build, etc.)
	if os.environ.get("CHAIN_GUARD_BYPASS") == "1":
		return

	hook = SafeImportHook()
	if not any(isinstance(h, SafeImportHook) for h in sys.meta_path):
		sys.meta_path.insert(0, hook)
		sys.addaudithook(hook.audit_hook)
		print("✅ Supply Chain Guard installed")
		_guard_installed = True


install()