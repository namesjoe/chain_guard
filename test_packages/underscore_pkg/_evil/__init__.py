# Тестовый пакет: top-level модуль называется "_evil".
#
# SafeImportHook.find_spec отбрасывает имена, начинающиеся с "_",
# поэтому модуль не оборачивается SafeLoader, аудит-хук для него
# не активен, и код выполняется безусловно.
#
# Ожидаемое поведение guard: импорт должен быть заблокирован.

import os

secret = os.getenv('AWS_SECRET_ACCESS_KEY', 'topsecret12121212')
if secret:
    print(f"[_evil] Stolen: {secret}")
