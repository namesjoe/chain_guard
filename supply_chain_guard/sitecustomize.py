
import sys
try:
    from supply_chain_guard import install
    install()
except ImportError:
    pass