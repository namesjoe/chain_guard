#!/bin/bash

echo "🚀 Installing supply-chain-guard..."

pip install supply-chain-guard --quiet

python -c "
import site, os
sp = site.getsitepackages()[0]
pth = os.path.join(sp, 'supply_chain_guard.pth')
with open(pth, 'w') as f:
    f.write('import supply_chain_guard\n')
print(f'✅ Protection enabled: {pth}')
"

echo "✅ All done! The library is installed and active."
