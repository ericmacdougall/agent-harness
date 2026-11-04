"""Import every harness hook module: the Mac runs hooks on the system python3 (3.9), so a 3.10+-only construct breaks every hook call."""
import importlib, pathlib, sys
hooks = pathlib.Path("harness/hooks")
sys.path.insert(0, str(hooks))
failed = []
for path in sorted(hooks.glob("*.py")):
    try:
        importlib.import_module(path.stem)
    except Exception as error:
        failed.append(f"{path.name}: {type(error).__name__}: {error}")
print(f"imported {len(list(hooks.glob('*.py'))) - len(failed)} hook modules on Python {sys.version.split()[0]}")
print("\n".join(failed))
sys.exit(1 if failed else 0)
