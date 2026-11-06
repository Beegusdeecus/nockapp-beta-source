"""Static local import closure, including packages; never executes source."""
import ast
from pathlib import Path
from policy import require


def module_closure(root,entries):
    root=Path(root);pending=list(entries);seen=set()
    while pending:
        name=pending.pop()
        if name in seen:continue
        path=root/name;require(path.is_file(),'public-install-source-missing');seen.add(name)
        tree=ast.parse(path.read_bytes())
        package=list(Path(name).parent.parts)
        for node in ast.walk(tree):
            modules=[]
            if isinstance(node,ast.Import):modules=[v.name for v in node.names]
            elif isinstance(node,ast.ImportFrom):
                if node.level:
                    require(node.level-1<=len(package),'public-install-relative-import')
                    base=package[:len(package)-(node.level-1)]
                else:base=[]
                parts=base+([] if node.module is None else node.module.split('.'))
                if parts:modules.append('.'.join(parts))
                modules.extend('.'.join(parts+[v.name])for v in node.names if v.name!='*')
            for module in modules:
                parts=module.split('.')
                if not all(p.isidentifier()for p in parts):continue
                # Include parent __init__ files as well as the actual submodule.
                # Relative and lazy imports must be frozen and pinned too.
                for length in range(1,len(parts)+1):
                    candidate=str(Path(*parts[:length])/'__init__.py')
                    if (root/candidate).is_file() and candidate not in seen:pending.append(candidate)
                candidate=str(Path(*parts).with_suffix('.py'))
                if (root/candidate).is_file() and candidate not in seen:pending.append(candidate)
    return seen
