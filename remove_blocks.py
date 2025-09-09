import os
import re

pattern = re.compile(
    r"\{\% code[^\%]*\%\}\n?(.*?)\n?\{\% endcode \%\}", re.DOTALL)

for root, _, files in os.walk("."):
    for f in files:
        if not f.endswith(".md"):
            continue
        path = os.path.join(root, f)
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
        new_content = pattern.sub(r"\1", content)
        if new_content != content:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(new_content)
            print(f"Cleaned: {path}")
        else:
            print(f"No wrappers found: {path}")
