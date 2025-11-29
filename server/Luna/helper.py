import os
import json

def tree_to_dict(path):
    node = {
        "name": os.path.basename(path),
        "path": path.replace("\\", "/")
    }

    if os.path.isdir(path):
        node["type"] = "directory"
        node["children"] = [
            tree_to_dict(os.path.join(path, item))
            for item in os.listdir(path)
        ]
    else:
        node["type"] = "file"
        node["size"] = os.path.getsize(path)
        node["modified"] = os.path.getmtime(path)

    return node


root_path = "C:/example/path"
tree = tree_to_dict(root_path)

with open("tree.json", "w") as f:
    json.dump(tree, f, indent=4)
