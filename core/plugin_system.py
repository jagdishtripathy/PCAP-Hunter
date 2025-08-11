import importlib.util
import argparse

def load_plugin(plugin_path):
    """
    Dynamically load a Python plugin.
    """
    spec = importlib.util.spec_from_file_location("plugin", plugin_path)
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    return plugin

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin", help="Path to custom plugin script")
    args = parser.parse_args()

    if args.plugin:
        plugin = load_plugin(args.plugin)
        # You can now use the loaded plugin module
        print(f"Plugin {args.plugin} loaded successfully.")