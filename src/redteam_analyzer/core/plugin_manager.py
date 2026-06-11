"""Plugin manager for discovering and loading scan plugins.

Dynamically discovers plugins from the modules/ directory using importlib.
"""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional, Type

from redteam_analyzer.modules.base import BasePlugin

logger = logging.getLogger(__name__)


class PluginManager:
    """Discovers, validates, and manages scan plugins."""

    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}
        self._plugin_classes: Dict[str, Type[BasePlugin]] = {}

    def discover_plugins(self) -> List[str]:
        """Discover all valid plugins in the modules directory.

        Returns:
            List of discovered plugin names
        """
        discovered = []
        modules_path = Path(__file__).parent.parent / "modules"

        # Walk through all subpackages in modules/
        for finder, name, ispkg in pkgutil.iter_modules(
            [str(modules_path)], prefix="redteam_analyzer.modules."
        ):
            if not ispkg:
                continue

            # Skip the base module itself
            if name.endswith(".base") or name == "redteam_analyzer.modules":
                continue

            plugin_name = name.split(".")[-1]

            try:
                plugin_class = self._load_plugin_class(name)
                if plugin_class and issubclass(plugin_class, BasePlugin):
                    self._plugin_classes[plugin_name] = plugin_class
                    discovered.append(plugin_name)
                    logger.info(f"Discovered plugin: {plugin_name}")
                else:
                    logger.warning(f"Module {name} does not contain a valid BasePlugin subclass")
            except Exception as e:
                logger.warning(f"Failed to load plugin from {name}: {e}")

        return discovered

    def _load_plugin_class(self, module_name: str) -> Optional[Type[BasePlugin]]:
        """Load a plugin class from a module name.

        Looks for a class named '{PluginName}Plugin' or any BasePlugin subclass.
        Searches both the package __init__.py and the .plugin submodule.
        """
        # Try the top-level module first
        plugin_class = self._find_base_plugin_in_module(module_name)
        if plugin_class:
            return plugin_class

        # For packages, also look in the .plugin submodule
        # e.g. redteam_analyzer.modules.recon -> redteam_analyzer.modules.recon.plugin
        plugin_submodule = f"{module_name}.plugin"
        plugin_class = self._find_base_plugin_in_module(plugin_submodule)
        if plugin_class:
            return plugin_class

        return None

    def _find_base_plugin_in_module(self, module_path: str) -> Optional[Type[BasePlugin]]:
        """Search for a BasePlugin subclass in a given module path."""
        try:
            module = importlib.import_module(module_path)
        except ImportError:
            return None

        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BasePlugin)
                and attr is not BasePlugin
            ):
                return attr

        return None

    def load_plugin(self, name: str) -> Optional[BasePlugin]:
        """Instantiate a plugin by name.

        Args:
            name: Plugin name (e.g., "recon", "scan")

        Returns:
            Plugin instance or None if not found
        """
        if name in self._plugins:
            return self._plugins[name]

        if name not in self._plugin_classes:
            logger.warning(f"Plugin '{name}' not found. Available: {list(self._plugin_classes.keys())}")
            return None

        try:
            plugin = self._plugin_classes[name]()
            self._plugins[name] = plugin
            return plugin
        except Exception as e:
            logger.error(f"Failed to instantiate plugin '{name}': {e}")
            return None

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a loaded plugin by name.

        Args:
            name: Plugin name

        Returns:
            Plugin instance or None
        """
        return self._plugins.get(name)

    def get_all_plugins(self) -> Dict[str, BasePlugin]:
        """Get all loaded plugins.

        Returns:
            Dictionary of plugin name -> plugin instance
        """
        return dict(self._plugins)

    def get_available_plugins(self) -> List[str]:
        """Get list of all discovered plugin names.

        Returns:
            List of plugin names
        """
        return list(self._plugin_classes.keys())

    def validate_plugin(self, name: str) -> bool:
        """Validate that a plugin can run (dependencies met).

        Args:
            name: Plugin name

        Returns:
            True if plugin is valid and ready to run
        """
        plugin = self.load_plugin(name)
        if not plugin:
            return False

        try:
            return plugin.validate_dependencies()
        except Exception as e:
            logger.error(f"Plugin '{name}' dependency check failed: {e}")
            return False
