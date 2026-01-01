"""
Configuration Manager
"""
import yaml
import os
from pathlib import Path
from typing import Dict, Any


class Config:
    """Configuration manager for the application"""
    
    _config: Dict[str, Any] = {}
    _config_path: str = None
    
    @classmethod
    def load(cls, config_path: str = 'config.yaml'):
        """Load configuration from YAML file"""
        cls._config_path = config_path
        
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r') as f:
            cls._config = yaml.safe_load(f)
        
        # Replace environment variables
        cls._replace_env_vars(cls._config)
        
        return cls._config
    
    @classmethod
    def _replace_env_vars(cls, config: Dict[str, Any]):
        """Recursively replace ${VAR} with environment variables"""
        for key, value in config.items():
            if isinstance(value, dict):
                cls._replace_env_vars(value)
            elif isinstance(value, str) and value.startswith('${') and value.endswith('}'):
                env_var = value[2:-1]
                config[key] = os.getenv(env_var, value)
    
    @classmethod
    def get(cls, key: str = None, default: Any = None) -> Any:
        """Get configuration value by key"""
        if key is None:
            return cls._config
        
        # Support nested keys with dot notation (e.g., 'database.host')
        keys = key.split('.')
        value = cls._config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        
        return value if value is not None else default
    
    @classmethod
    def get_targets(cls):
        """Get list of configured targets"""
        return cls._config.get('targets', [])
    
    @classmethod
    def get_database_config(cls):
        """Get database configuration"""
        return cls._config.get('database', {})
    
    @classmethod
    def get_recon_config(cls):
        """Get reconnaissance configuration"""
        return cls._config.get('recon', {})
    
    @classmethod
    def get_scan_config(cls):
        """Get scanning configuration"""
        return cls._config.get('scan', {})
    
    @classmethod
    def get_reporting_config(cls):
        """Get reporting configuration"""
        return cls._config.get('reporting', {})
    
    @classmethod
    def is_tool_enabled(cls, category: str, tool: str) -> bool:
        """Check if a specific tool is enabled"""
        config = cls._config.get(category, {})
        tool_config = config.get(tool, {})
        return tool_config.get('enabled', False)
    
    @classmethod
    def reload(cls):
        """Reload configuration from file"""
        if cls._config_path:
            cls.load(cls._config_path)
