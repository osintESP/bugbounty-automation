"""
Command executor utility
"""
import subprocess
import shlex
from typing import Tuple, List
from utils.logger import get_logger

logger = get_logger(__name__)


class CommandExecutor:
    """Execute external commands safely"""
    
    @staticmethod
    def run(command: str, timeout: int = 300, shell: bool = False) -> Tuple[int, str, str]:
        """
        Execute a command and return exit code, stdout, stderr
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            shell: Whether to use shell execution
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            logger.debug(f"Executing command: {command}")
            
            if not shell:
                command = shlex.split(command)
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=shell
            )
            
            logger.debug(f"Command completed with exit code: {result.returncode}")
            
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout} seconds: {command}")
            return -1, "", f"Command timed out after {timeout} seconds"
            
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return -1, "", str(e)
    
    @staticmethod
    def run_async(command: str, callback=None):
        """Execute command asynchronously"""
        # TODO: Implement async execution with Celery
        pass
    
    @staticmethod
    def check_tool_installed(tool: str) -> bool:
        """Check if a tool is installed and available"""
        exit_code, _, _ = CommandExecutor.run(f"which {tool}", timeout=5)
        return exit_code == 0
    
    @staticmethod
    def get_tool_version(tool: str) -> str:
        """Get version of installed tool"""
        exit_code, stdout, _ = CommandExecutor.run(f"{tool} --version", timeout=5)
        if exit_code == 0:
            return stdout.strip().split('\n')[0]
        return "Unknown"
