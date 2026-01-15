#!/usr/bin/env python3
"""
SSH Command Executor

Executes verified commands on TDX VMs via SSH.
Uses paramiko for SSH connections.
"""

import time
import subprocess
from dataclasses import dataclass
from typing import Tuple, Optional

# Try to import paramiko, fallback to subprocess
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


@dataclass
class SSHConfig:
    """SSH connection configuration."""
    host: str
    port: int = 22
    username: str = "nkoirala"
    private_key_path: str = None
    password: str = None
    timeout: int = 30


class CommandExecutor:
    """
    Executes commands on TDX VMs via SSH.
    
    All command execution is logged and the output returned.
    """
    
    def __init__(self, ssh_config: SSHConfig):
        self.config = ssh_config
        self.connected = False
        self._client = None
    
    def connect(self) -> Tuple[bool, str]:
        """Establish SSH connection to TDX VM."""
        if PARAMIKO_AVAILABLE:
            return self._connect_paramiko()
        else:
            # For subprocess-based SSH, we don't maintain a connection
            return True, None
    
    def _connect_paramiko(self) -> Tuple[bool, str]:
        """Connect using paramiko."""
        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                "hostname": self.config.host,
                "port": self.config.port,
                "username": self.config.username,
                "timeout": self.config.timeout
            }
            
            if self.config.private_key_path:
                connect_kwargs["key_filename"] = self.config.private_key_path
            elif self.config.password:
                connect_kwargs["password"] = self.config.password
            
            self._client.connect(**connect_kwargs)
            self.connected = True
            return True, None
            
        except Exception as e:
            return False, f"SSH connection failed: {str(e)}"
    
    def execute(self, command: str) -> Tuple[int, str, str, float]:
        """
        Execute a command on the TDX VM.
        
        Args:
            command: The command to execute
        
        Returns:
            (exit_code, stdout, stderr, execution_time_ms)
        """
        if PARAMIKO_AVAILABLE and self._client:
            return self._execute_paramiko(command)
        else:
            return self._execute_subprocess(command)
    
    def _execute_paramiko(self, command: str) -> Tuple[int, str, str, float]:
        """Execute using paramiko."""
        try:
            start_time = time.time()
            
            stdin, stdout, stderr = self._client.exec_command(
                command, 
                timeout=self.config.timeout
            )
            
            exit_code = stdout.channel.recv_exit_status()
            stdout_str = stdout.read().decode('utf-8', errors='replace')
            stderr_str = stderr.read().decode('utf-8', errors='replace')
            
            execution_time = (time.time() - start_time) * 1000
            
            return exit_code, stdout_str, stderr_str, execution_time
            
        except Exception as e:
            return -1, "", str(e), 0.0
    
    def _execute_subprocess(self, command: str) -> Tuple[int, str, str, float]:
        """Execute using subprocess ssh command."""
        try:
            start_time = time.time()
            
            ssh_cmd = ["ssh"]
            
            # Add identity file if specified
            if self.config.private_key_path:
                ssh_cmd.extend(["-i", self.config.private_key_path])
            
            # Add connection options
            ssh_cmd.extend([
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", f"ConnectTimeout={self.config.timeout}",
                "-p", str(self.config.port),
                f"{self.config.username}@{self.config.host}",
                command
            ])
            
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout + 10
            )
            
            execution_time = (time.time() - start_time) * 1000
            
            return result.returncode, result.stdout, result.stderr, execution_time
            
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out", 0.0
        except Exception as e:
            return -1, "", str(e), 0.0
    
    def disconnect(self):
        """Close SSH connection."""
        if self._client:
            try:
                self._client.close()
            except:
                pass
            self._client = None
        self.connected = False
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test SSH connectivity with a simple command."""
        exit_code, stdout, stderr, _ = self.execute("echo 'connection_test'")
        if exit_code == 0 and "connection_test" in stdout:
            return True, None
        return False, stderr or "Connection test failed"
