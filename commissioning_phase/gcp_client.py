"""
Google Cloud Platform client for provisioning TDX Confidential VMs.

This is the GCP equivalent of Duet's azure_client.py. It handles:
  - Authentication via google.auth.default() or service account key
  - Creating firewall rules (SSH restricted to controller IP)
  - Provisioning C3-series TDX CVMs with ConfidentialInstanceConfig
  - Waiting for VM to be ready and retrieving external IP
  - Deleting all provisioned resources on CVM stop
"""

import os
import time
import random
import requests

try:
    from google.cloud import compute_v1
    from google.api_core.extended_operation import ExtendedOperation
    GCP_SDK_AVAILABLE = True
except ImportError:
    GCP_SDK_AVAILABLE = False
    compute_v1 = None
    ExtendedOperation = None

from .cvm import ConfidentialVM


def _wait_for_operation(operation: ExtendedOperation, description: str, logger):
    """Wait for a long-running GCP operation to complete."""
    logger.info(f"Waiting for {description}...")
    result = operation.result()
    logger.info(f"{description} completed.")
    return result


class GCPClient:
    """Client for provisioning TDX Confidential VMs on Google Cloud."""

    def __init__(self, config, logger):
        if not GCP_SDK_AVAILABLE:
            raise RuntimeError(
                "google-cloud-compute SDK is not installed. "
                "Install it with: pip install google-cloud-compute google-auth"
            )
        self._config = config
        self._logger = logger

        # Set credentials if a service account key path is provided
        sa_key_path = config.get("service_account_key")
        if sa_key_path and os.path.isfile(sa_key_path):
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = sa_key_path

        self._project = config["project_id"]
        self._zone = config["zone"]
        self._region = config["region"]

        # GCP Compute clients
        self._instances_client = compute_v1.InstancesClient()
        self._firewalls_client = compute_v1.FirewallsClient()

    # ------------------------------------------------------------------
    # Firewall Rules
    # ------------------------------------------------------------------

    def _get_controller_ip(self):
        """Get the external IP of this machine (the controller)."""
        try:
            resp = requests.get("https://api.ipify.org", timeout=10)
            ip = resp.text.strip()
            self._logger.info(f"Controller external IP: {ip}")
            return ip
        except Exception as exc:
            self._logger.warning(f"Could not determine controller IP: {exc}")
            return None

    def setup_firewall(self):
        """Create a firewall rule allowing SSH only from the controller's IP.

        This ensures that only the SGX controller can SSH into the CVM.
        """
        firewall_name = self._config["firewall_name"]
        network = self._config["network"]

        # Get controller IP for source range restriction
        controller_ip = self._get_controller_ip()
        if controller_ip:
            source_ranges = [f"{controller_ip}/32"]
        else:
            # Fallback: allow from any (less secure, for development)
            self._logger.warning("Using 0.0.0.0/0 as source range (could not detect controller IP)")
            source_ranges = ["0.0.0.0/0"]

        firewall = compute_v1.Firewall(
            name=firewall_name,
            network=f"projects/{self._project}/global/networks/{network}",
            direction="INGRESS",
            priority=1000,
            allowed=[
                compute_v1.Allowed(
                    I_p_protocol="tcp",
                    ports=["22"],
                ),
            ],
            source_ranges=source_ranges,
            target_tags=[self._config["vm_tag"]],
            description=f"Allow SSH from SGX controller ({controller_ip}) to CVM",
        )

        try:
            operation = self._firewalls_client.insert(
                project=self._project,
                firewall_resource=firewall,
            )
            _wait_for_operation(operation, f"Firewall rule '{firewall_name}'", self._logger)
        except Exception as exc:
            # Firewall may already exist from a previous run
            if "already exists" in str(exc).lower():
                self._logger.info(f"Firewall rule '{firewall_name}' already exists, continuing.")
            else:
                raise

        return firewall_name

    # ------------------------------------------------------------------
    # VM Provisioning
    # ------------------------------------------------------------------

    def provision_cvm(self, serialized_public_key):
        """Provision a TDX Confidential VM on GCP.

        Args:
            serialized_public_key: SSH public key (OpenSSH format) to inject
                                   into the VM for login.

        Returns:
            ConfidentialVM: The provisioned CVM object.
        """
        vm_name = self._config["vm_name"]
        username = self._config["username"]
        machine_type = self._config["machine_type"]
        zone = self._zone
        project = self._project
        network = self._config["network"]
        subnet = self._config["subnet"]
        image_project = self._config["image_project"]
        image_family = self._config["image_family"]

        self._logger.info(f"Provisioning TDX CVM: {vm_name} ({machine_type}) in {zone}")

        # --- Boot disk ---
        boot_disk = compute_v1.AttachedDisk(
            auto_delete=True,
            boot=True,
            initialize_params=compute_v1.AttachedDiskInitializeParams(
                source_image=f"projects/{image_project}/global/images/family/{image_family}",
                disk_size_gb=50,
                disk_type=f"zones/{zone}/diskTypes/pd-ssd",
            ),
        )

        # --- Network interface with external IP ---
        access_config = compute_v1.AccessConfig(
            name="External NAT",
            type_="ONE_TO_ONE_NAT",
            network_tier="PREMIUM",
        )

        network_interface = compute_v1.NetworkInterface(
            network=f"projects/{project}/global/networks/{network}",
            subnetwork=f"projects/{project}/regions/{self._region}/subnetworks/{subnet}",
            access_configs=[access_config],
        )

        # --- Confidential computing config (TDX) ---
        confidential_config = compute_v1.ConfidentialInstanceConfig(
            enable_confidential_compute=True,
            confidential_instance_config_type="TDX",
        )

        # --- Scheduling (must be TERMINATE for CVM) ---
        scheduling = compute_v1.Scheduling(
            on_host_maintenance="TERMINATE",
            automatic_restart=True,
        )

        # --- Metadata: inject SSH public key + disable GCP SSH key management ---
        # SECURITY: We inject only the controller's ephemeral public key and
        # set metadata flags to block project-level SSH keys and disable
        # guest attributes. This prevents IAM-based SSH key injection attacks.
        ssh_key_entry = f"{username}:{serialized_public_key}"
        metadata = compute_v1.Metadata(
            items=[
                compute_v1.Items(
                    key="ssh-keys",
                    value=ssh_key_entry,
                ),
                # Block project-wide SSH keys from being injected
                compute_v1.Items(
                    key="block-project-ssh-keys",
                    value="TRUE",
                ),
                # Disable guest attributes (SSH key management via metadata)
                compute_v1.Items(
                    key="enable-guest-attributes",
                    value="FALSE",
                ),
                # Disable OS Login (another SSH key injection vector)
                compute_v1.Items(
                    key="enable-oslogin",
                    value="FALSE",
                ),
            ],
        )

        # --- Instance definition ---
        instance = compute_v1.Instance(
            name=vm_name,
            machine_type=f"zones/{zone}/machineTypes/{machine_type}",
            disks=[boot_disk],
            network_interfaces=[network_interface],
            confidential_instance_config=confidential_config,
            scheduling=scheduling,
            metadata=metadata,
            tags=compute_v1.Tags(items=[self._config["vm_tag"]]),
        )

        # --- Create the VM ---
        operation = self._instances_client.insert(
            project=project,
            zone=zone,
            instance_resource=instance,
        )
        _wait_for_operation(operation, f"VM '{vm_name}' creation", self._logger)

        # --- Get the external IP ---
        vm = self._instances_client.get(project=project, zone=zone, instance=vm_name)
        external_ip = None
        for iface in vm.network_interfaces:
            for ac in iface.access_configs:
                if ac.nat_i_p:
                    external_ip = ac.nat_i_p
                    break

        if not external_ip:
            raise RuntimeError(f"Could not determine external IP for VM '{vm_name}'")

        self._logger.info(f"VM '{vm_name}' running at {external_ip}")

        # Create CVM object
        cvm = ConfidentialVM(username, external_ip, serialized_public_key, self._logger)
        return cvm

    # ------------------------------------------------------------------
    # Full Provisioning Pipeline
    # ------------------------------------------------------------------

    def provision_resources(self, serialized_public_key):
        """Full provisioning pipeline: firewall + CVM.

        Returns:
            ConfidentialVM: The provisioned CVM object.
        """
        # 1. Setup firewall rule allowing SSH from controller only
        self.setup_firewall()

        # 2. Provision the TDX CVM
        cvm = self.provision_cvm(serialized_public_key)

        return cvm

    # ------------------------------------------------------------------
    # Resource Cleanup
    # ------------------------------------------------------------------

    def delete_resources(self):
        """Delete all GCP resources created for this CVM."""
        project = self._project
        zone = self._zone
        vm_name = self._config["vm_name"]
        firewall_name = self._config["firewall_name"]

        # Delete VM
        self._logger.info(f"Deleting VM: {vm_name}")
        try:
            operation = self._instances_client.delete(
                project=project, zone=zone, instance=vm_name,
            )
            _wait_for_operation(operation, f"VM '{vm_name}' deletion", self._logger)
        except Exception as exc:
            self._logger.error(f"Error deleting VM: {exc}")

        # Delete firewall rule
        self._logger.info(f"Deleting firewall rule: {firewall_name}")
        try:
            operation = self._firewalls_client.delete(
                project=project, firewall=firewall_name,
            )
            _wait_for_operation(operation, f"Firewall '{firewall_name}' deletion", self._logger)
        except Exception as exc:
            self._logger.error(f"Error deleting firewall: {exc}")
