# Copyright (c) 2016 VMware, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import tempfile

from oslo_log import log as logging
from oslo_utils import fileutils
from oslo_utils import units

try:
    from oslo_vmware import api
    from oslo_vmware import exceptions as oslo_vmw_exceptions
    from oslo_vmware import image_transfer
    from oslo_vmware.objects import datastore
    from oslo_vmware import rw_handles
    from oslo_vmware import vim_util
except ImportError:
    vim_util = None
import six

from os_brick import exception
from os_brick.i18n import _
from os_brick.initiator import initiator_connector

LOG = logging.getLogger(__name__)

BACKING_UUID_KEY = 'instanceUuid'
MIN_VIRTUAL_DISK_SIZE_KB = 4 * units.Ki


class VmdkConnector(initiator_connector.InitiatorConnector):
    """Connector for volumes created by the VMDK driver.

    This connector is only used for backup and restore of Cinder volumes.
    """

    TMP_IMAGES_DATASTORE_FOLDER_PATH = "cinder_temp"

    def __init__(self, *args, **kwargs):
        # Check if oslo.vmware library is available.
        if vim_util is None:
            message = _("Missing oslo_vmware python module, ensure oslo.vmware"
                        " library is installed and available.")
            raise exception.BrickException(message=message)

        super(VmdkConnector, self).__init__(*args, **kwargs)

        self._ip = None
        self._port = None
        self._username = None
        self._password = None
        self._api_retry_count = None
        self._task_poll_interval = None
        self._ca_file = None
        self._insecure = None
        self._tmp_dir = None
        self._timeout = None

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        return {}

    def check_valid_device(self, path, *args, **kwargs):
        try:
            with open(path, 'r') as dev:
                dev.read(1)
        except IOError:
            LOG.exception(
                "Failed to access the device on the path "
                "%(path)s", {"path": path})
            return False
        return True

    def get_volume_paths(self, connection_properties):
        return []

    def get_search_path(self):
        return None

    def get_all_available_volumes(self, connection_properties=None):
        pass

    def _load_config(self, connection_properties):
        config = connection_properties['config']
        self._ip = config['vmware_host_ip']
        self._port = config['vmware_host_port']
        self._username = config['vmware_host_username']
        self._password = config['vmware_host_password']
        self._api_retry_count = config['vmware_api_retry_count']
        self._task_poll_interval = config['vmware_task_poll_interval']
        self._ca_file = config['vmware_ca_file']
        self._insecure = config['vmware_insecure']
        self._tmp_dir = config['vmware_tmp_dir']
        self._timeout = config['vmware_image_transfer_timeout_secs']

    def _create_session(self):
        return api.VMwareAPISession(self._ip,
                                    self._username,
                                    self._password,
                                    self._api_retry_count,
                                    self._task_poll_interval,
                                    port=self._port,
                                    cacert=self._ca_file,
                                    insecure=self._insecure)

    def _create_temp_file(self, *args, **kwargs):
        fileutils.ensure_tree(self._tmp_dir)
        fd, tmp = tempfile.mkstemp(dir=self._tmp_dir, *args, **kwargs)
        os.close(fd)
        return tmp

    def _download_vmdk(
            self, tmp_file_path, session, backing, vmdk_path, vmdk_size):
        with open(tmp_file_path, "wb") as tmp_file:
            image_transfer.copy_stream_optimized_disk(
                None,
                self._timeout,
                tmp_file,
                session=session,
                host=self._ip,
                port=self._port,
                vm=backing,
                vmdk_file_path=vmdk_path,
                vmdk_size=vmdk_size)

    def connect_volume(self, connection_properties):
        # Download the volume vmdk from vCenter server to a temporary file
        # and return its path.
        self._load_config(connection_properties)
        session = self._create_session()

        tmp_file_path = self._create_temp_file(
            suffix=".vmdk", prefix=connection_properties['volume_id'])
        backing = vim_util.get_moref(connection_properties['volume'],
                                     "VirtualMachine")
        vmdk_path = connection_properties['vmdk_path']
        vmdk_size = connection_properties['vmdk_size']
        try:
            self._download_vmdk(
                tmp_file_path, session, backing, vmdk_path, vmdk_size)
        finally:
            session.logout()

        # Save the last modified time of the temporary so that we can decide
        # whether to upload the file back to vCenter server during disconnect.
        last_modified = os.path.getmtime(tmp_file_path)
        return {'path': tmp_file_path, 'last_modified': last_modified}

    def _snapshot_exists(self, session, backing):
        snapshot = session.invoke_api(vim_util,
                                      'get_object_property',
                                      session.vim,
                                      backing,
                                      'snapshot')
        if snapshot is None or snapshot.rootSnapshotList is None:
            return False
        return len(snapshot.rootSnapshotList) != 0

    def _create_temp_ds_folder(self, session, ds_folder_path, dc_ref):
        fileManager = session.vim.service_content.fileManager
        try:
            session.invoke_api(session.vim,
                               'MakeDirectory',
                               fileManager,
                               name=ds_folder_path,
                               datacenter=dc_ref)
        except oslo_vmw_exceptions.FileAlreadyExistsException:
            pass

    # Note(vbala) remove this method when we implement it in oslo.vmware
    def _upload_vmdk(
            self, read_handle, host, port, timeout_secs, session,
            rp_ref, vm_folder_ref, import_spec, vmdk_size):

        write_handle = rw_handles.VmdkWriteHandle(session,
                                                  host,
                                                  port,
                                                  rp_ref,
                                                  vm_folder_ref,
                                                  import_spec,
                                                  vmdk_size,
                                                  'POST')

        image_transfer._start_transfer(read_handle, write_handle, timeout_secs)
        return write_handle.get_imported_vm()

    def _disconnect(self, tmp_file_path, session, volume, rp_ref,
                    vm_folder_ref, name, size_kb, disk_type, ds_name,
                    profile_id, adapter_type, extra_config, vmdk_size,
                    volume_id):

        volume_ops = VolumeOps(session=session)
        #
        # relocate_spec = volume_ops.relocate_spec(datastore=temp_ds_ref)
        # volume_ops.relocate_vm(backing, relocate_spec)
        # backing = volume_ops.get_backing_by_uuid(volume_id)
        # The restored volume is in compressed (streamOptimized) format.
        # So we upload it to a temporary location in vCenter datastore and copy
        # the compressed vmdk to the volume vmdk. The copy operation
        # decompresses the disk to a format suitable for attaching to Nova
        # instances in vCenter.
        # temp_dstore = datastore.get_datastore_by_ref(session, ds_ref)
        # temp_ds_path = temp_dstore.build_path(
        #     VmdkConnector.TMP_IMAGES_DATASTORE_FOLDER_PATH,
        #     os.path.basename(tmp_file_path))
        # self._create_temp_ds_folder(
        #     session, six.text_type(temp_ds_path.parent), dc_ref)

        with open(tmp_file_path, "rb") as tmp_file:
            # dc_name = session.invoke_api(
            #     vim_util, 'get_object_property', session.vim, dc_ref, 'name')
            # cookies = session.vim.client.options.transport.cookiejar
            # cacerts = self._ca_file if self._ca_file else not self._insecure
            vm_config_spec = volume_ops.get_create_spec(
                name,
                size_kb,
                disk_type,
                ds_name,
                profile_id,
                adapter_type,
                extra_config)

            vm_import = volume_ops.import_spec(config_spec=vm_config_spec)

            try:
                volume_ops.rename_backing(volume, name + "-backup")
                imported_vm = self._upload_vmdk(tmp_file,
                                                self._ip,
                                                self._port,
                                                self._timeout,
                                                session,
                                                rp_ref,
                                                vm_folder_ref,
                                                vm_import,
                                                vmdk_size)
                volume_ops.delete_backing(volume)
            except oslo_vmw_exceptions.VimException as e:
                volume_ops.rename_backing(volume, name)
                raise e

        volume_ops.update_backing_disk_uuid(imported_vm, volume_id)
        # # Delete the current volume vmdk because the copy operation does not
        # # overwrite.
        # LOG.debug("Deleting %s", vmdk_path)
        # disk_mgr = session.vim.service_content.virtualDiskManager
        # task = session.invoke_api(session.vim,
        #                           'DeleteVirtualDisk_Task',
        #                           disk_mgr,
        #                           name=vmdk_path,
        #                           datacenter=dc_ref)
        # session.wait_for_task(task)
        #
        # src = six.text_type(temp_ds_path)
        # LOG.debug("Copying %(src)s to %(dest)s", {'src': src,
        #                                           'dest': vmdk_path})
        # task = session.invoke_api(session.vim,
        #                           'CopyVirtualDisk_Task',
        #                           disk_mgr,
        #                           sourceName=src,
        #                           sourceDatacenter=dc_ref,
        #                           destName=vmdk_path,
        #                           destDatacenter=dc_ref)
        # session.wait_for_task(task)
        #
        # # Delete the compressed vmdk at the temporary location.
        # LOG.debug("Deleting %s", src)
        # file_mgr = session.vim.service_content.fileManager
        # task = session.invoke_api(session.vim,
        #                           'DeleteDatastoreFile_Task',
        #                           file_mgr,
        #                           name=src,
        #                           datacenter=dc_ref)
        # session.wait_for_task(task)
        #
        # relocate_spec = volume_ops.relocate_spec(datastore=ds_ref)
        # volume_ops.relocate_vm(backing, relocate_spec)

    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        tmp_file_path = device_info['path']
        if not os.path.exists(tmp_file_path):
            msg = _("Vmdk: %s not found.") % tmp_file_path
            raise exception.NotFound(message=msg)

        session = None
        try:
            # We upload the temporary file to vCenter server only if it is
            # modified after connect_volume.
            if os.path.getmtime(tmp_file_path) > device_info['last_modified']:
                self._load_config(connection_properties)
                session = self._create_session()
                backing = vim_util.get_moref(connection_properties['volume'],
                                             "VirtualMachine")
                # Currently there is no way we can restore the volume if it
                # contains redo-log based snapshots (bug 1599026).
                if self._snapshot_exists(session, backing):
                    msg = (_("Backing of volume: %s contains one or more "
                             "snapshots; cannot disconnect.") %
                           connection_properties['volume_id'])
                    raise exception.BrickException(message=msg)
                #
                # temp_ds_ref = vim_util.get_moref(
                #     connection_properties['temp_datastore'], "Datastore")
                # ds_ref = vim_util.get_moref(
                #     connection_properties['datastore'], "Datastore")
                # dc_ref = vim_util.get_moref(
                #     connection_properties['datacenter'], "Datacenter")
                # vmdk_path = connection_properties['vmdk_path']
                rp_ref = vim_util.get_moref(connection_properties['rp_ref'],
                                            'ResourcePool')
                vm_folder_ref = vim_util.get_moref(connection_properties[
                                           'vm_folder_ref'], 'Folder')
                name = connection_properties.get('name')
                size_kb = connection_properties.get('size_kb')
                disk_type = connection_properties.get('disk_type')
                ds_name = connection_properties.get('ds_name')
                profile_id = connection_properties.get('profile_id')
                adapter_type = connection_properties.get('adapter_type')
                extra_config = connection_properties.get('extra_config')
                vmdk_size = connection_properties.get('vmdk_size')
                volume_id = connection_properties.get('volume_id')

                self._disconnect(
                    tmp_file_path, session,backing,
                    rp_ref, vm_folder_ref, name, size_kb, disk_type, ds_name,
                    profile_id, adapter_type, extra_config, vmdk_size,
                    volume_id)
        finally:
            os.remove(tmp_file_path)
            if session:
                session.logout()

    def extend_volume(self, connection_properties):
        raise NotImplementedError


class VolumeOps:

    def __init__(self, session):
        self._session = session
        self._client_factory = self._session.vim.client.factory

    def get_disk_device(self, backing):
        """Get the virtual device corresponding to disk."""
        hardware_devices = self._session.invoke_api(vim_util,
                                                    'get_object_property',
                                                    self._session.vim,
                                                    backing,
                                                    'config.hardware.device')
        if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
            hardware_devices = hardware_devices.VirtualDevice
        for device in hardware_devices:
            if device.__class__.__name__ == "VirtualDisk":
                return device

        LOG.error("Virtual disk device of backing: %s not found.", backing)
        return None

    def rename_backing(self, backing, new_name):
        """Rename backing VM.

        :param backing: VM to be renamed
        :param new_name: new VM name
        """
        LOG.info("Renaming backing VM: %(backing)s to %(new_name)s.",
                 {'backing': backing,
                  'new_name': new_name})
        rename_task = self._session.invoke_api(self._session.vim,
                                               "Rename_Task",
                                               backing,
                                               newName=new_name)
        LOG.debug("Task: %s created for renaming VM.", rename_task)
        self._session.wait_for_task(rename_task)
        LOG.info("Backing VM: %(backing)s renamed to %(new_name)s.",
                 {'backing': backing,
                  'new_name': new_name})

    def update_backing_disk_uuid(self, backing, disk_uuid):
        """Update backing VM's disk UUID.

        :param backing: Reference to backing VM
        :param disk_uuid: New disk UUID
        """
        LOG.debug("Reconfiguring backing VM: %(backing)s to change disk UUID "
                  "to: %(disk_uuid)s.",
                  {'backing': backing,
                   'disk_uuid': disk_uuid})

        disk_device = self.get_disk_device(backing)
        disk_device.backing.uuid = disk_uuid

        cf = self._session.vim.client.factory
        disk_spec = cf.create('ns0:VirtualDeviceConfigSpec')
        disk_spec.device = disk_device
        disk_spec.operation = 'edit'

        reconfig_spec = cf.create('ns0:VirtualMachineConfigSpec')
        reconfig_spec.deviceChange = [disk_spec]
        self.reconfig_vm(backing, reconfig_spec)

        LOG.debug("Backing VM: %(backing)s reconfigured with new disk UUID: "
                  "%(disk_uuid)s.",
                  {'backing': backing,
                   'disk_uuid': disk_uuid})

    def delete_backing(self, backing):
        """Delete the backing.

        :param backing: Managed object reference to the backing
        """
        LOG.debug("Deleting the VM backing: %s.", backing)
        task = self._session.invoke_api(self._session.vim, 'Destroy_Task',
                                        backing)
        LOG.debug("Initiated deletion of VM backing: %s.", backing)
        self._session.wait_for_task(task)
        LOG.info("Deleted the VM backing: %s.", backing)

    def relocate_spec(self, datastore=None, resource_pool=None, host=None,
                      disk_move_type=None):
        relocate_spec = self._client_factory.create(
            'ns0:VirtualMachineRelocateSpec')
        relocate_spec.datastore = datastore
        relocate_spec.pool = resource_pool
        relocate_spec.host = host
        relocate_spec.diskMoveType = disk_move_type
        return relocate_spec

    def reconfig_spec(self, device_change=None):
        spec = self._client_factory.create("ns0:VirtualMachineConfigSpec")
        spec.deviceChange = device_change
        return spec

    def backing_spec(self, thin_provisioned=None, eagerly_scrub=None,
                     file_name=None, disk_mode=None, datastore=None, spec=None):
        new_backing = spec or self._client_factory.create(
            "ns0:VirtualDiskFlatVer2BackingInfo")
        if thin_provisioned is not None:
            new_backing.thinProvisioned = thin_provisioned
        if eagerly_scrub is not None:
            new_backing.eagerlyScrub = eagerly_scrub
        new_backing.datastore = datastore
        new_backing.fileName = file_name
        new_backing.diskMode = disk_mode
        return new_backing

    def disk_spec(self, capacity_in_kb=None, unit_number=0,
                  backing=None, controller_key=None, key=None, spec=None):
        new_disk_device = spec or self._client_factory.create("ns0:VirtualDisk")
        new_disk_device.capacityInKB = capacity_in_kb
        new_disk_device.unitNumber = unit_number
        new_disk_device.backing = backing
        new_disk_device.controllerKey = controller_key
        new_disk_device.key = key
        return new_disk_device

    def device_spec(self, device=None, operation=None,
                    file_operation=None, profile_id=None, spec=None):
        disk_spec = spec or self._client_factory.create(
            "ns0:VirtualDeviceConfigSpec")
        disk_spec.device = device
        disk_spec.operation = operation
        disk_spec.fileOperation = file_operation
        if profile_id is not None:
            LOG.info("Setting profile_id=%s" % profile_id)
            disk_profile = self._client_factory.create(
                'ns0:VirtualMachineDefinedProfileSpec')
            disk_profile.profileId = profile_id
            disk_spec.profile = [disk_profile]
        return disk_spec

    def _create_specs_for_disk_add(self, size_kb, disk_type, adapter_type,
                                   profile_id, vmdk_ds_file_path=None):
        """Create controller and disk config specs for adding a new disk.

        :param size_kb: disk size in KB
        :param disk_type: disk provisioning type
        :param adapter_type: disk adapter type
        :param profile_id: storage policy profile identification
        :param vmdk_ds_file_path: Optional datastore file path of an existing
                                  virtual disk. If specified, file backing is
                                  not created for the virtual disk.
        :return: list containing controller and disk config specs
        """
        controller_spec = None
        if adapter_type == 'ide':
            # For IDE disks, use one of the default IDE controllers (with keys
            # 200 and 201) created as part of backing VM creation.
            controller_key = 200
        else:
            controller_spec = self._create_controller_config_spec(adapter_type)
            controller_key = controller_spec.device.key

        disk_spec = self._create_virtual_disk_config_spec(size_kb,
                                                          disk_type,
                                                          controller_key,
                                                          profile_id,
                                                          vmdk_ds_file_path)
        specs = [disk_spec]
        if controller_spec is not None:
            specs.append(controller_spec)
        return specs

    def _create_backing_int(self, folder, resource_pool, host, create_spec):
        """Helper for create backing methods."""
        LOG.debug("Creating volume backing with spec: %s.", create_spec)
        task = self._session.invoke_api(self._session.vim, 'CreateVM_Task',
                                        folder, config=create_spec,
                                        pool=resource_pool, host=host)
        task_info = self._session.wait_for_task(task)
        backing = task_info.result
        LOG.info("Successfully created volume backing: %s.", backing)
        return backing

    def _create_controller_config_spec(self, adapter_type):
        """Returns config spec for adding a disk controller."""
        cf = self._session.vim.client.factory

        controller_type = ControllerType.get_controller_type(adapter_type)
        controller_device = cf.create('ns0:%s' % controller_type)
        controller_device.key = -100
        controller_device.busNumber = 0
        if ControllerType.is_scsi_controller(controller_type):
            controller_device.sharedBus = 'noSharing'

        controller_spec = cf.create('ns0:VirtualDeviceConfigSpec')
        controller_spec.operation = 'add'
        controller_spec.device = controller_device
        return controller_spec

    def import_spec(self, config_spec):
        vm_import_spec = self._client_factory.create(
            'ns0:VirtualMachineImportSpec')
        vm_import_spec.configSpec = config_spec
        return vm_import_spec

    def rename_spec(self, name):
        spec = self._client_factory.create('ns0:VirtualMachineFileInfo')
        spec.name = name
        return spec

    def config_spec(self, **kwargs):
        cf = self._session.vim.client.factory
        vm_file_info = cf.create('ns0:VirtualMachineFileInfo')
        vm_file_info.vmPathName = '[%s]' % kwargs.get('ds_name')

        create_spec = cf.create('ns0:VirtualMachineConfigSpec')
        create_spec.name = kwargs.get('name') or kwargs.get('volume_name')
        create_spec.guestId = 'otherGuest'
        create_spec.numCPUs = 1
        create_spec.memoryMB = 128
        create_spec.files = vm_file_info
        # Set the default hardware version to a compatible version supported by
        # vSphere 5.0. This will ensure that the backing VM can be migrated
        # without any incompatibility issues in a mixed cluster of ESX hosts
        # with versions 5.0 or above.
        create_spec.version = kwargs.get('vmx_version')
        BACKING_UUID_KEY = 'instanceUuid'
        profile_id = kwargs.get('profile_id')
        if profile_id:
            vm_profile = cf.create('ns0:VirtualMachineDefinedProfileSpec')
            vm_profile.profileId = profile_id
            create_spec.vmProfile = [vm_profile]

        extra_config = kwargs.get('extra_config')
        if extra_config:
            if BACKING_UUID_KEY in extra_config:
                create_spec.instanceUuid = extra_config.pop(BACKING_UUID_KEY)
            create_spec.extraConfig = self._get_extra_config_option_values(
                extra_config)

        create_spec.managedBy = self._create_managed_by_info(kwargs.get(
            'extension_key'), kwargs.get('extension_type'))

        return create_spec

    def _get_extra_config_option_values(self, extra_config):

        cf = self._session.vim.client.factory
        option_values = []

        for key, value in extra_config.items():
            opt = cf.create('ns0:OptionValue')
            opt.key = key
            opt.value = value
            option_values.append(opt)

        return option_values

    def _create_managed_by_info(self, extension_key, extension_type):
        managed_by = self._session.vim.client.factory.create(
            'ns0:ManagedByInfo')
        managed_by.extensionKey = extension_key
        managed_by.type = extension_type
        return managed_by

    def _create_virtual_disk_config_spec(self, size_kb, disk_type,
                                         controller_key, profile_id,
                                         vmdk_ds_file_path):
        """Returns config spec for adding a virtual disk."""
        cf = self._session.vim.client.factory

        disk_device = cf.create('ns0:VirtualDisk')
        # disk size should be at least 4MB for VASA provider
        min_size_kb = MIN_VIRTUAL_DISK_SIZE_KB
        disk_device.capacityInKB = max(min_size_kb, int(size_kb))
        if controller_key < 0:
            disk_device.key = controller_key - 1
        else:
            disk_device.key = -101
        disk_device.unitNumber = 0
        disk_device.controllerKey = controller_key
        disk_device.backing = self._create_disk_backing(disk_type,
                                                        vmdk_ds_file_path)

        disk_spec = cf.create('ns0:VirtualDeviceConfigSpec')
        disk_spec.operation = 'add'
        if vmdk_ds_file_path is None:
            disk_spec.fileOperation = 'create'
        disk_spec.device = disk_device
        if profile_id:
            disk_profile = cf.create('ns0:VirtualMachineDefinedProfileSpec')
            disk_profile.profileId = profile_id
            disk_spec.profile = [disk_profile]

        return disk_spec

    def _create_disk_backing(self, disk_type, vmdk_ds_file_path):
        """Creates file backing for virtual disk."""
        cf = self._session.vim.client.factory
        disk_device_bkng = cf.create('ns0:VirtualDiskFlatVer2BackingInfo')

        if disk_type == VirtualDiskType.EAGER_ZEROED_THICK:
            disk_device_bkng.eagerlyScrub = True
        elif disk_type == VirtualDiskType.THIN:
            disk_device_bkng.thinProvisioned = True

        disk_device_bkng.fileName = vmdk_ds_file_path or ''
        disk_device_bkng.diskMode = 'persistent'

        return disk_device_bkng

    def get_create_spec(self, name, size_kb, disk_type, ds_name,
                        profile_id=None, adapter_type='lsiLogic',
                        extra_config=None):
        """Return spec for creating backing with a single disk.

        :param name: name of the backing
        :param size_kb: disk size in KB
        :param disk_type: disk provisioning type
        :param ds_name: datastore name where the disk is to be provisioned
        :param profile_id: storage policy profile identification
        :param adapter_type: disk adapter type
        :param extra_config: key-value pairs to be written to backing's
                             extra-config
        :return: spec for creation
        """
        create_spec = self.config_spec(
            name=name, ds_name=ds_name, profile_id=profile_id,
            extra_config=extra_config)
        create_spec.deviceChange = self._create_specs_for_disk_add(
            size_kb, disk_type, adapter_type, profile_id)
        return create_spec

    def reconfig_vm(self, backing, reconfig_spec):
        LOG.debug("Reconfiguring backing VM: %(backing)s with spec: %(spec)s.",
                  {'backing': backing,
                   'spec': reconfig_spec})
        reconfig_task = self._session.invoke_api(self._session.vim,
                                                 "ReconfigVM_Task",
                                                 backing,
                                                 spec=reconfig_spec)
        LOG.debug("Task: %s created for reconfiguring backing VM.",
                  reconfig_task)
        self._session.wait_for_task(reconfig_task)

    def relocate_vm(self, vm_ref, spec):
        task = self._session.invoke_api(self._session.vim,
                                        "RelocateVM_Task",
                                        vm_ref,
                                        spec=spec)
        self._session.wait_for_task(task)

    def get_backing_by_uuid(self, uuid):
        LOG.debug("Get ref by UUID: %s.", uuid)
        result = self._session.invoke_api(
            self._session.vim,
            'FindAllByUuid',
            self._session.vim.service_content.searchIndex,
            uuid=uuid,
            vmSearch=True,
            instanceUuid=True)
        if result:
            return result[0]

class VirtualDiskType(object):
    """Supported virtual disk types."""

    EAGER_ZEROED_THICK = "eagerZeroedThick"
    PREALLOCATED = "preallocated"
    THIN = "thin"

    # thick in extra_spec means lazy-zeroed thick disk
    EXTRA_SPEC_DISK_TYPE_DICT = {'eagerZeroedThick': EAGER_ZEROED_THICK,
                                 'thick': PREALLOCATED,
                                 'thin': THIN
                                 }

    @staticmethod
    def is_valid(extra_spec_disk_type):
        """Check if the given disk type in extra_spec is valid.

        :param extra_spec_disk_type: disk type in extra_spec
        :return: True if valid
        """
        return (extra_spec_disk_type in
                VirtualDiskType.EXTRA_SPEC_DISK_TYPE_DICT)

    @staticmethod
    def validate(extra_spec_disk_type):
        """Validate the given disk type in extra_spec.

        This method throws an instance of InvalidDiskTypeException if the given
        disk type is invalid.

        :param extra_spec_disk_type: disk type in extra_spec
        :raises: InvalidDiskTypeException
        """
        if not VirtualDiskType.is_valid(extra_spec_disk_type):
            raise ValueError()

    @staticmethod
    def get_virtual_disk_type(extra_spec_disk_type):
        """Return disk type corresponding to the extra_spec disk type.

        :param extra_spec_disk_type: disk type in extra_spec
        :return: virtual disk type
        :raises: InvalidDiskTypeException
        """
        VirtualDiskType.validate(extra_spec_disk_type)
        return (VirtualDiskType.EXTRA_SPEC_DISK_TYPE_DICT[
                extra_spec_disk_type])


class VirtualDiskAdapterType(object):
    """Supported virtual disk adapter types."""

    LSI_LOGIC = "lsiLogic"
    BUS_LOGIC = "busLogic"
    LSI_LOGIC_SAS = "lsiLogicsas"
    PARA_VIRTUAL = "paraVirtual"
    IDE = "ide"

    @staticmethod
    def is_valid(adapter_type):
        """Check if the given adapter type is valid.

        :param adapter_type: adapter type to check
        :return: True if valid
        """
        return adapter_type in [VirtualDiskAdapterType.LSI_LOGIC,
                                VirtualDiskAdapterType.BUS_LOGIC,
                                VirtualDiskAdapterType.LSI_LOGIC_SAS,
                                VirtualDiskAdapterType.PARA_VIRTUAL,
                                VirtualDiskAdapterType.IDE]

    @staticmethod
    def validate(extra_spec_adapter_type):
        """Validate the given adapter type in extra_spec.

        This method throws an instance of InvalidAdapterTypeException if the
        given adapter type is invalid.

        :param extra_spec_adapter_type: adapter type in extra_spec
        :raises: InvalidAdapterTypeException
        """
        if not VirtualDiskAdapterType.is_valid(extra_spec_adapter_type):
            raise ValueError()

    @staticmethod
    def get_adapter_type(extra_spec_adapter):
        """Get the adapter type to be used in VirtualDiskSpec.

        :param extra_spec_adapter: adapter type in the extra_spec
        :return: adapter type to be used in VirtualDiskSpec
        """
        VirtualDiskAdapterType.validate(extra_spec_adapter)
        # We set the adapter type as lsiLogic for lsiLogicsas/paraVirtual
        # since it is not supported by VirtualDiskManager APIs. This won't
        # be a problem because we attach the virtual disk to the correct
        # controller type and the disk adapter type is always resolved using
        # its controller key.
        if (extra_spec_adapter == VirtualDiskAdapterType.LSI_LOGIC_SAS or
                extra_spec_adapter == VirtualDiskAdapterType.PARA_VIRTUAL):
            return VirtualDiskAdapterType.LSI_LOGIC
        else:
            return extra_spec_adapter


class ControllerType(object):
    """Encapsulate various controller types."""

    LSI_LOGIC = 'VirtualLsiLogicController'
    BUS_LOGIC = 'VirtualBusLogicController'
    LSI_LOGIC_SAS = 'VirtualLsiLogicSASController'
    PARA_VIRTUAL = 'ParaVirtualSCSIController'
    IDE = 'VirtualIDEController'

    CONTROLLER_TYPE_DICT = {
        VirtualDiskAdapterType.LSI_LOGIC: LSI_LOGIC,
        VirtualDiskAdapterType.BUS_LOGIC: BUS_LOGIC,
        VirtualDiskAdapterType.LSI_LOGIC_SAS: LSI_LOGIC_SAS,
        VirtualDiskAdapterType.PARA_VIRTUAL: PARA_VIRTUAL,
        VirtualDiskAdapterType.IDE: IDE}

    @staticmethod
    def get_controller_type(adapter_type):
        """Get the disk controller type based on the given adapter type.

        :param adapter_type: disk adapter type
        :return: controller type corresponding to the given adapter type
        :raises: InvalidAdapterTypeException
        """
        if adapter_type in ControllerType.CONTROLLER_TYPE_DICT:
            return ControllerType.CONTROLLER_TYPE_DICT[adapter_type]
        raise ValueError()

    @staticmethod
    def is_scsi_controller(controller_type):
        """Check if the given controller is a SCSI controller.

        :param controller_type: controller type
        :return: True if the controller is a SCSI controller
        """
        return controller_type in [ControllerType.LSI_LOGIC,
                                   ControllerType.BUS_LOGIC,
                                   ControllerType.LSI_LOGIC_SAS,
                                   ControllerType.PARA_VIRTUAL]

