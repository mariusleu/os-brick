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
            self, read_handle, host, port, dc_name, ds_name, cookies,
            upload_file_path, file_size, cacerts, timeout_secs):
        write_handle = rw_handles.FileWriteHandle(host,
                                                  port,
                                                  dc_name,
                                                  ds_name,
                                                  cookies,
                                                  upload_file_path,
                                                  file_size,
                                                  cacerts=cacerts)
        image_transfer._start_transfer(read_handle, write_handle, timeout_secs)

    def _disconnect(self, tmp_file, tmp_file_path, file_size, session,
                    ds_ref,  dc_ref, vmdk_path):
        # The restored volume is in compressed (streamOptimized) format.
        # So we upload it to a temporary location in vCenter datastore and copy
        # the compressed vmdk to the volume vmdk. The copy operation
        # decompresses the disk to a format suitable for attaching to Nova
        # instances in vCenter.
        dstore = datastore.get_datastore_by_ref(session, ds_ref)
        ds_path = dstore.build_path(
            VmdkConnector.TMP_IMAGES_DATASTORE_FOLDER_PATH,
            os.path.basename(tmp_file_path))
        self._create_temp_ds_folder(
            session, six.text_type(ds_path.parent), dc_ref)

        dc_name = session.invoke_api(
            vim_util, 'get_object_property', session.vim, dc_ref, 'name')
        cookies = session.vim.client.options.transport.cookiejar
        cacerts = self._ca_file if self._ca_file else not self._insecure
        self._upload_vmdk(
                tmp_file, self._ip, self._port, dc_name, dstore.name, cookies,
                ds_path.rel_path, file_size, cacerts,
                self._timeout)

        # Delete the current volume vmdk because the copy operation does not
        # overwrite.
        LOG.debug("Deleting %s", vmdk_path)
        disk_mgr = session.vim.service_content.virtualDiskManager
        task = session.invoke_api(session.vim,
                                  'DeleteVirtualDisk_Task',
                                  disk_mgr,
                                  name=vmdk_path,
                                  datacenter=dc_ref)
        session.wait_for_task(task)

        src = six.text_type(ds_path)
        LOG.debug("Copying %(src)s to %(dest)s", {'src': src,
                                                  'dest': vmdk_path})
        task = session.invoke_api(session.vim,
                                  'CopyVirtualDisk_Task',
                                  disk_mgr,
                                  sourceName=src,
                                  sourceDatacenter=dc_ref,
                                  destName=vmdk_path,
                                  destDatacenter=dc_ref)
        session.wait_for_task(task)

        # Delete the compressed vmdk at the temporary location.
        LOG.debug("Deleting %s", src)
        file_mgr = session.vim.service_content.fileManager
        task = session.invoke_api(session.vim,
                                  'DeleteDatastoreFile_Task',
                                  file_mgr,
                                  name=src,
                                  datacenter=dc_ref)
        session.wait_for_task(task)

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

                self._disconnect_volume(backing, session, tmp_file_path,
                                        connection_properties)

        finally:
            os.remove(tmp_file_path)
            if session:
                session.logout()

    def _disconnect_volume(self, backing, session, tmp_file_path,
                           connection_properties):
        with open(tmp_file_path, "rb") as tmp_file:
            file_size = os.path.getsize(tmp_file_path)

            if connection_properties['lease'] and \
                    connection_properties['lease_info']:
                lease = vim_util.get_moref(connection_properties['lease'],
                                           'HttpNfcLease')
                lease_info = connection_properties['lease_info']

                self._disconnect_http_nfc(backing, session, self._ip,
                                          self._port,
                                          lease, lease_info, tmp_file,
                                          file_size, self._timeout)
            else:
                ds_ref = vim_util.get_moref(
                    connection_properties['datastore'], "Datastore")
                dc_ref = vim_util.get_moref(
                    connection_properties['datacenter'], "Datacenter")
                vmdk_path = connection_properties['vmdk_path']
                self._disconnect(
                    tmp_file_path, tmp_file, file_size, session, ds_ref,
                    dc_ref, vmdk_path)

    def _disconnect_http_nfc(self, backing, session, host, port, lease,
                             lease_info, file_handle, file_size, timeout_secs):
        write_handle = VmdkWriteHandleLeaseAware(session,
                                                 host,
                                                 port,
                                                 lease,
                                                 lease_info,
                                                 file_size,
                                                 'POST')
        image_transfer._start_transfer(file_handle, write_handle, timeout_secs)
        uuid = backing.instanceUuid
        self.delete_backing(backing)
        vm_ref = write_handle.get_imported_vm()
        self.update_backing_uuid(vm_ref, uuid)

    def update_backing_uuid(self, backing, uuid):
        cf = self._session.vim.client.factory
        reconfig_spec = cf.create('ns0:VirtualMachineConfigSpec')
        reconfig_spec.instanceUuid = uuid
        self._reconfigure_backing(backing, reconfig_spec)
        LOG.debug("Backing: %(backing)s reconfigured with uuid: %(uuid)s.",
                  {'backing': backing,
                   'uuid': uuid})

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

    def extend_volume(self, connection_properties):
        raise NotImplementedError


class VmdkWriteHandleLeaseAware(rw_handles.VmdkWriteHandle):
    """
    VmdkWriteHandle which takes as parameter an existing lease and lease_info
    """
    def __init__(self, session, host, port, lease, lease_info, vmdk_size,
                 http_method='PUT'):
        self._vmdk_size = vmdk_size
        self._bytes_written = 0

        # Find VMDK URL where data is to be written
        url, thumbprint = self._find_vmdk_url(lease_info, host, port)
        self._vm_ref = lease_info.entity

        cookies = session.vim.client.options.transport.cookiejar
        # Create HTTP connection to write to VMDK URL
        if http_method == 'PUT':
            overwrite = 't'
            content_type = 'binary/octet-stream'
        elif http_method == 'POST':
            overwrite = None
            content_type = 'application/x-vnd.vmware-streamVmdk'
        else:
            raise ValueError('http_method must be either PUT or POST')
        self._conn = self._create_write_connection(http_method,
                                                   url,
                                                   vmdk_size,
                                                   cookies=cookies,
                                                   overwrite=overwrite,
                                                   content_type=content_type,
                                                   ssl_thumbprint=thumbprint)
        super(rw_handles.VmdkWriteHandle, self).__init__(session, lease, url,
                                                         self._conn)
