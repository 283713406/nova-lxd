# Copyright 2011 Justin Santa Barbara
# Copyright 2015 Canonical Ltd
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


from nova.api.metadata import base as instance_metadata
from nova.virt import configdrive
import os
import pwd
import shutil

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import units

from nova import i18n
from nova import utils

from ..lxd import container_firewall
from ..lxd import utils as container_dir
from ..lxd import vif

_ = i18n._
_LE = i18n._LE
_LW = i18n._LW
_LI = i18n._LI

CONF = cfg.CONF
CONF.import_opt('vif_plugging_timeout', 'nova.virt.driver')
CONF.import_opt('vif_plugging_is_fatal', 'nova.virt.driver')
LOG = logging.getLogger(__name__)

MAX_CONSOLE_BYTES = 100 * units.Ki


class LXDContainerNetwork(object):
    """LXD container network."""

    def __init__(self):
        self.container_dir = container_dir.LXDContainerDirectories()
        self.firewall_driver = container_firewall.LXDContainerFirewall()

        self.vif_driver = vif.LXDGenericDriver()
        self.instance_dir = None

    def setup_network(self, instance_name, instance, network_info):
        """Setup the network when creating the lXD container

        :param instance_name: nova instance name
        :param instance: nova instance object
        :param network_info: instance network configuration
        """
        LOG.debug('_setup_network called for instance', instance=instance)
        try:
            self.plug_vifs(instance, network_info)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to create container network for '
                              '%(instance)s: %(ex)s'),
                          {'instance': instance_name, 'ex': ex},
                          instance=instance)

    def _add_configdrive(self, instance, injected_files):
        """Configure the config drive for the container

        :param instance: nova instance object
        :param injected_files: instance injected files
        """
        LOG.debug('add_configdrive called for instance', instance=instance)

        extra_md = {}
        inst_md = instance_metadata.InstanceMetadata(instance,
                                                     content=injected_files,
                                                     extra_md=extra_md)
        # Create the ISO image so we can inject the contents of the ISO
        # into the container
        iso_path = os.path.join(self.instance_dir, 'configdirve.iso')
        with configdrive.ConfigDriveBuilder(instance_md=inst_md) as cdb:
            try:
                cdb.make_drive(iso_path)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Creating config drive failed with error: '
                                  '%s'), e, instance=instance)

        # Copy the metadata info from the ISO into the container
        configdrive_dir = \
            self.container_dir.get_container_configdrive(instance.name)
        with utils.tempdir() as tmpdir:
            mounted = False
            try:
                _, err = utils.execute('mount',
                                       '-o',
                                       'loop,uid=%d,gid=%d' % (os.getuid(),
                                                               os.getgid()),
                                       iso_path, tmpdir,
                                       run_as_root=True)
                mounted = True

                # Copy and adjust the files from the ISO so that we
                # dont have the ISO mounted during the life cycle of the
                # instance and the directory can be removed once the instance
                # is terminated
                for ent in os.listdir(tmpdir):
                    shutil.copytree(os.path.join(tmpdir, ent),
                                    os.path.join(configdrive_dir, ent))
                utils.execute('chmod', '-R', '775', configdrive_dir,
                              run_as_root=True)
                utils.execute('chown', '-R', '%s:%s'
                              % (self._uid_map('/etc/subuid').rstrip(),
                                 self._uid_map('/etc/subgid').rstrip()),
                              configdrive_dir, run_as_root=True)
            finally:
                if mounted:
                    utils.execute('umount', tmpdir, run_as_root=True)

    def plug_vifs(self, instance, network_info):
        """Setup the container network on the host

         :param instance: nova instance object
         :param network_info: instance network configuration
         """
        LOG.debug('plug_vifs called for instance', instance=instance)
        try:
            for viface in network_info:
                self.vif_driver.plug(instance, viface)
            self.start_firewall(instance, network_info)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to configure container network'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

    def unplug_vifs(self, instance, network_info):
        """Unconfigure the LXD container network

           :param instance: nova intance object
           :param network_info: instance network confiugration
        """
        try:
            for viface in network_info:
                self.vif_driver.unplug(instance, viface)
            self.stop_firewall(instance, network_info)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to remove container network'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True):
        """Cleanup a contianer after its been deleted.

        :param context: security context
        :param instance: Instance object as returned by DB layer.
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices that should
                                  be detached from the instance.
        :param destroy_disks: Indicates if disks should be destroyed
        :param migrate_data: implementation specific params
        """
        LOG.debug('cleanup called for instance', instance=instance)
        try:
            if destroy_vifs:
                self.unplug_vifs(instance, network_info)

            name = pwd.getpwuid(os.getuid()).pw_name
            configdrive_dir = \
                self.container_dir.get_container_configdrive(instance.name)
            if os.path.exists(configdrive_dir):
                utils.execute('chown', '-R', '%s:%s' % (name, name),
                              configdrive_dir, run_as_root=True)
                shutil.rmtree(configdrive_dir)

            container_dir = self.container_dir.get_instance_dir(instance.name)
            if os.path.exists(container_dir):
                shutil.rmtree(container_dir)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Container cleanup failed for '
                                  '%(instance)s: %(ex)s'),
                              {'instance': instance.name,
                               'ex': ex}, instance=instance)

    def get_console_output(self, context, instance):
        """Get console output for an instance
        :param context: security context
        :param instance: nova.objects.instance.Instance
        """
        LOG.debug('get_console_output called for instance', instance=instance)
        try:
            console_log = self.container_dir.get_console_path(instance.name)
            if not os.path.exists(console_log):
                return ""
            uid = pwd.getpwuid(os.getuid()).pw_uid
            utils.execute('chown', '%s:%s' % (uid, uid),
                          console_log, run_as_root=True)
            utils.execute('chmod', '755',
                          os.path.join(
                              self.container_dir.get_container_dir(
                                  instance.name), instance.name),
                          run_as_root=True)
            with open(console_log, 'rb') as fp:
                log_data, remaning = utils.last_bytes(fp,
                                                      MAX_CONSOLE_BYTES)
                return log_data
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to get container output'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

    def start_firewall(self, instance, network_info):
        self.firewall_driver.setup_basic_filtering(instance, network_info)
        self.firewall_driver.prepare_instance_filter(instance, network_info)
        self.firewall_driver.apply_instance_filter(instance, network_info)

    def stop_firewall(self, instance, network_info):
        self.firewall_driver.unfilter_instance(instance, network_info)

    def _uid_map(self, subuid_f):
        LOG.debug('Checking for subuid')

        line = None
        with open(subuid_f, 'r') as fp:
            name = pwd.getpwuid(os.getuid()).pw_name
            for cline in fp:
                if cline.startswith(name + ":"):
                    line = cline
                    break
            if line is None:
                raise ValueError("%s not found in %s" % (name, subuid_f))
            toks = line.split(":")
            return toks[1]
