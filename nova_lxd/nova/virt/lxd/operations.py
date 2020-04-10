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
from nova.virt import hardware
import os
import pwd
import socket
import shutil

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import fileutils
from oslo_utils import units
from pylxd.deprecated import exceptions as lxd_exceptions

from nova import exception
from nova import i18n
from nova import utils
from nova.compute import power_state
from nova.compute import task_states

from nova_lxd.nova.virt.lxd import config as container_config
from nova_lxd.nova.virt.lxd import container_firewall
from nova_lxd.nova.virt.lxd import image
from nova_lxd.nova.virt.lxd import session
from nova_lxd.nova.virt.lxd import utils as container_dir
from nova_lxd.nova.virt.lxd import vif

_ = i18n._
_LE = i18n._LE
_LW = i18n._LW
_LI = i18n._LI

CONF = cfg.CONF
CONF.import_opt('vif_plugging_timeout', 'nova.virt.driver')
CONF.import_opt('vif_plugging_is_fatal', 'nova.virt.driver')
allow_ptp_device = cfg.StrOpt(
    'allow_ptp_device',
    help='Mount path of ptp device '
         'The format is (allow_ptp_device = /dev/xxx).')
ALL_OPTS = [allow_ptp_device]

CONF.register_opts(ALL_OPTS)

LOG = logging.getLogger(__name__)

MAX_CONSOLE_BYTES = 100 * units.Ki


class LXDContainerOperations(object):
    """LXD container operations."""

    def __init__(self, virtapi):
        self.virtapi = virtapi

        self.nbd_dev_cache = {}
        self.config = container_config.LXDContainerConfig()
        self.container_dir = container_dir.LXDContainerDirectories()
        self.image = image.LXDContainerImage()
        self.firewall_driver = container_firewall.LXDContainerFirewall()
        self.session = session.LXDAPISession()

        self.vif_driver = vif.LXDGenericDriver()
        self.instance_dir = None

    def list_instances(self):
        return self.session.container_list()

    def list_instance_uuids(self):
        uuids = []
        instances = self.session.container_list()
        for instance in instances:
            client = self.session.get_session()
            profile = client.profile_show(instance)
            uuid = profile[1]['metadata']['config']['environment.product_name']
            uuids.append(uuid)

        return uuids

    def rebuild(self, context, instance, image_meta, injected_files,
                admin_password, bdms, detach_block_devices,
                attach_block_devices, network_info=None,
                recreate=False, block_device_info=None,
                preserve_ephemeral=False):
        LOG.debug('Rebuild called for instance', instance=instance)

        if not recreate:
            self.destroy(context, instance, network_info, block_device_info)
            instance.task_state = task_states.REBUILD_SPAWNING
            instance.save(expected_task_state=[task_states.REBUILDING])
            self.spawn(context, instance, image_meta, injected_files,
                       admin_password, network_info, block_device_info)
            return

        instance_dir = '/var/lib/lxd/storage-pools/pool/containers/%s/' % instance.name
        if os.path.exists(instance_dir):
            return

        try:
            instance.task_state = task_states.REBUILD_SPAWNING
            instance.save(expected_task_state=[task_states.REBUILDING])
            # Ensure that the instance directory exists
            if not os.path.exists(instance_dir):
                fileutils.ensure_tree(instance_dir)

            images = 'container_%s' % instance.name

            path, err = utils.trycmd('rbd', 'map', '-p', 'pool', '--image', images, discard_warnings=True,
                                    run_as_root=True)
            if err:
                LOG.error('Detaching from erroneous rbd device returned, error: %s', err)
                return

            out, err = utils.trycmd('nsenter', '-t', '1', '-m', 'mount', path.split('\n')[0], instance_dir,
                                    discard_warnings=True, run_as_root=True)

            # Step 1 - Setup the profile on the dest host
            if not self.session.profile_defined(instance.name, instance):
                container_profile = self.config.create_profile(instance,
                                                               network_info)
                self.session.profile_create(container_profile, instance)

            # Step 2 - import container
            out, err = utils.trycmd('nsenter', '-t', '1', '-m', 'lxd', 'import', instance.name, '--force',
                                    discard_warnings=True, run_as_root=True)

            # Step 3 - Start contianer
            self.session.container_start(instance.name, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Migration failed for %(instance)s: '
                                  '%(ex)s'),
                              {'instance': instance.name,
                               'ex': ex}, instance=instance)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password=None, network_info=None, block_device_info=None):
        """Start the LXD container

        Once this successfully completes, the instance should be
        running (power_state.RUNNING).

        If this fails, any partial instance should be completely
        cleaned up, and the virtualization platform should be in the state
        that it was before this call began.

        :param context: security context
        :param instance: nova.objects.instance.Instance
                         This function should use the data there to guide
                         the creation of the new instance.
        :param image_meta: image object returned by nova.image.glance that
                           defines the image from which to boot this instance
        :param injected_files: User files to inject into instance.
        :param admin_password: Administrator password to set in instance.
        :param network_info:
            :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices to be
                                  attached to the instance
        """
        msg = ('Spawning container '
               'network_info=%(network_info)s '
               'image_meta=%(image_meta)s '
               'instance=%(instance)s '
               'block_device_info=%(block_device_info)s' %
               {'network_info': network_info,
                'instance': instance,
                'image_meta': image_meta,
                'block_device_info': block_device_info})
        LOG.debug(msg, instance=instance)

        instance_name = instance.name

        if self.session.container_defined(instance_name, instance):
            raise exception.InstanceExists(name=instance.name)

        try:

            # Ensure that the instance directory exists
            self.instance_dir = \
                self.container_dir.get_instance_dir(instance_name)
            if not os.path.exists(self.instance_dir):
                fileutils.ensure_tree(self.instance_dir)

            # Step 1 - Fetch the image from glance
            self._fetch_image(context, instance, image_meta)

            # Step 2 - Setup the container network
            self._setup_network(instance_name, instance, network_info)

            # Step 3 - Create the container profile
            self._setup_profile(instance_name, instance, network_info)

            # Step 4 - Create a config drive (optional)
            if configdrive.required_by(instance):
                self._add_configdrive(instance, injected_files)

            # Step 5 - Configure and start the container
            self._setup_container(instance_name, instance)

            if CONF.allow_ptp_device is not None:
                ptp_device_path = CONF.allow_ptp_device
                disk = os.stat(os.path.realpath(ptp_device_path))

                device_allow = "c %s:%s rwm" % (os.major(disk.st_rdev), os.minor(disk.st_rdev))
                device_allow_path = '/sys/fs/cgroup/devices/lxc.payload/%s/devices.allow' % instance.name
                if os.path.exists(device_allow_path):
                    with open(device_allow_path, 'a') as f:
                        f.write(device_allow)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Faild to start container '
                              '%(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)
                self.destroy(context, instance, network_info)

    def _fetch_image(self, context, instance, image_meta):
        """Fetch the LXD image from glance

        :param context: nova security context
        :param instance: nova instance object
        :param image_meta: nova image opbject
        """
        LOG.debug('_fetch_image called for instance', instance=instance)
        try:
            # Download the image from glance and upload the image
            # to the local LXD image store.
            self.image.setup_image(context, instance, image_meta)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Upload image failed for %(instance)s '
                              'for %(image)s: %(e)s'),
                          {'instance': instance.name,
                           'image': instance.image_ref,
                           'ex': ex}, instance=instance)

    def _setup_network(self, instance_name, instance, network_info):
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

    def _setup_profile(self, instance_name, instance, network_info):
        """Create an LXD container profile for the nova intsance

        :param instance_name: nova instance name
        :param instance: nova instance object
        :param network_info: nova instance netowkr configuration
        """
        LOG.debug('_setup_profile called for instance', instance=instance)
        # mount ptp device
        ptp_device_path = None
        if CONF.allow_ptp_device is not None:
            ptp_device_path = CONF.allow_ptp_device
        try:
            # Setup the container profile based on the nova
            # instance object and network objects
            flavor = None
            container_profile = self.config.create_profile(instance,
                                                           network_info, flavor, ptp_device_path)
            self.session.profile_create(container_profile, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to create a profile for'
                              ' %(instance)s: %(ex)s'),
                          {'instance': instance_name,
                           'ex': ex}, instance=instance)

    def _setup_container(self, instance_name, instance):
        """Create and start the LXD container.

        :param instance_name: nova instjace name
        :param instance: nova instance object
        """
        LOG.debug('_setup_container called for instance', instance=instance)
        try:
            # Create the container
            container_config = \
                self.config.create_container(instance)
            self.session.container_init(
                container_config, instance)

            # Start the container
            self.session.container_start(instance_name, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Container creation failed for '
                                  '%(instance)s: %(ex)s'),
                              {'instance': instance.name,
                               'ex': ex}, instance=instance)

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

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        """Reboot a instance on a LXD host

        :param instance: nova.objects.instance.Instance
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param reboot_type: Either a HARD or SOFT reboot
        :param block_device_info: Info pertaining to attached volumes
        :param bad_volumes_callback: Function to handle any bad volumes
            encountered
        """
        LOG.debug('reboot called for instance', instance=instance)
        try:
            self.session.container_reboot(instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Container reboot failed for '
                                  '%(instance)s: %(ex)s'),
                              {'instance': instance.name,
                               'ex': ex}, instance=instance)

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

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        """Destroy the instance on the LXD host

        :param context: security context
        :param instance: Instance object as returned by DB layer.
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices that should
                                  be detached from the instance.
        :param destroy_disks: Indicates if disks should be destroyed
        :param migrate_data: implementation specific params
        """
        LOG.debug('destroy called for instance', instance=instance)
        try:
            hostname = socket.gethostname()
            local = instance.host

            if hostname != local:
                self.session.container_stop(instance.name, instance)
                instance_dir = '/var/lib/lxd/storage-pools/pool/containers/%s/' % instance.name
                if os.path.exists(instance_dir):
                    shutil.rmtree(instance_dir)

                rbd_dir = '/dev/rbd/pool/container_%s' % instance.name
                out, err = utils.trycmd('ls', '-l', rbd_dir, discard_warnings=True,
                                        run_as_root=True)
                arr_out = out.split(' ')
                if arr_out == '':
                    return

                tmp = arr_out[len(arr_out) - 1]
                path = '/dev/%s' % tmp.split('\n')[0].split('/')[2]

                out, err = utils.trycmd('rbd', 'unmap', '-o', 'force', path, discard_warnings=True,
                                        run_as_root=True)

                return

            if instance.name in self.nbd_dev_cache:
                out, err = utils.trycmd('rbd', 'unmap', self.nbd_dev_cache[instance.name], run_as_root=True,
                                        discard_warnings=True)
            else:
                LOG.debug('There is no cloud disk attached to the instance', instance=instance)

            self.session.container_destroy(instance.name,
                                           instance)
            self.session.profile_delete(instance)
            self.cleanup(context, instance, network_info, block_device_info)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to remove container'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

    def power_off(self, instance, timeout=0, retry_interval=0):
        """Power off an instance

        :param instance: nova.objects.instance.Instance
        :param timeout: time to wait for GuestOS to shutdown
        :param retry_interval: How often to signal guest while
                               waiting for it to shutdown
        """
        LOG.debug('power_off called for instance', instance=instance)
        try:
            self.session.container_stop(instance.name,
                                        instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to power_off container'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

    def power_on(self, context, instance, network_info,
                 block_device_info=None):
        """Power on instance

        :param instance: nova.objects.instance.Instance
        """
        LOG.debug('power_on called for instance', instance=instance)
        try:
            self.session.container_start(instance.name, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Container power off for '
                                  '%(instance)s: %(ex)s'),
                              {'instance': instance.name,
                               'ex': ex}, instance=instance)

    def pause(self, instance):
        """Pause an instance

        :param nova.objects.instance.Instance instance:
            The instance which should be paused.
        """
        LOG.debug('pause called for instance', instance=instance)
        try:
            self.session.container_pause(instance.name, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to pause container'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

    def unpause(self, instance):
        """Unpause an instance

        :param nova.objects.instance.Instance instance:
            The instance which should be paused.
        """
        LOG.debug('unpause called for instance', instance=instance)
        try:
            self.session.container_unpause(instance.name, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to unpause container'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

    def suspend(self, context, instance):
        """Suspend an instance

        :param context: nova security context
        :param nova.objects.instance.Instance instance:
            The instance which should be paused.
        """
        LOG.debug('suspend called for instance', instance=instance)
        try:
            self.session.container_pause(instance.name, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Container suspend failed for '
                                  '%(instance)s: %(ex)s'),
                              {'instance': instance.name,
                               'ex': ex}, instance=instance)

    def resume(self, context, instance, network_info, block_device_info=None):
        """Resume an instance on an LXD host

        :param nova.context.RequestContext context:
            The context for the resume.
        :param nova.objects.instance.Instance instance:
            The suspended instance to resume.
        :param nova.network.model.NetworkInfo network_info:
            Necessary network information for the resume.
        :param dict block_device_info:
            Instance volume block device info.
        """
        LOG.debug('resume called for instance', instance=instance)
        try:
            self.session.container_unpause(instance.name, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to resume container'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        """Rescue an instance

        :param instance: nova.objects.instance.Instance
        """
        LOG.debug('rescue called for instance', instance=instance)
        try:
            if not self.session.container_defined(instance.name, instance):
                msg = _('Unable to find instance')
                raise exception.NovaException(msg)

            # Step 1 - Stop the old container
            self.session.container_stop(instance.name, instance)

            # Step 2 - Rename the broken contianer to be rescued
            self.session.container_move(instance.name,
                                        {'name': '%s-backup' % instance.name},
                                        instance)

            # Step 3 - Re use the old instance object and confiugre
            #          the disk mount point and create a new container.
            container_config = self.config.create_container(instance)
            rescue_dir = self.container_dir.get_container_rescue(
                instance.name + '-backup')
            config = self.config.configure_disk_path(rescue_dir,
                                                     'mnt', 'rescue', instance)
            container_config['devices'].update(config)
            self.session.container_init(container_config, instance)

            # Step 4 - Start the rescue instance
            self.session.container_start(instance.name, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Container rescue failed for '
                                  '%(instance)s: %(ex)s'),
                              {'instance': instance.name,
                               'ex': ex}, instance=instance)

    def unrescue(self, instance, network_info):
        """Unrescue a LXD host

        :param instance: nova instance object
        :param network_info: nova network configuration
        """
        LOG.debug('unrescue called for instance', instance=instance)
        try:
            if not self.session.container_defined(instance.name, instance):
                msg = _('Unable to find instance')
                raise exception.NovaException(msg)

            # Step 1 - Destory the rescue instance.
            self.session.container_destroy(instance.name,
                                           instance)

            # Step 2 - Rename the backup container that
            #          the user was working on.
            self.session.container_move(instance.name + '-backup',
                                        {'name': instance.name},
                                        instance)

            # Step 3 - Start the old contianer
            self.session.container_start(instance.name, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Container unrescue failed for '
                                  '%(instance)s: %(ex)s'),
                              {'instance': instance.name,
                               'ex': ex}, instance=instance)

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

    def get_info(self, instance):
        """Get the current status of an instance, by name (not ID!)

        :param instance: nova.objects.instance.Instance object

        Returns a InstanceInfo object
        """
        LOG.debug('get_info called for instance', instance=instance)
        try:
            if not self.session.container_defined(instance.name, instance):
                return hardware.InstanceInfo(state=power_state.NOSTATE)

            container_state = self.session.container_state(instance)
            return hardware.InstanceInfo(state=container_state['state'],
                                         max_mem_kb=container_state['max_mem'],
                                         mem_kb=container_state['mem'],
                                         num_cpu=instance.flavor.vcpus,
                                         cpu_time_ns=0)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to get container info'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

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

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach block device to a nova instance.

        Attaching a block device to a container requires a couple of steps.
        First os_brick connects the cinder volume to the host. Next,
        the block device is added to the containers profile. Next, the
        apparmor profile for the container is updated to allow mounting
        'ext4' block devices. Finally, the profile is saved.

        The block device must be formatted as ext4 in order to mount
        the block device inside the container.

        See `nova.virt.driver.ComputeDriver.attach_volume' for
        more information/
        """
        LOG.debug('attach_volume called for instance', instance=instance)
        profile = self.session.profile_show(instance)
        protocol = connection_info['driver_volume_type']
        device_path = self._connect_volume(protocol, connection_info, instance)
        disk = os.stat(os.path.realpath(device_path))
        vol_id = connection_info['data']['volume_id']

        disk_device = {
            vol_id: {
                'path': mountpoint,
                'major': '%s' % os.major(disk.st_rdev),
                'minor': '%s' % os.minor(disk.st_rdev),
                'type': 'unix-block'
            }
        }

        profile['devices'].update(disk_device)
        # XXX zulcss (10 Jul 2016) - fused is currently not supported.
        config = {'raw.apparmor': 'mount fstype=ext4,', 'security.privileged': 'true'}
        profile['config'].update(config)
        self.session.profile_update(profile, instance)
        self.session.container_reboot(instance)

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach block device from a nova instance.

        First the volume id is deleted from the profile, and the
        profile is saved. The os-brick disconnects the volume
        from the host.

        See `nova.virt.driver.Computedriver.detach_volume` for
        more information.
        """
        LOG.debug('detach_volume called for instance', instance=instance)
        profile = self.session.profile_show(instance)
        vol_id = connection_info['data']['volume_id']
        if vol_id in profile['devices']:
            del profile['devices'][vol_id]
            del profile['config']['raw.apparmor']
            try:
                self.session.profile_update(profile, instance)
            except lxd_exceptions.APIError as ex:
                LOG.warn(_LW('Failed to update container profile'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)
            finally:
                self.session.container_reboot(instance)
                protocol = connection_info['driver_volume_type']
                # storage_driver = brick_get_connector(protocol)
                # storage_driver.disconnect_volume(connection_info, None)
                self._disconnect_volume(protocol, instance)

    def _connect_volume(self, protocol, connection_info, instance):
        """Wrapper to get a brick connector object.
        This automatically populates the required protocol as well
        as the root_helper needed to execute commands.
        """
        if protocol.upper() == "RBD":
            pool, image = connection_info['data']['name'].split('/')  # 'volumes'
            # image = 'volume-730bc233-b4a5-457e-bba1-89b25d2636f0'
            # rbd feature disable volumes/volume-7653bc2d-41be-4f53-a4ae-605a5545d248 object-map fast-diff deep-flatten
            out, err = utils.trycmd('rbd', '-p', pool, 'feature', 'disable', image, 'exclusive-lock', 'object-map',
                                    'fast-diff', 'deep-flatten', discard_warnings=True, run_as_root=True)
            out, err = utils.trycmd('rbd', '-p', pool, 'map', image, discard_warnings=True,
                                    run_as_root=True)
            if err:
                LOG.warn(_LW('Detaching from erroneous rbd device returned'
                             'error: %s'), err)
                return
            instance_name = instance.name
            self.nbd_dev_cache[instance_name] = out.split('\n')[0]
            return out.split('\n')[0]
        else:
            LOG.warn(_LW('Unsupported protocol'))
            return

    def _disconnect_volume(self, protocol, instance):
        """Wrapper to get a brick connector object.
        This automatically populates the required protocol as well
        as the root_helper needed to execute commands.
        """
        instance_name = instance.name
        if protocol.upper() == "RBD":
            out, err = utils.trycmd('rbd', 'unmap', self.nbd_dev_cache[instance_name], run_as_root=True,
                                    discard_warnings=True)
        else:
            LOG.warn(_LW('Unsupported protocol'))
            return

    def container_attach_interface(self, instance, image_meta, vif):
        LOG.debug('container_attach_interface called for instance',
                  instance=instance)
        try:
            self.vif_driver.plug(instance, vif)
            self.firewall_driver.setup_basic_filtering(instance, vif)

            container_config = self.config.create_container(instance)
            container_network = self.config.create_container_net_device(
                instance, vif)
            container_config['devices'].update(container_network)
            self.session.container_update(container_config, instance)
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                self.vif_driver.unplug(instance, vif)
                LOG.error(_LE('Failed to configure network'
                              ' for %(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

    def container_detach_interface(self, instance, vif):
        LOG.debug('container_defatch_interface called for instance',
                  instance=instance)
        try:
            self.vif_driver.unplug(instance, vif)
            config = self.session.container_config(instance)

            for key, val in config['devices'].items():
                if val.get('hwaddr') == vif['address']:
                    del config['devices'][key]
                    self.session.container_update(config, instance)
                    break

        except exception.NovaException:
            pass

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
