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

from __future__ import absolute_import

import errno
import os
import pwd
import shutil
import socket
import eventlet
import nova.conf

from nova import exception
from nova import i18n
from nova import utils
from nova import image as nova_image
from nova.virt import driver
from nova.virt import hardware
from nova.virt import configdrive
from nova.objects import migrate_data
from nova.compute import power_state
from nova.compute import vm_states
from nova.compute import task_states
from nova.api.metadata import base as instance_metadata

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import fileutils
from oslo_utils import units
from os_brick.initiator import connector
from oslo_concurrency import lockutils
from oslo_concurrency import processutils
from oslo_serialization import jsonutils

import pylxd
from pylxd import exceptions as lxd_exceptions

from ..lxd import container_firewall
from ..lxd import common
from ..lxd import host
from ..lxd import storage
from ..lxd import flavor
from ..lxd import image
from ..lxd import vif as lxd_vif

_ = i18n._
_LE = i18n._LE
_LI = i18n._LI

lxd_opts = [
    cfg.StrOpt('root_dir',
               default='/var/snap/lxd/common/lxd/',
               help='Default LXD directory'),
    cfg.IntOpt('timeout',
               default=-1,
               help='Default LXD timeout'),
    cfg.IntOpt('retry_interval',
               default=2,
               help='How often to retry in seconds when a'
                    'request does conflict'),
]

CONF = cfg.CONF
CONF.register_opts(lxd_opts, 'lxd')
LOG = logging.getLogger(__name__)
MAX_CONSOLE_BYTES = 100 * units.Ki
NOVA_CONF = nova.conf.CONF
IMAGE_API = nova_image.API()


def _last_bytes(file_like_object, num):
    """Return num bytes from the end of the file, and remaning byte count.

    :param file_like_object: The file to read
    :param num: The number of bytes to return

    :returns: (data, remaining)
    """

    try:
        file_like_object.seek(-num, os.SEEK_END)
    except IOError as e:
        # seek() fails with EINVAL when trying to go before the start of
        # the file. It means that num is larger than the file size, so
        # just go to the start.
        if e.errno == errno.EINVAL:
            file_like_object.seek(0, os.SEEK_SET)
        else:
            raise

    remaining = file_like_object.tell()
    return (file_like_object.read(), remaining)


def _neutron_failed_callback(event_name, instance):
    LOG.error("Neutron Reported failure on event "
              "{event} for instance {uuid}"
              .format(event=event_name, uuid=instance.name),
              instance=instance)
    if CONF.vif_plugging_is_fatal:
        raise exception.VirtualInterfaceCreateException()


def _get_power_state(lxd_state):
    """Take a lxd state code and translate it to nova power state."""
    state_map = [
        (power_state.RUNNING, {100, 101, 103, 200}),
        (power_state.SHUTDOWN, {102, 104, 107}),
        (power_state.NOSTATE, {105, 106, 401}),
        (power_state.CRASHED, {108, 400}),
        (power_state.SUSPENDED, {109, 110, 111}),
    ]
    for nova_state, lxd_states in state_map:
        if lxd_state in lxd_states:
            return nova_state
    raise ValueError('Unknown LXD power state: {}'.format(lxd_state))


def brick_get_connector(protocol, driver=None,
                        use_multipath=False,
                        device_scan_attempts=3,
                        *args, **kwargs):
    """Wrapper to get a brick connector object.
    This automatically populates the required protocol as well
    as the root_helper needed to execute commands.
    """

    root_helper = utils.get_root_helper()
    if protocol.upper() == "RBD":
        kwargs['do_local_attach'] = True
    return connector.InitiatorConnector.factory(
        protocol, root_helper,
        driver=driver,
        use_multipath=use_multipath,
        device_scan_attempts=device_scan_attempts,
        *args, **kwargs)


class LXDLiveMigrateData(migrate_data.LiveMigrateData):
    """LiveMigrateData for LXD."""

    VERSION = '1.0'
    fields = {}


class LXDDriver(driver.ComputeDriver):

    """LXD Lightervisor."""

    capabilities = {
        "has_imagecache": False,
        "supports_recreate": False,
        "supports_migrate_to_same_host": False,
    }

    def __init__(self, virtapi):
        self.virtapi = virtapi

        self.vif_driver = lxd_vif.LXDGenericDriver()
        self.image = image.LXDContainerImage()
        self.container_firewall = container_firewall.LXDContainerFirewall()
        self.host = host.LXDHost()

    def init_host(self, host):
        return self.host.init_host(host)

    def get_info(self, instance):
        """Return an InstanceInfo object for the instance."""
        try:
            container = self.host.client.containers.get(instance.name)
        except lxd_exceptions.NotFound:
            raise exception.InstanceNotFound(instance_id=instance.uuid)

        state = container.state()
        return hardware.InstanceInfo(
            state=_get_power_state(state.status_code))

    def list_instances(self):
        LOG.info('container_list called')
        try:
            client = self.host.client
            containers = client.containers.all()
            for container in containers:
                LOG.info(_LI("LXD container list: '%s'"), container.name)

            return [c.name for c in client.containers.all()]
        except lxd_exceptions.APIError as ex:
            msg = _('Failed to communicate with LXD API: %(reason)s') \
                  % {'reason': ex}
            LOG.error(msg)
            raise exception.NovaException(msg)

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        for vif in network_info:
            self.vif_driver.plug(instance, vif)

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        for vif in network_info:
            try:
                self.vif_driver.unplug(instance, vif)
            except exception.NovaException:
                pass

    def estimate_instance_overhead(self, instance_info):
        return {'memory_mb': 0}

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """Create a new lxd container as a nova instance.

                Creating a new container requires a number of steps. First, the
                image is fetched from glance, if needed. Next, the network is
                connected. A profile is created in LXD, and then the container
                is created and started.

                See `nova.virt.driver.ComputeDriver.spawn` for more
                information.
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
        LOG.info(msg, instance=instance)

        try:
            LOG.info("Check to see if LXD instance '%s' already exit.", instance.name)
            self.host.client.containers.get(instance.name)
            raise exception.InstanceExists(name=instance.name)
        except lxd_exceptions.LXDAPIException as e:
            if e.response.status_code != 404:
                raise  # Re-raise the exception if it wasn't NotFound

        # Check to see if LXD instance dir already exit. If not, fetch it.
        LOG.info("Check to see if LXD instance dir '%s' already exit.", common.InstanceAttributes(instance).instance_dir)
        instance_dir = common.InstanceAttributes(instance).instance_dir
        if not os.path.exists(instance_dir):
            fileutils.ensure_tree(instance_dir)

        # Check to see if LXD already has a copy of the image. If not,
        # fetch it.
        try:
            LOG.info("Check to see if LXD image '%s' already exit.",
                     self.host.client.images.get_by_alias(instance.image_ref))
            self.host.client.images.get_by_alias(instance.image_ref)
        except lxd_exceptions.LXDAPIException as e:
            if e.response.status_code != 404:
                raise
            self.image.sync_glance_image_to_lxd(
                self.host.client, context, image_meta, instance.image_ref)

        # Setup the network when creating the lXD container
        if network_info:
            timeout = CONF.vif_plugging_timeout
            if (utils.is_neutron() and timeout):
                events = [('network-vif-plugged', vif['id'])
                          for vif in network_info if not vif.get(
                        'active', True)]
            else:
                events = []

            try:
                with self.virtapi.wait_for_instance_event(
                        instance, events, deadline=timeout,
                        error_callback=_neutron_failed_callback):
                    self.plug_vifs(instance, network_info)
            except eventlet.timeout.Timeout:
                LOG.warn("Timeout waiting for vif plugging callback for "
                         "instance {uuid}"
                         .format(uuid=instance['name']))
                if CONF.vif_plugging_is_fatal:
                    self.destroy(
                        context, instance, network_info, block_device_info)
                    raise exception.InstanceDeployFailure(
                        'Timeout waiting for vif plugging',
                        instance_id=instance['name'])

        # Create an LXD container profile for the nova intsance
        try:
            profile = flavor.to_profile(
                self.host.client, instance, network_info, block_device_info)
        except lxd_exceptions.LXDAPIException as e:
            with excutils.save_and_reraise_exception():
                self.cleanup(
                    context, instance, network_info, block_device_info)

        # Create the container
        container_config = {
            'name': instance.name,
            'profiles': [profile.name],
            'source': {
                'type': 'image',
                'alias': instance.image_ref,
            },
        }
        try:
            container = self.host.client.containers.create(
                container_config, wait=True)
        except lxd_exceptions.LXDAPIException as e:
            with excutils.save_and_reraise_exception():
                self.cleanup(
                    context, instance, network_info, block_device_info)

        lxd_config = self.host.client.host_info
        storage.attach_ephemeral(
            self.host.client, block_device_info, lxd_config, instance)
        if configdrive.required_by(instance):
            configdrive_path = self._add_configdrive(
                context, instance,
                injected_files, admin_password,
                network_info)

            profile = self.host.client.profiles.get(instance.name)
            config_drive = {
                'configdrive': {
                    'path': '/config-drive',
                    'source': configdrive_path,
                    'type': 'disk',
                    'readonly': 'True',
                }
            }
            profile.devices.update(config_drive)
            profile.save()

        try:
            self.firewall_driver.setup_basic_filtering(
                instance, network_info)
            self.firewall_driver.instance_filter(
                instance, network_info)

            container.start(wait=True)

            self.firewall_driver.apply_instance_filter(
                instance, network_info)
        except lxd_exceptions.LXDAPIException:
            with excutils.save_and_reraise_exception():
                try:
                    self.cleanup(
                        context, instance, network_info, block_device_info)
                except Exception as e:
                    LOG.warn('The cleanup process failed with: %s. This '
                             'error may or not may be relevant', e)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        """Destroy a running instance.

                Since the profile and the instance are created on `spawn`, it is
                safe to delete them together.

                See `nova.virt.driver.ComputeDriver.destroy` for more
                information.
                """
        lock_path = os.path.join(CONF.instances_path, 'locks')

        with lockutils.lock(
                lock_path, external=True,
                lock_file_prefix='lxd-container-{}'.format(instance.name)):
            # TODO(sahid): Each time we get a container we should
            # protect it by using a mutex.
            try:
                container = self.host.client.containers.get(instance.name)
                if container.status != 'Stopped':
                    container.stop(wait=True)
                container.delete(wait=True)
                if (instance.vm_state == vm_states.RESCUED):
                    rescued_container = self.host.client.containers.get(
                        '{}-rescue'.format(instance.name))
                    if rescued_container.status != 'Stopped':
                        rescued_container.stop(wait=True)
                    rescued_container.delete(wait=True)
            except lxd_exceptions.LXDAPIException as e:
                if e.response.status_code == 404:
                    LOG.warning("Failed to delete instance. "
                                "Container does not exist for {instance}."
                                .format(instance=instance.name))
                else:
                    raise
            finally:
                self.cleanup(
                    context, instance, network_info, block_device_info)

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True):
        """Clean up the filesystem around the container.

                See `nova.virt.driver.ComputeDriver.cleanup` for more
                information.
                """
        if destroy_vifs:
            self.unplug_vifs(instance, network_info)
            self.firewall_driver.unfilter_instance(instance, network_info)

        lxd_config = self.host.client.host_info
        storage.detach_ephemeral(self.host.client,
                                 block_device_info,
                                 lxd_config,
                                 instance)

        name = pwd.getpwuid(os.getuid()).pw_name

        container_dir = common.InstanceAttributes(instance).instance_dir
        if os.path.exists(container_dir):
            utils.execute(
                'chown', '-R', '{}:{}'.format(name, name),
                container_dir, run_as_root=True)
            shutil.rmtree(container_dir)

        try:
            self.host.client.profiles.get(instance.name).delete()
        except lxd_exceptions.LXDAPIException as e:
            if e.response.status_code == 404:
                LOG.warning("Failed to delete instance. "
                            "Profile does not exist for {instance}."
                            .format(instance=instance.name))
            else:
                raise

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        """Reboot the container.

                Nova *should* not execute this on a stopped container, but
                the documentation specifically says that if it is called, the
                container should always return to a 'Running' state.

                See `nova.virt.driver.ComputeDriver.cleanup` for more
                information.
                """
        container = self.host.client.containers.get(instance.name)
        container.restart(force=True, wait=True)

    def get_console_output(self, context, instance):
        """Get the output of the container console.

                See `nova.virt.driver.ComputeDriver.get_console_output` for more
                information.
                """
        instance_attrs = common.InstanceAttributes(instance)
        console_path = instance_attrs.console_path
        if not os.path.exists(console_path):
            return ''
        uid = pwd.getpwuid(os.getuid()).pw_uid
        utils.execute(
            'chown', '%s:%s' % (uid, uid), console_path, run_as_root=True)
        utils.execute(
            'chmod', '755', instance_attrs.container_path, run_as_root=True)
        with open(console_path, 'rb') as f:
            log_data, _ = _last_bytes(f, MAX_CONSOLE_BYTES)
            return log_data

    def get_diagnostics(self, instance):
        raise NotImplementedError()

    def get_instance_diagnostics(self, instance):
        raise NotImplementedError()

    def get_all_bw_counters(self, instances):
        raise NotImplementedError()

    def get_all_volume_usage(self, context, compute_host_bdms):
        raise NotImplementedError()

    def get_host_ip_addr(self):
        return self.host.get_host_ip_addr()

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
        profile = self.host.client.profiles.get(instance.name)
        protocol = connection_info['driver_volume_type']
        storage_driver = brick_get_connector(protocol)
        device_info = storage_driver.connect_volume(
            connection_info['data'])
        disk = os.stat(os.path.realpath(device_info['path']))
        vol_id = connection_info['data']['volume_id']

        disk_device = {
            vol_id: {
                'path': mountpoint,
                'major': '%s' % os.major(disk.st_rdev),
                'minor': '%s' % os.minor(disk.st_rdev),
                'type': 'unix-block'
            }
        }

        profile.devices.update(disk_device)
        # XXX zulcss (10 Jul 2016) - fused is currently not supported.
        profile.config.update({'raw.apparmor': 'mount fstype=ext4,'})
        profile.save()

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach block device from a nova instance.

                First the volume id is deleted from the profile, and the
                profile is saved. The os-brick disconnects the volume
                from the host.

                See `nova.virt.driver.Computedriver.detach_volume` for
                more information.
                """
        profile = self.host.client.profiles.get(instance.name)
        vol_id = connection_info['data']['volume_id']
        if vol_id in profile.devices:
            del profile.devices[vol_id]
            profile.save()

        protocol = connection_info['driver_volume_type']
        storage_driver = brick_get_connector(protocol)
        storage_driver.disconnect_volume(connection_info['data'], None)

    def attach_interface(self, instance, image_meta, vif):
        self.vif_driver.plug(instance, vif)
        self.container_firewall.setup_basic_filtering(instance, vif)

        profile = self.host.client.profiles.get(instance.name)

        net_device = lxd_vif.get_vif_devname(vif)
        config_update = {
            net_device: {
                'nictype': 'physical',
                'hwaddr': vif['address'],
                'parent': lxd_vif.get_vif_internal_devname(vif),
                'type': 'nic',
            }
        }

        profile.devices.update(config_update)
        profile.save(wait=True)

    def detach_interface(self, instance, vif):
        try:
            profile = self.host.client.profiles.get(instance.name)
            devname = lxd_vif.get_vif_devname(vif)

            # NOTE(jamespage): Attempt to remove device using
            #                  new style tap naming
            if devname in profile.devices:
                del profile.devices[devname]
                profile.save(wait=True)
            else:
                # NOTE(jamespage): For upgrades, scan devices
                #                  and attempt to identify
                #                  using mac address as the
                #                  device will *not* have a
                #                  consistent name
                for key, val in profile.devices.items():
                    if val.get('hwaddr') == vif['address']:
                        del profile.devices[key]
                        profile.save(wait=True)
                        break
        except lxd_exceptions.NotFound:
            # This method is called when an instance get destroyed. It
            # could happen that Nova to receive an event
            # "vif-delete-event" after the instance is destroyed which
            # result the lxd profile not exist.
            LOG.debug("lxd profile for instance {instance} does not exist. "
                      "The instance probably got destroyed before this method "
                      "got called.".format(instance=instance.name))

        self.vif_driver.unplug(instance, vif)

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   flavor, network_info,
                                   block_device_info=None,
                                   timeout=0, retry_interval=0):
        if CONF.my_ip == dest:
            # Make sure that the profile for the container is up-to-date to
            # the actual state of the container.
            flavor.to_profile(
                self.host.client, instance, network_info, block_device_info,
                update=True)
        container = self.host.client.containers.get(instance.name)
        container.stop(wait=True)
        return ''

    def snapshot(self, context, instance, image_id, update_task_state):
        """Create a LXD snapshot  of the instance

                   Steps involved in creating an LXD Snapshot:

                   1. Ensure the container exists
                   2. Stop the LXD container: LXD requires a container
                      to be stopped in or
                   3. Publish the container: Run the API equivalent to
                      'lxd publish container --alias <image_name>' to create
                      a snapshot and upload it to the local LXD image store.
                   4. Create an alias for the image: Create an alias so that
                      nova-lxd can re-use the image that was created.
                   5. Upload the image to glance so that it can bed on other
                      compute hosts.

                  :param context: nova security context
                  :param instance: nova instance object
                  :param image_id: glance image id
                """
        LOG.debug('snapshot called for instance', instance=instance)

        lock_path = str(os.path.join(CONF.instances_path, 'locks'))

        with lockutils.lock(
                lock_path, external=True,
                lock_file_prefix='lxd-container-{}'.format(instance.name)):
            update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)

            container = self.host.client.containers.get(instance.name)
            if container.status != 'Stopped':
                container.stop(wait=True)
            image = container.publish(wait=True)
            container.start(wait=True)

            update_task_state(
                task_state=task_states.IMAGE_UPLOADING,
                expected_state=task_states.IMAGE_PENDING_UPLOAD)

            snapshot = IMAGE_API.get(context, image_id)
            data = image.export()
            image_meta = {'name': snapshot['name'],
                          'disk_format': 'raw',
                          'container_format': 'bare'}
            IMAGE_API.update(context, image_id, image_meta, data)

    def post_interrupted_snapshot_cleanup(self, context, instance):
        pass

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         block_device_info=None, power_on=True):
        # Ensure that the instance directory exists
        instance_dir = common.InstanceAttributes(instance).instance_dir
        if not os.path.exists(instance_dir):
            fileutils.ensure_tree(instance_dir)

        # Step 1 - Setup the profile on the dest host
        flavor.to_profile(self.host.client,
                          instance, network_info, block_device_info)

        # Step 2 - Open a websocket on the srct and and
        #          generate the container config
        self._migrate(migration['source_compute'], instance)

        # Step 3 - Start the network and container
        self.plug_vifs(instance, network_info)
        self.host.client.container.get(instance.name).start(wait=True)

    def _migrate(self, source_host, instance):
        """Migrate an instance from source."""
        source_client = pylxd.Client(
            endpoint='https://{}'.format(source_host), verify=False)
        container = source_client.containers.get(instance.name)
        data = container.generate_migration_data()

        self.containers.create(data, wait=True)

    def confirm_migration(self, migration, instance, network_info):
        self.unplug_vifs(instance, network_info)

        self.host.client.profiles.get(instance.name).delete()
        self.host.client.containers.get(instance.name).delete(wait=True)

    def finish_revert_migration(self, context, instance, network_info,
                                block_device_info=None, power_on=True):
        self.host.client.containers.get(instance.name).start(wait=True)

    def pause(self, instance):
        """Pause container.

                See `nova.virt.driver.ComputeDriver.pause` for more
                information.
                """
        container = self.host.client.containers.get(instance.name)
        container.freeze(wait=True)

    def unpause(self, instance):
        """Unpause container.

        See `nova.virt.driver.ComputeDriver.unpause` for more
        information.
        """
        container = self.host.client.containers.get(instance.name)
        container.unfreeze(wait=True)

    def suspend(self, context, instance):
        """Suspend container.

        See `nova.virt.driver.ComputeDriver.suspend` for more
        information.
        """
        self.pause(instance)

    def resume(self, context, instance, network_info, block_device_info=None):
        """Resume container.

                See `nova.virt.driver.ComputeDriver.resume` for more
                information.
                """
        self.unpause(instance)

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        """Rescue a LXD container.

                From the perspective of nova, rescuing a instance requires a number of
                steps. First, the failed container is stopped, and then this method is
                called.

                So the original container is already stopped, and thus, next,
                '-rescue', is appended to the failed container's name, this is done so
                the container can be unrescued. The container's profile is updated with
                the rootfs of the failed container. Finally, a new container is created
                and started.

                See 'nova.virt.driver.ComputeDriver.rescue` for more
                information.
                """
        rescue = '%s-rescue' % instance.name

        container = self.host.client.containers.get(instance.name)
        container_rootfs = os.path.join(
            nova.conf.CONF.lxd.root_dir, 'containers', instance.name, 'rootfs')
        container.rename(rescue, wait=True)

        profile = self.host.client.profiles.get(instance.name)

        rescue_dir = {
            'rescue': {
                'source': container_rootfs,
                'path': '/mnt',
                'type': 'disk',
            }
        }
        profile.devices.update(rescue_dir)
        profile.save()

        container_config = {
            'name': instance.name,
            'profiles': [profile.name],
            'source': {
                'type': 'image',
                'alias': instance.image_ref,
            }
        }
        container = self.host.client.containers.create(
            container_config, wait=True)
        container.start(wait=True)

    def unrescue(self, instance, network_info):
        """Unrescue an instance.

                Unrescue a container that has previously been rescued.
                First the rescue containerisremoved. Next the rootfs
                of the defective container is removed from the profile.
                Finally the container is renamed and started.

                See 'nova.virt.drvier.ComputeDriver.unrescue` for more
                information.
                """
        rescue = '%s-rescue' % instance.name

        container = self.host.client.containers.get(instance.name)
        if container.status != 'Stopped':
            container.stop(wait=True)
        container.delete(wait=True)

        profile = self.host.client.profiles.get(instance.name)
        del profile.devices['rescue']
        profile.save()

        container = self.host.client.containers.get(rescue)
        container.rename(instance.name, wait=True)
        container.start(wait=True)

    def power_off(self, instance, timeout=0, retry_interval=0):
        """Power off an instance

                See 'nova.virt.drvier.ComputeDriver.power_off` for more
                information.
                """
        container = self.host.client.containers.get(instance.name)
        if container.status != 'Stopped':
            container.stop(wait=True)

    def power_on(self, context, instance, network_info,
                 block_device_info=None):
        """Power on an instance

                See 'nova.virt.drvier.ComputeDriver.power_on` for more
                information.
                """
        container = self.host.client.containers.get(instance.name)
        if container.status != 'Running':
            container.start(wait=True)

    def soft_delete(self, instance):
        raise NotImplementedError()

    def get_available_resource(self, nodename):
        return self.host.get_available_resource(nodename)

    def pre_live_migration(self, context, instance, block_device_info,
                           network_info, disk_info, migrate_data=None):
        for vif in network_info:
            self.vif_driver.plug(instance, vif)
        self.firewall_driver.setup_basic_filtering(
            instance, network_info)
        self.firewall_driver.prepare_instance_filter(
            instance, network_info)
        self.firewall_driver.apply_instance_filter(
            instance, network_info)

        flavor.to_profile(self.host.client,
                          instance, network_info, block_device_info)

    def live_migration(self, context, instance, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        self._migrate(dest, instance)
        post_method(context, instance, dest, block_migration)

    def post_live_migration(self, context, instance, block_device_info,
                            migrate_data=None):
        self.host.client.containers.get(instance.name).delete(wait=True)

    def post_live_migration_at_source(self, context, instance, network_info):
        self.host.client.profiles.get(instance.name).delete()
        self.cleanup(context, instance, network_info)

    def post_live_migration_at_destination(self, context, instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        raise NotImplementedError()

    def check_instance_shared_storage_local(self, context, instance):
        raise NotImplementedError()

    def check_instance_shared_storage_remote(self, context, data):
        raise NotImplementedError()

    def check_instance_shared_storage_cleanup(self, context, data):
        pass

    def check_can_live_migrate_destination(self, context, instance,
                                           src_compute_info, dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        try:
            self.host.client.containers.get(instance.name)
            raise exception.InstanceExists(name=instance.name)
        except lxd_exceptions.LXDAPIException as e:
            if e.response.status_code != 404:
                raise
        return LXDLiveMigrateData()

    def check_can_live_migrate_destination_cleanup(self, context,
                                                   dest_check_data):
        raise NotImplementedError()

    def check_can_live_migrate_source(self, context, instance,
                                      dest_check_data, block_device_info=None):
        if not CONF.lxd.allow_live_migration:
            msg = _("Live migration is not enabled.")
            LOG.error(msg, instance=instance)
            raise exception.MigrationPreCheckError(reason=msg)
        return dest_check_data

    def get_instance_disk_info(self, instance,
                               block_device_info=None):
        raise NotImplementedError()

    def refresh_security_group_rules(self, security_group_id):
        return (self.container_firewall
                .refresh_security_group_rules(security_group_id))

    def refresh_security_group_members(self, security_group_id):
        return (self.container_firewall
                .refresh_security_group_members(security_group_id))

    def refresh_provider_fw_rules(self):
        return self.container_firewall.refresh_provider_fw_rules()

    def refresh_instance_security_rules(self, instance):
        return (self.container_firewall
                .refresh_instance_security_rules(instance))

    def ensure_filtering_rules_for_instance(self, instance, network_info):
        return (self.container_firewall
                .ensure_filtering_rules_for_instance(instance, network_info))

    def filter_defer_apply_on(self):
        return self.container_firewall.filter_defer_apply_on()

    def filter_defer_apply_off(self):
        return self.container_firewall.filter_defer_apply_off()

    def unfilter_instance(self, instance, network_info):
        return self.container_firewall.unfilter_instance(instance,
                                                         network_info)

    def poll_rebooting_instances(self, timeout, instances):
        raise NotImplementedError()

    def host_power_action(self, action):
        raise NotImplementedError()

    def host_maintenance_mode(self, host, mode):
        raise NotImplementedError()

    def set_host_enabled(self, enabled):
        raise NotImplementedError()

    def get_host_uptime(self):
        return self.host.get_host_uptime()

    def get_host_cpu_stats(self):
        return self.host.get_host_cpu_stats()

    def block_stats(self, instance, disk_id):
        raise NotImplementedError()

    def deallocate_networks_on_reschedule(self, instance):
        """Does the driver want networks deallocated on reschedule?"""
        return False

    def macs_for_instance(self, instance):
        return None

    def manage_image_cache(self, context, all_instances):
        pass

    def add_to_aggregate(self, context, aggregate, host, **kwargs):
        raise NotImplementedError()

    def remove_from_aggregate(self, context, aggregate, host, **kwargs):
        raise NotImplementedError()

    def undo_aggregate_operation(self, context, op, aggregate,
                                 host, set_error=True):
        raise NotImplementedError()

    def get_volume_connector(self, instance):
        return {'ip': CONF.my_block_storage_ip,
                'initiator': 'fake',
                'host': 'fakehost'}

    def get_available_nodes(self, refresh=False):
        hostname = socket.gethostname()
        return [hostname]

    def node_is_available(self, nodename):
        if nodename in self.get_available_nodes():
            return True
        # Refresh and check again.
        return nodename in self.get_available_nodes(refresh=True)

    def get_per_instance_usage(self):
        return {}

    def instance_on_disk(self, instance):
        return False

    def volume_snapshot_create(self, context, instance, volume_id,
                               create_info):
        raise NotImplementedError()

    def volume_snapshot_delete(self, context, instance, volume_id,
                               snapshot_id, delete_info):
        raise NotImplementedError()

    def quiesce(self, context, instance, image_meta):
        raise NotImplementedError()

    def unquiesce(self, context, instance, image_meta):
        raise NotImplementedError()

 #
    # LXDDriver "private" implementation methods
    #
    # XXX: rockstar (21 Nov 2016) - The methods and code below this line
    # have not been through the cleanup process. We know the cleanup process
    # is complete when there is no more code below this comment, and the
    # comment can be removed.
    def _add_configdrive(self, context, instance,
                         injected_files, admin_password, network_info):
        """Create configdrive for the instance."""
        if CONF.config_drive_format != 'iso9660':
            raise exception.ConfigDriveUnsupportedFormat(
                format=CONF.config_drive_format)

        container = self.host.client.containers.get(instance.name)
        storage_id = 0
        """
        Determine UID shift used for container uid mapping
        Sample JSON config from LXD
        {
            "volatile.apply_template": "create",
            ...
            "volatile.last_state.idmap": "[
                {
                \"Isuid\":true,
                \"Isgid\":false,
                \"Hostid\":100000,
                \"Nsid\":0,
                \"Maprange\":65536
                },
                {
                \"Isuid\":false,
                \"Isgid\":true,
                \"Hostid\":100000,
                \"Nsid\":0,
                \"Maprange\":65536
                }] ",
            "volatile.tap5fd6808a-7b.name": "eth0"
        }
        """
        container_id_map = jsonutils.loads(
            container.config['volatile.last_state.idmap'])
        uid_map = list(filter(lambda id_map: id_map.get("Isuid"),
                              container_id_map))
        if uid_map:
            storage_id = uid_map[0].get("Hostid", 0)
        else:
            # privileged containers does not have uid/gid mapping
            # LXD API return nothing
            pass

        extra_md = {}
        if admin_password:
            extra_md['admin_pass'] = admin_password

        inst_md = instance_metadata.InstanceMetadata(
            instance, content=injected_files, extra_md=extra_md,
            network_info=network_info, request_context=context)

        iso_path = os.path.join(
            common.InstanceAttributes(instance).instance_dir,
            'configdrive.iso')

        with configdrive.ConfigDriveBuilder(instance_md=inst_md) as cdb:
            try:
                cdb.make_drive(iso_path)
            except processutils.ProcessExecutionError as e:
                with excutils.save_and_reraise_exception():
                    LOG.error("Creating config drive failed with error: {}"
                              .format(e), instance=instance)

        configdrive_dir = os.path.join(
            nova.conf.CONF.instances_path, instance.name, 'configdrive')
        if not os.path.exists(configdrive_dir):
            fileutils.ensure_tree(configdrive_dir)

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
                utils.execute('chown', '-R',
                              '%s:%s' % (storage_id, storage_id),
                              configdrive_dir, run_as_root=True)
            finally:
                if mounted:
                    utils.execute('umount', tmpdir, run_as_root=True)

        return configdrive_dir