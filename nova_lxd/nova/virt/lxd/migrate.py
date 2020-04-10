# Copyright 2016 Canonical Ltd
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
import shutil

from nova import exception
from nova import i18n
from nova import utils

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import fileutils

from nova_lxd.nova.virt.lxd import config
from nova_lxd.nova.virt.lxd import operations
from nova_lxd.nova.virt.lxd import utils as container_dir
from nova_lxd.nova.virt.lxd import session

_ = i18n._
_LE = i18n._LE
_LI = i18n._LI

CONF = cfg.CONF
CONF.import_opt('my_ip', 'nova.netconf')
LOG = logging.getLogger(__name__)


class LXDContainerMigrate(object):

    def __init__(self, virtapi):
        self.virtapi = virtapi
        self.isLocalMigrate = False
        self.config = config.LXDContainerConfig()
        self.container_dir = container_dir.LXDContainerDirectories()
        self.session = session.LXDAPISession()
        self.operations = \
            operations.LXDContainerOperations(
                self.virtapi)

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   flavor, network_info,
                                   block_device_info=None, timeout=0,
                                   retry_interval=0):
        LOG.debug("migrate_disk_and_power_off called", instance=instance)

        same_host = False
        if CONF.my_ip == dest:
            self.isLocalMigrate = True
            same_host = True
            LOG.debug('Migration target is the source host')
        else:
            LOG.debug('Migration target host: %s' % dest)

        if not self.session.container_defined(instance.name, instance):
            msg = _('Instance is not found.')
            raise exception.NovaException(msg)

        try:
            if same_host:
                container_profile = self.config.create_profile(instance,
                                                               network_info, flavor)
                self.session.profile_update(container_profile, instance)
            else:
                images = 'container_%s' % instance.name
                if self._is_rbd_image(images):
                    self.session.container_stop(instance.name, instance)
                else:
                    LOG.error('error opening image, migration not supported')
                    return
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('failed to resize container '
                              '%(instance)s: %(ex)s'),
                          {'instance': instance.name, 'ex': ex},
                          instance=instance)

        # disk_info is not used
        return ""

    def confirm_migration(self, migration, instance, network_info):
        LOG.debug("confirm_migration called", instance=instance)

        if self.isLocalMigrate:
            return

        if not self.session.container_defined(instance.name, instance):
            msg = _('Failed to find container %(instance)s') % \
                {'instance': instance.name}
            raise exception.NovaException(msg)

        try:
            images = 'container_%s' % instance.name
            if self._is_rbd_image(images):
                # Ensure that the instance directory exists
                instance_dir = '/var/lib/lxd/storage-pools/pool/containers/%s/' % instance.name
                # instance_dir = \
                #     self.container_dir.get_instance_dir(instance.name)
                if os.path.exists(instance_dir):
                    shutil.rmtree(instance_dir)

                rbd_dir = '/dev/rbd/pool/container_%s' % instance.name
                out, err = utils.trycmd('ls', '-l', rbd_dir, discard_warnings=True,
                                         run_as_root=True)
                arr_out = out.split(' ')
                tmp = arr_out[len(arr_out)-1]
                path = '/dev/%s' % tmp.split('\n')[0].split('/')[2]

                out, err = utils.trycmd('rbd', 'unmap', '-o', 'force', path, discard_warnings=True,
                                         run_as_root=True)
                # self.session.container_destroy(instance.name, instance)
                # self.session.profile_delete(instance)
                self.operations.unplug_vifs(instance, network_info)
            else:
                LOG.error('error opening image, migration not supported')
                return
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Confirm migration failed for %(instance)s: '
                                  '%(ex)s'), {'instance': instance.name,
                                              'ex': ex}, instance=instance)

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance=False,
                         block_device_info=None, power_on=True):
        LOG.debug("finish_migration called", instance=instance)

        if self.session.container_defined(instance.name, instance):
            c_info = self.session.container_info(instance)
            if c_info['status'] == 'Running':
                return

        try:
            # Ensure that the instance directory exists
            instance_dir = '/var/lib/lxd/storage-pools/pool/containers/%s/' % instance.name
            # instance_dir = \
            #     self.container_dir.get_instance_dir(instance.name)
            if not os.path.exists(instance_dir):
                fileutils.ensure_tree(instance_dir)

            images = 'container_%s' % instance.name
            if self._is_rbd_image(images):
                path, err = utils.trycmd('rbd', 'map', '-p', 'pool', '--image', images, discard_warnings=True,
                                        run_as_root=True)
                if err:
                    LOG.error('Detaching from erroneous rbd device returned, error: %s', err)
                    return

                out, err = utils.trycmd('nsenter', '-t', '1', '-m', 'mount', path.split('\n')[0], instance_dir,
                                    discard_warnings=True, run_as_root=True)
            else:
                LOG.error('error opening image %s',  images)
                return

            # Step 1 - Setup the profile on the dest host
            if not self.session.profile_defined(instance.name, instance):
                container_profile = self.config.create_profile(instance, network_info)
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

    def finish_revert_migration(self, context, instance, network_info,
                                block_device_info=None, power_on=True):
        LOG.debug('finish_revert_migration called for instance',
                  instance=instance)
        if self.session.container_defined(instance.name, instance):
            self.session.container_start(instance.name, instance)

    def _get_hostname(self, host, instance):
        LOG.debug('_get_hostname called for instance', instance=instance)
        out, err = utils.execute('env', 'LANG=C', 'dnsdomainname')
        if out != '':
            return '%s.%s' % (host, out.rstrip('\n'))
        else:
            return host

    def _is_rbd_image(self, images):
        out, err = utils.trycmd('rbd', '-p', 'pool', 'info', images, discard_warnings=True,
                                run_as_root=True)
        if out:
            return True
        else:
            return False
