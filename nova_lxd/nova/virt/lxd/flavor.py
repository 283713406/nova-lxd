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

from nova import exception
from nova import i18n
from nova.virt import driver
from oslo_config import cfg
from oslo_utils import units
from oslo_log import log as logging

from ..lxd import common
from ..lxd import vif

_ = i18n._
CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _base_config(instance, _):
    instance_attributes = common.InstanceAttributes(instance)
    return {
        'environment.product_name': 'OpenStack Nova',
        'raw.lxc': 'lxc.console.logfile={}\n'.format(
            instance_attributes.console_path),
    }


def _nesting(instance, _):
    if instance.flavor.extra_specs.get('lxd:nested_allowed'):
        return {'security.nesting': 'True'}


def _security(instance, _):
    if instance.flavor.extra_specs.get('lxd:privileged_allowed'):
        return {'security.privileged': 'True'}


def _memory(instance, _):
    mem = instance.memory_mb
    if mem >= 0:
        return {'limits.memory': '{}MB'.format(mem)}


def _cpu(instance, _):
    vcpus = instance.flavor.vcpus
    if vcpus >= 0:
        return {'limits.cpu': str(vcpus)}


def _isolated(instance, client):
    lxd_isolated = instance.flavor.extra_specs.get('lxd:isolated')
    if lxd_isolated:
        extensions = client.host_info.get('api_extensions', [])
        if 'id_map' in extensions:
            return {'security.idmap.isolated': 'True'}
        else:
            msg = _("Host does not support isolated instances")
            raise exception.NovaException(msg)


_CONFIG_FILTER_MAP = [
    _base_config,
    _nesting,
    _security,
    _memory,
    _cpu,
    _isolated,
]


def _root(instance, client, *_):
    """Configure the root disk."""
    LOG.debug('configure_container_root called for instance',
              instance=instance)
    device = {'type': 'disk', 'path': '/'}

    storage_type = client.host_info['environment']['storage']
    if storage_type in ['btrfs', 'zfs']:
        device['size'] = '{}GB'.format(instance.root_gb)

    return {'root': device}


def _network(instance, _, network_info, __):
    if not network_info:
        return

    import pdb; pdb.set_trace()
    devices = {}
    for vifaddr in network_info:
        cfg = vif.LXDGenericDriver().get_config(instance, vifaddr)
        devname = vif.LXDGenericDriver().get_vif_devname(vifaddr)
        # key = devname
        key = str(cfg['bridge'])
        devices[key] = {
            # 'nictype': 'physical',
            # 'hwaddr': str(cfg['mac_address']),
            # 'parent': key,    # vif.LXDGenericDriver().get_vif_devname(vifaddr).replace('tap', 'tin'),
            # 'type': 'nic'
            'nictype': 'bridged',
            'hwaddr': 'fe:2b:8c:32:33:8b',
            'parent': 'lxdbr0',  # vif.LXDGenericDriver().get_vif_devname(vifaddr).replace('tap', 'tin'),
            'type': 'nic'
        }
        host_device = vif.LXDGenericDriver().get_vif_devname(vifaddr)
        if host_device:
            devices[key]['host_name'] = host_device

    return devices


_DEVICE_FILTER_MAP = [
    _root,
    _network,
]


def to_profile(client, instance, network_info, block_info, update=False):
    """Convert a nova flavor to a lxd profile.

    Every instance container created via nova-lxd has a profile by the
    same name. The profile is sync'd with the configuration of the container.
    When the instance container is deleted, so is the profile.
    """

    name = instance.name
    LOG.info("instance name is '%s'", name)
    config = {}
    for f in _CONFIG_FILTER_MAP:
        new = f(instance, client)
        if new:
            config.update(new)

    devices = {}
    import pdb; pdb.set_trace()
    for f in _DEVICE_FILTER_MAP:
        new = f(instance, client, network_info, block_info)
        if new:
            devices.update(new)

    if update is True:
        profile = client.profiles.get(name)
        profile.devices = devices
        profile.config = config
        profile.save()
        return profile
    else:
        return client.profiles.create(name, config, devices)
