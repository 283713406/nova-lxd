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

import hashlib
import io
import os
import tarfile
import tempfile
from contextlib import closing
from pylxd import exceptions as lxd_exceptions

from oslo_concurrency import lockutils
from oslo_serialization import jsonutils
from oslo_config import cfg
from oslo_log import log as logging

from nova.compute import arch
from nova import exception
from nova import i18n
from nova import image


_ = i18n._
_LE = i18n._LE

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
IMAGE_API = image.API()

ACCEPTABLE_IMAGE_FORMATS = {'raw', 'root-tar', 'squashfs'}


class LXDContainerImage(object):
    """Upload an image from glance to the local LXD image store."""

    def __init__(self):
        self.lock_path = str(os.path.join(CONF.instances_path, 'locks'))

    def sync_glance_image_to_lxd(self, client, context, image_meta, image_ref):
        """Sync an image from glance to LXD image store.

        The image from glance can't go directly into the LXD image store,
        as LXD needs some extra metadata connected to it.

        The image is stored in the LXD image store with an alias to
        the image_ref. This way, it will only copy over once.
        """
        LOG.info('Start to sync_glance_image_to_lxd')
        with lockutils.lock(
                self.lock_path, external=True,
                lock_file_prefix='lxd-image-{}'.format(image_ref)):

            # NOTE(jamespage): Re-query by image_ref to ensure
            #                  that another process did not
            #                  sneak infront of this one and create
            #                  the same image already.
            try:
                client.images.get_by_alias(image_ref)
                return
            except lxd_exceptions.LXDAPIException as e:
                if e.response.status_code != 404:
                    raise

            try:
                # Inspect image to verify the correct disk format.
                ifd, image_file = tempfile.mkstemp()
                mfd, manifest_file = tempfile.mkstemp()

                image = IMAGE_API.get(context, image_ref)
                if image.get('disk_format') not in ACCEPTABLE_IMAGE_FORMATS:
                    raise exception.ImageUnacceptable(
                        image_id=image_ref, reason=_("Bad image format"))

                # Fetch an image from glance
                LOG.debug('_fetch_image called for instance')
                IMAGE_API.download(context, image_ref, dest_path=image_file)

                # It is possible that LXD already have the same image
                # but NOT aliased as result of previous publish/export operation
                # (snapshot from openstack).
                # In that case attempt to add it again
                # (implicitly via instance launch from affected image) will produce
                # LXD error - "Image with same fingerprint already exists".
                # Error does not have unique identifier to handle it we calculate
                # fingerprint of image as LXD do it and check if LXD already have
                # image with such fingerprint.
                # If any we will add alias to this image and will not re-import it
                def add_alias():

                    def lxdimage_fingerprint():
                        def sha256_file():
                            sha256 = hashlib.sha256()
                            with closing(open(image_file, 'rb')) as f:
                                for block in iter(lambda: f.read(65536), b''):
                                    sha256.update(block)
                            return sha256.hexdigest()

                        return sha256_file()

                    fingerprint = lxdimage_fingerprint()
                    if client.images.exists(fingerprint):
                        LOG.info("Image with fingerprint {fingerprint} already "
                                 "exists but not accessible by alias {alias}, "
                                 "add alias"
                                 .format(fingerprint=fingerprint, alias=image_ref))
                        lxdimage = client.images.get(fingerprint)
                        lxdimage.add_alias(image_ref, '')
                        return True

                    return False

                if add_alias():
                    return

                # up2date LXD publish/export operations produce images which
                # already contains /rootfs and metdata.yaml in exported file.
                # We should not pass metdata explicitly in that case as imported
                # image will be unusable bacause LXD will think that it containts
                # rootfs and will not extract embedded /rootfs properly.
                # Try to detect if image content already has metadata and not pass
                # explicit metadata in that case
                def imagefile_has_metadata(image_file):
                    try:
                        with closing(tarfile.TarFile.open(
                                name=image_file, mode='r:*')) as tf:
                            try:
                                tf.getmember('metadata.yaml')
                                return True
                            except KeyError:
                                pass
                    except tarfile.ReadError:
                        pass
                    return False

                if imagefile_has_metadata(image_file):
                    LOG.info("Image {alias} already has metadata, "
                             "skipping metadata injection..."
                             .format(alias=image_ref))
                    with open(image_file, 'rb') as image:
                        image = client.images.create(image, wait=True)
                else:
                    image_arch = image_meta.properties.get('hw_architecture')
                    if image_arch is None:
                        image_arch = arch.from_host()
                    metadata = {
                        'architecture': image_arch,
                        'creation_date': int(os.stat(image_file).st_ctime)}
                    metadata_yaml = jsonutils.dumps(
                        metadata, sort_keys=True, indent=4,
                        separators=(',', ': '),
                        ensure_ascii=False).encode('utf-8') + b"\n"

                    tarball = tarfile.open(manifest_file, "w:gz")
                    tarinfo = tarfile.TarInfo(name='metadata.yaml')
                    tarinfo.size = len(metadata_yaml)
                    tarball.addfile(tarinfo, io.BytesIO(metadata_yaml))
                    tarball.close()

                    with open(manifest_file, 'rb') as manifest:
                        with open(image_file, 'rb') as image:
                            image = client.images.create(
                                image, metadata=manifest,
                                wait=True)

                image.add_alias(image_ref, '')

            finally:
                os.close(ifd)
                os.close(mfd)
                os.unlink(image_file)
                os.unlink(manifest_file)

