import requests
import tempfile
import argparse
import logging
import tarfile
import shutil
import sys
import os
from urllib.parse import urlparse

MOTD = """
                               _____                      _ _         
     /\                       / ____|                    (_) |        
    /  \   __ _ _   _  __ _  | (___   ___  ___ _   _ _ __ _| |_ _   _ 
   / /\ \ / _` | | | |/ _` |  \___ \ / _ \/ __| | | | '__| | __| | | |
  / ____ \ (_| | |_| | (_| |  ____) |  __/ (__| |_| | |  | | |_| |_| |
 /_/    \_\__, |\__,_|\__,_| |_____/ \___|\___|\__,_|_|  |_|\__|\__, |
             | |                                                 __/ |
             |_|                                                |___/ 

Docker images verifier cli-tool (CVE-2018-8115)
To help the community stay safe, we at Aqua created an open source tool
that tests images for whether they are safe of this vulnerability.

Aqua Security
https://www.aquasec.com
"""

REGISTRY_URL = 'https://registry.hub.docker.com'
# REGISTRY_URL = 'http://127.0.0.1:5000'
REGISTRY_AUTH_URL = 'https://auth.docker.io'
REGISTRY_SERVICE = 'registry.docker.io'

logging.basicConfig(format='%(message)s')
logger = logging.getLogger('CVE-2018-8115')
logger.setLevel(logging.INFO)


class DockerRegistry(object):
    def __init__(self, image, tag, arch=None, operate_system=None):
        self.image = image
        self.tag = tag
        self.arch = arch
        self.os = operate_system
        self.layers = []
        self.headers = {'Accept': 'application/vnd.docker.distribution.manifest.v2+json, '
                                  'application/vnd.docker.distribution.manifest.list.v2+json'}

    def authenticate(self):
        fetch_url = '{auth_url}/token?service={service}&scope=repository:{image_name}:pull'.format(
            auth_url=REGISTRY_AUTH_URL, service=REGISTRY_SERVICE, image_name=self.image)
        token = requests.get(fetch_url).json().get('token', None)
        if token:
            self.token = token
            self.headers['Authorization'] = 'Bearer {0}'.format(token)
        else:
            raise Exception("Cant Authenticate")

    def craft_layer_url(self, layer):
        if layer.get('urls'):
            return layer.get('urls')[0]
        else:
            return '{registry_url}/v2/{image}/blobs/{layer_hash}'.format(
                registry_url=REGISTRY_URL, image=self.image, layer_hash=layer.get('digest'))

    def get_layers(self):
        logger.info('[~] Fetching %s metadata...', self.image)
        manifest = requests.get(
            '{registry_url}/v2/{image}/manifests/{tag}'.format(registry_url=REGISTRY_URL, image=self.image,
                                                               tag=self.tag), headers=self.headers).json()
        if manifest.get('layers'):
            for single_layer in manifest.get('layers'):
                self.layers.append((single_layer.get('digest'), self.craft_layer_url(single_layer)))

        elif manifest.get('manifests'):
            if not self.arch:
                architectures = {}
                for index, tag in enumerate(manifest.get('manifests')):
                    architectures[index] = tag.get('platform').get('architecture')

                architectures = list(set(architectures.values()))
                architectures = {v: k for v, k in enumerate(architectures)}
                for index in architectures:
                    print(index, "\t", architectures[index])

                arch = num_input("Please select an architecture: ")
                self.arch = architectures.get(int(arch))

            if not self.os:
                operate_systems = {}
                for index, tag in enumerate(manifest.get('manifests')):
                    operate_systems[index] = tag.get('platform').get('os')

                operate_systems = list(set(operate_systems.values()))
                operate_systems = {v: k for v, k in enumerate(operate_systems)}
                for index in operate_systems:
                    print(index, "\t", operate_systems[index])

                operate_system = num_input("Please select an operate system: ")
                self.os = operate_systems.get(int(operate_system))

            if not self.os or not self.arch:
                logger.error("[-] Error: undefined architecture or operate system")
                sys.exit(1)

            for tag in manifest.get('manifests'):
                if tag.get('platform').get('architecture') == self.arch \
                        and tag.get('platform').get('os') == self.os:
                    self.tag = tag.get('digest')
                    return self.get_layers()

        elif manifest.get('errors'):
            logger.error('[-] Image is private or not exists')
            sys.exit(1)

        else:
            print(manifest)
            raise Exception('Unexpected manifest')


def num_input(msg):
    number = input(msg)
    if number.isdigit():
        return number
    else:
        print("You must enter a number (i.e. 0,1,2...)")
        return num_input(msg)


def download_layer(url, auth_token=None):
    headers = {}

    if auth_token:
        headers['Authorization'] = 'Bearer {0}'.format(auth_token)

    r = requests.get(url, stream=True, headers=headers)

    if r.status_code == 200:

        total_length = r.headers.get('content-length')
        layer_fd, filename = tempfile.mkstemp()

        with open(layer_fd, 'wb') as f:
            if total_length is None:
                r.raw.decode_content = True
                shutil.copyfileobj(r.raw, f)
                sys.stdout.write('\r[{0}] 100%'.format('=' * 50))
                sys.stdout.flush()
            else:
                dl = 0
                total_length = int(total_length)
                for data in r.iter_content(chunk_size=4096):
                    dl += len(data)
                    f.write(data)
                    done = int(50 * dl / total_length)
                    sys.stdout.write(
                        '\r[{0}{1}] {2}%'.format('=' * done, ' ' * (50 - done), int(dl / total_length * 100)))
                    sys.stdout.flush()
                sys.stdout.write('\n')

        return filename
    return None


def is_layer_safe(layer_file):
    results = []
    try:
        tar = tarfile.open(layer_file, mode='r:gz')
    except tarfile.ReadError:
        tar = tarfile.open(layer_file, mode='r')

    while True:
        next_block = tar.next()
        if not next_block:
            break

        filename = next_block.name
        link_destination = next_block.linkname

        if not os.path.relpath(filename).find('..\\') or not os.path.relpath(filename).find('../'):
            results.append((filename, 0, layer_file))

        if link_destination:
            if link_destination[0] not in ['/', '\\']:
                full_path = os.path.dirname(filename) + "/" + link_destination
                if not os.path.relpath(full_path).find('..\\') or not os.path.relpath(full_path).find('../'):
                    results.append((full_path, 1, layer_file))

    return results


def generate_report(image_name, results, layer):
    if not results:
        logger.info("\n=== {image} is safe of CVE-2018-8115 ===".format(image=image_name))
        return
    else:
        logger.warning("Found {files_count} malicious files".format(files_count=len(results)))
        for malicious_file in results:
            logger.warning(
                " Layer: {layer}, File: {file}".format(layer=layer, file=malicious_file[0]))

        logger.critical("\n=== IMAGE IS NOT SAFE! ===")


if __name__ == "__main__":

    logger.info(MOTD)
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('image', type=str, help='Registry image name. Ex. library/ubuntu')
    parser.add_argument('--tag', type=str, help='Image tag. Ex. latest', default='latest')
    parser.add_argument('--arch', type=str, help='Image architecture. Ex. amd64', default='amd64')
    parser.add_argument('--os', type=str, help='Operate system. Ex. Linux', default='linux')

    args = parser.parse_args()
    results = []
    instance = DockerRegistry(args.image, args.tag)
    instance.authenticate()
    instance.get_layers()
    for single_layer in instance.layers:
        layer_name = single_layer[0][single_layer[0].find(':') + 1:][:12]
        logger.info("[+] Checking layer {0}".format(layer_name))
        o = urlparse(single_layer[1])
        if o.netloc == 'go.microsoft.com':
            sys.stdout.write('\r[{0}] 100%'.format('=' * 50))
            sys.stdout.write('\n')
            sys.stdout.flush()
            continue
        layer_file = download_layer(single_layer[1], instance.token)
        results += is_layer_safe(layer_file)
    generate_report(args.image, results, layer_name)
