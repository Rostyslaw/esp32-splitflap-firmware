#!/usr/bin/env python3
"""Validate a signed delivery and publish with this public repository's job token."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

REPO = 'Rostyslaw/esp32-splitflap-firmware'
VERSION = r'(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def field(data):
    value, sep, tail = data.partition(b'\0')
    require(sep and not any(tail), 'Malformed signed string')
    return value.decode('ascii')


def validate(root):
    request = json.loads((root / 'delivery.json').read_text())
    version = request['version']
    require(request['schema'] == 1 and re.fullmatch(VERSION, version), 'Invalid version/schema')
    require(request['mode'] in ('publish', 'verify-existing'), 'Invalid delivery mode')
    require(re.fullmatch(r'[0-9a-f]{40}', request['source_commit']), 'Invalid source revision')
    allowed = {'firmware.sfu', 'manifest.json', f'first-flash-{version}.zip', 'FIRST_FLASH.md', 'VERIFICATION.md', 'SHA256SUMS.txt'}
    entries = request['assets']
    names = [a['name'] for a in entries]
    require(len(names) == len(set(names)) and set(names) <= allowed, 'Invalid/duplicate asset names')
    require({'firmware.sfu', 'manifest.json'} <= set(names), 'Missing signed package/manifest')
    folder = root / 'releases' / ('v' + version)
    require(set(p.name for p in folder.iterdir()) == set(names) | {'notes.txt'}, 'Unexpected delivery files')
    data = {}
    for entry in entries:
        path = folder / entry['name']
        require(path.is_file() and not path.is_symlink(), 'Asset must be a regular file')
        require(path.stat().st_size <= 16 * 1024 * 1024, 'Asset too large')
        content = path.read_bytes()
        require(len(content) == entry['size'] and digest(content) == entry['sha256'], 'Delivery checksum mismatch: ' + entry['name'])
        data[entry['name']] = content
    notes = (folder / 'notes.txt').read_bytes()
    require(digest(notes) == request['notes_sha256'], 'Notes checksum mismatch')
    package = data['firmware.sfu']
    require(800 <= len(package) <= 0x1f0000 + 512, 'Invalid package size')
    header, signature, image = package[:256], package[256:512], package[512:]
    public = serialization.load_der_public_key((root / 'trust' / 'release-public.der').read_bytes())
    public.verify(signature, header, padding.PKCS1v15(), hashes.SHA256())
    sequence = sum(int(n) * factor for n, factor in zip(version.split('.'), [1000000, 1000, 1]))
    require(header[:8] == b'SFLPOTA1' and struct.unpack_from('<III', header, 8) == (1, len(image), sequence), 'Signed size/version mismatch')
    require(field(header[20:36]) == 'esp32s3' and field(header[36:68]) == 'esp32-splitflap-idf' and field(header[68:100]) == version, 'Signed identity mismatch')
    require(header[100:132] == hashlib.sha256(image).digest() and not any(header[132:]), 'Signed content mismatch')
    require(image[0] == 0xe9 and struct.unpack_from('<H', image, 12)[0] == 9 and struct.unpack_from('<I', image, 32)[0] == 0xabcd5432, 'Wrong ESP32-S3 application')
    require(field(image[48:80]) == version and field(image[80:112]) == 'esp32-splitflap-idf', 'Image descriptor does not match release')
    manifest = json.loads(data['manifest.json'])
    expected = {'schema': 1, 'product': 'esp32-splitflap-idf', 'target': 'esp32s3', 'version': version, 'sequence': sequence, 'asset': 'firmware.sfu', 'image_size':len(image), 'image_sha256':digest(image), 'package_size':len(package), 'package_sha256':digest(package), 'signed_header_base64':base64.b64encode(header).decode(), 'signature_base64':base64.b64encode(signature).decode(), 'signature_algorithm':'RSA-2048-PKCS1v1.5-SHA256'}
    require(manifest == expected, 'Manifest differs from authenticated package')
    return request, data, notes.decode('utf-8')


class GitHub:
    def __init__(self, token):
        self.token = token

    def api(self, method, path, body=None):
        req = urllib.request.Request('https://api.github.com/repos/' + REPO + path, method=method,
            data=None if body is None else json.dumps(body).encode(), headers={'Authorization':'Bearer '+self.token, 'Accept':'application/vnd.github+json', 'Content-Type':'application/json', 'User-Agent':'signed-firmware-publisher'})
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                result = response.read()
                return response.status, json.loads(result) if result else {}
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def download(self, asset):
        url = asset['browser_download_url']
        require(url.startswith('https://github.com/'+REPO+'/releases/download/'), 'Unexpected asset URL')
        # Public release downloads intentionally carry no credential across redirects.
        with urllib.request.urlopen(url, timeout=60) as response:
            return response.read(16 * 1024 * 1024 + 1)

    def upload(self, release, name, content):
        url = release['upload_url'].split('{')[0]
        require(url.startswith('https://uploads.github.com/repos/'+REPO+'/releases/'), 'Unexpected upload URL')
        req = urllib.request.Request(url+'?name='+urllib.parse.quote(name), method='POST', data=content,
            headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/octet-stream','User-Agent':'signed-firmware-publisher'})
        with urllib.request.urlopen(req, timeout=60) as response:
            asset = json.load(response)
        require(asset['state'] == 'uploaded' and asset['size'] == len(content), 'Asset upload incomplete')
        require(asset.get('digest') == 'sha256:'+digest(content), 'Uploaded asset digest differs')


def publish(request, data, notes, github):
    tag = 'v' + request['version']
    status, release = github.api('GET', '/releases/tags/' + tag)
    if status == 200:
        require(not release['draft'] and not release['prerelease'], 'Existing release is not a published stable release; inspect its draft manually')
        require({a['name'] for a in release['assets']} == set(data), 'Existing release asset names differ')
        for asset in release['assets']:
            require(github.download(asset) == data[asset['name']], 'Existing release bytes differ: ' + asset['name'])
        require((release.get('body') or '') == notes, 'Existing release notes differ')
        print('Verified existing release: all asset bytes and notes match. No release writes performed.')
        return release['html_url']
    require(status == 404, 'Could not read existing release')
    require(request['mode'] == 'publish', 'Verification mode cannot create a release')
    latest_status, latest = github.api('GET', '/releases/latest')
    if latest_status == 200:
        latest_tag = latest.get('tag_name', '')
        require(not latest.get('draft', True) and not latest.get('prerelease', True), 'Latest release is not a published stable release')
        require(isinstance(latest_tag, str) and re.fullmatch('v' + VERSION, latest_tag), 'Latest release has a noncanonical version')
        new_sequence = tuple(int(part) for part in request['version'].split('.'))
        latest_sequence = tuple(int(part) for part in latest_tag[1:].split('.'))
        require(new_sequence > latest_sequence, 'Delivery must be newer than the latest stable release')
    else:
        require(latest_status == 404, 'Could not read latest release')
    status, release = github.api('POST', '/releases', {'tag_name':tag, 'target_commitish':os.environ['GITHUB_SHA'], 'name':'Split-flap '+request['version'], 'body':notes, 'draft':True, 'prerelease':False})
    require(status == 201, 'Could not create release draft')
    for name, content in data.items():
        github.upload(release, name, content)
    status, published = github.api('PATCH', '/releases/'+str(release['id']), {'draft':False,'make_latest':'true'})
    require(status == 200 and not published['draft'], 'Could not publish validated release')
    print('Published signed release after every upload digest matched.')
    return published['html_url']


def main():
    require(os.environ.get('GITHUB_REPOSITORY') == REPO, 'Publisher is restricted to the public firmware repository')
    root = Path(__file__).resolve().parents[1]
    request, data, notes = validate(root)
    url = publish(request, data, notes, GitHub(os.environ['GH_TOKEN']))
    summary = f"Mode: {request['mode']}\n\nRelease: {url}\n\nValidated {len(data)} exact assets, RSA signature, manifest and ESP32-S3 application version.\n"
    print(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
            output.write(summary)


if __name__ == '__main__':
    main()
