"""Self-contained publisher tests. No device, production signing key, or network.

The RSA key and synthetic ESP image exist only inside a temporary fixture. Fake
GitHub records every request so compare-only delivery cannot accidentally write.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SPEC = importlib.util.spec_from_file_location(
    "firmware_publish", Path(__file__).resolve().parents[1] / "scripts" / "publish.py"
)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixed(value, size):
    encoded = value.encode("ascii")
    if len(encoded) >= size:
        raise ValueError("fixture field too long")
    return encoded + bytes(size - len(encoded))


class FakeGitHub:
    """A stateful API double; unexpected calls fail instead of using the network."""
    def __init__(self, release=None, contents=None, get_status=None, fail_upload=None, latest=None, latest_status=None):
        self.existing = copy.deepcopy(release)
        self.contents = dict(contents or {})
        self.get_status = get_status
        self.fail_upload = fail_upload
        self.latest = copy.deepcopy(latest)
        self.latest_status = latest_status
        self.calls = []
        self.uploaded = {}
        self.draft = None

    def api(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == "GET" and path == "/releases/tags/v0.1.2":
            status = self.get_status if self.get_status is not None else (200 if self.existing else 404)
            return status, copy.deepcopy(self.existing or {})
        if method == "GET" and path == "/releases/latest":
            status = self.latest_status if self.latest_status is not None else (200 if self.latest else 404)
            return status, copy.deepcopy(self.latest or {})
        if method == "POST" and path == "/releases":
            if self.existing or self.draft:
                raise AssertionError("publisher tried to create an existing release")
            if not body.get("draft") or body.get("prerelease"):
                raise AssertionError("new release must be a stable draft until every upload succeeds")
            self.draft = dict(body, id=42, upload_url="https://uploads.github.com/repos/" + publisher.REPO + "/releases/42/assets{?name,label}")
            return 201, copy.deepcopy(self.draft)
        if method == "PATCH" and path == "/releases/42":
            if not self.draft:
                raise AssertionError("publishing without a draft")
            self.draft.update(body)
            self.draft["html_url"] = "https://github.com/" + publisher.REPO + "/releases/tag/v0.1.2"
            return 200, copy.deepcopy(self.draft)
        raise AssertionError("Unexpected API operation: " + method + " " + path)

    def download(self, asset):
        self.calls.append(("DOWNLOAD", asset["name"], None))
        return self.contents[asset["name"]]

    def upload(self, release, name, content):
        self.calls.append(("UPLOAD", name, bytes(content)))
        if not self.draft or not self.draft["draft"] or release["id"] != 42:
            raise AssertionError("asset upload must happen while the release is still a draft")
        if name == self.fail_upload:
            raise ValueError("Uploaded asset digest differs")
        self.uploaded[name] = bytes(content)

    @property
    def writes(self):
        return [call for call in self.calls if call[0] in {"POST", "PATCH", "DELETE", "UPLOAD"}]


class PublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This is a throwaway test key, generated anew; production trust is never read.
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.version = "0.1.2"
        image = bytearray(4096)
        image[0] = 0xE9
        image[1] = 1
        struct.pack_into("<H", image, 12, 9)
        struct.pack_into("<I", image, 28, 256)
        struct.pack_into("<I", image, 32, 0xABCD5432)
        image[48:80] = fixed(cls.version, 32)
        image[80:112] = fixed("esp32-splitflap-idf", 32)
        cls.image = bytes(image)
        cls.header = bytearray(256)
        cls.header[:8] = b"SFLPOTA1"
        struct.pack_into("<III", cls.header, 8, 1, len(image), 1002)
        cls.header[20:36] = fixed("esp32s3", 16)
        cls.header[36:68] = fixed("esp32-splitflap-idf", 32)
        cls.header[68:100] = fixed(cls.version, 32)
        cls.header[100:132] = hashlib.sha256(image).digest()
        cls.header = bytes(cls.header)
        cls.signature = cls.key.sign(cls.header, padding.PKCS1v15(), hashes.SHA256())
        cls.package = cls.header + cls.signature + cls.image
        cls.manifest = {
            "schema": 1, "product": "esp32-splitflap-idf", "target": "esp32s3",
            "version": cls.version, "sequence": 1002, "asset": "firmware.sfu",
            "image_size": len(cls.image), "image_sha256": sha(cls.image),
            "package_size": len(cls.package), "package_sha256": sha(cls.package),
            "signed_header_base64": base64.b64encode(cls.header).decode(),
            "signature_base64": base64.b64encode(cls.signature).decode(),
            "signature_algorithm": "RSA-2048-PKCS1v1.5-SHA256",
        }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / "releases" / "v0.1.2"
        self.folder.mkdir(parents=True)
        (self.root / "trust").mkdir()
        self.write_public_key(self.key)
        self.notes = "Перевірений реліз 0.1.2.\n"
        self.data = {
            "firmware.sfu": self.package,
            "manifest.json": json.dumps(self.manifest, sort_keys=True).encode(),
            "FIRST_FLASH.md": b"Synthetic test instructions only.\n",
        }
        for name, content in self.data.items():
            (self.folder / name).write_bytes(content)
        (self.folder / "notes.txt").write_bytes(self.notes.encode("utf-8"))
        self.request = {
            "schema": 1, "version": self.version, "source_commit": "a" * 40,
            "mode": "verify-existing", "notes_sha256": sha(self.notes.encode()),
            "assets": [{"name": name, "size": len(content), "sha256": sha(content)} for name, content in self.data.items()],
        }
        self.write_request()
        self.existing = {
            "id": 42, "draft": False, "prerelease": False, "body": self.notes,
            "assets": [{"name": name, "browser_download_url": "https://github.com/" + publisher.REPO + "/releases/download/v0.1.2/" + name} for name in self.data],
            "html_url": "https://github.com/" + publisher.REPO + "/releases/tag/v0.1.2",
        }
        # Even an accidental use of the real client during a unit test cannot contact GitHub.
        patch = mock.patch.object(publisher.urllib.request, "urlopen", side_effect=AssertionError("Network forbidden in publisher unit tests"))
        patch.start()
        self.addCleanup(patch.stop)

    def write_public_key(self, key):
        (self.root / "trust" / "release-public.der").write_bytes(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))

    def write_request(self):
        (self.root / "delivery.json").write_text(json.dumps(self.request), encoding="utf-8")

    def replace_asset(self, name, content, update_transport_hash=True):
        (self.folder / name).write_bytes(content)
        if update_transport_hash:
            entry = next(a for a in self.request["assets"] if a["name"] == name)
            entry.update(size=len(content), sha256=sha(content))
            self.write_request()

    def test_valid_delivery_is_self_contained(self):
        request, data, notes = publisher.validate(self.root)
        self.assertEqual(request, self.request)
        self.assertEqual(data, self.data)
        self.assertEqual(notes, self.notes)

    def test_verify_existing_exact_bytes_never_writes(self):
        client = FakeGitHub(self.existing, self.data)
        self.assertEqual(publisher.publish(self.request, self.data, self.notes, client), self.existing["html_url"])
        self.assertEqual(client.writes, [])
        self.assertEqual(sum(c[0] == "DOWNLOAD" for c in client.calls), len(self.data))

    def test_publish_mode_existing_match_is_also_read_only(self):
        self.request["mode"] = "publish"
        client = FakeGitHub(self.existing, self.data)
        publisher.publish(self.request, self.data, self.notes, client)
        self.assertEqual(client.writes, [])

    def test_existing_changed_bytes_refused_without_mutation(self):
        for name in self.data:
            with self.subTest(asset=name):
                changed = dict(self.data, **{name: self.data[name] + b"changed"})
                client = FakeGitHub(self.existing, changed)
                with self.assertRaisesRegex(ValueError, "Existing release bytes differ"):
                    publisher.publish(self.request, self.data, self.notes, client)
                self.assertEqual(client.writes, [])

    def test_existing_changed_notes_refused_without_mutation(self):
        release = dict(self.existing, body="Different notes")
        client = FakeGitHub(release, self.data)
        with self.assertRaisesRegex(ValueError, "Existing release notes differ"):
            publisher.publish(self.request, self.data, self.notes, client)
        self.assertEqual(client.writes, [])

    def test_existing_missing_or_extra_asset_refused(self):
        for assets in (self.existing["assets"][:-1], self.existing["assets"] + [{"name": "unexpected.bin"}]):
            with self.subTest(assets=assets):
                client = FakeGitHub(dict(self.existing, assets=assets), self.data)
                with self.assertRaisesRegex(ValueError, "asset names differ"):
                    publisher.publish(self.request, self.data, self.notes, client)
                self.assertEqual(client.writes, [])

    def test_existing_draft_or_prerelease_is_not_promoted(self):
        for flag in ("draft", "prerelease"):
            with self.subTest(flag=flag):
                client = FakeGitHub(dict(self.existing, **{flag: True}), self.data)
                with self.assertRaisesRegex(ValueError, "published stable release"):
                    publisher.publish(self.request, self.data, self.notes, client)
                self.assertEqual(client.writes, [])

    def test_verify_missing_cannot_create(self):
        client = FakeGitHub()
        with self.assertRaisesRegex(ValueError, "Verification mode cannot create"):
            publisher.publish(self.request, self.data, self.notes, client)
        self.assertEqual(client.writes, [])

    def test_api_read_failure_cannot_create(self):
        self.request["mode"] = "publish"
        for status in (401, 403, 429, 500):
            with self.subTest(status=status):
                client = FakeGitHub(get_status=status)
                with self.assertRaisesRegex(ValueError, "Could not read existing"):
                    publisher.publish(self.request, self.data, self.notes, client)
                self.assertEqual(client.writes, [])

    def test_new_release_stays_draft_until_all_uploads_succeed(self):
        self.request["mode"] = "publish"
        client = FakeGitHub()
        with mock.patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
            url = publisher.publish(self.request, self.data, self.notes, client)
        self.assertEqual(url, self.existing["html_url"])
        self.assertEqual(client.uploaded, self.data)
        self.assertEqual([c[0] for c in client.calls], ["GET", "GET", "POST"] + ["UPLOAD"] * len(self.data) + ["PATCH"])
        create = client.calls[2][2]
        self.assertEqual(create["tag_name"], "v0.1.2")
        self.assertEqual(create["target_commitish"], "b" * 40)
        self.assertEqual(create["body"], self.notes)
        self.assertTrue(create["draft"])
        self.assertEqual(client.calls[-1][2], {"draft": False, "make_latest": "true"})

    def test_upload_failure_never_publishes_partial_release(self):
        self.request["mode"] = "publish"
        client = FakeGitHub(fail_upload="manifest.json")
        with mock.patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
            with self.assertRaisesRegex(ValueError, "digest differs"):
                publisher.publish(self.request, self.data, self.notes, client)
        self.assertTrue(client.draft["draft"])
        self.assertFalse(any(c[0] == "PATCH" for c in client.calls))

    def test_new_release_can_follow_older_stable_latest(self):
        self.request["mode"] = "publish"
        client = FakeGitHub(latest={"tag_name": "v0.1.1", "draft": False, "prerelease": False})
        with mock.patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}):
            publisher.publish(self.request, self.data, self.notes, client)
        self.assertEqual(client.uploaded, self.data)
        self.assertEqual(client.calls[-1][0], "PATCH")

    def test_new_release_cannot_move_latest_backwards_or_sideways(self):
        self.request["mode"] = "publish"
        for tag in ("v0.1.2", "v0.1.3", "v0.2.0", "v1.0.0", "v999.999.999"):
            with self.subTest(latest=tag):
                client = FakeGitHub(latest={"tag_name": tag, "draft": False, "prerelease": False})
                with self.assertRaisesRegex(ValueError, "newer than the latest"):
                    publisher.publish(self.request, self.data, self.notes, client)
                self.assertEqual(client.writes, [])

    def test_untrusted_or_unreadable_latest_never_creates_release(self):
        self.request["mode"] = "publish"
        invalid = [
            {"tag_name": "v0.1.1", "draft": True, "prerelease": False},
            {"tag_name": "v0.1.1", "draft": False, "prerelease": True},
            {"tag_name": "v00.1.1", "draft": False, "prerelease": False},
            {"tag_name": "0.1.1", "draft": False, "prerelease": False},
            {"tag_name": "v0.1.1-rc1", "draft": False, "prerelease": False},
        ]
        for latest in invalid:
            with self.subTest(latest=latest):
                client = FakeGitHub(latest=latest)
                with self.assertRaises(ValueError):
                    publisher.publish(self.request, self.data, self.notes, client)
                self.assertEqual(client.writes, [])
        for status in (401, 403, 429, 500):
            with self.subTest(status=status):
                client = FakeGitHub(latest_status=status)
                with self.assertRaisesRegex(ValueError, "Could not read latest"):
                    publisher.publish(self.request, self.data, self.notes, client)
                self.assertEqual(client.writes, [])

    def test_mutated_manifest_rejected_even_after_transport_rehash(self):
        for field, value in (("version", "0.1.3"), ("target", "esp32"), ("image_sha256", "0" * 64), ("signature_base64", "AA=="), ("unexpected", True)):
            with self.subTest(field=field):
                changed = dict(self.manifest, **{field: value})
                self.replace_asset("manifest.json", json.dumps(changed).encode())
                with self.assertRaisesRegex(ValueError, "Manifest differs"):
                    publisher.validate(self.root)

    def test_mutated_signature_rejected_even_after_transport_rehash(self):
        for offset in (256, 400, 511):
            with self.subTest(offset=offset):
                changed = bytearray(self.package)
                changed[offset] ^= 1
                self.replace_asset("firmware.sfu", bytes(changed))
                with self.assertRaises(InvalidSignature):
                    publisher.validate(self.root)

    def test_mutated_image_rejected_even_after_transport_rehash(self):
        changed = bytearray(self.package)
        changed[-1] ^= 1
        self.replace_asset("firmware.sfu", bytes(changed))
        with self.assertRaisesRegex(ValueError, "Signed content mismatch"):
            publisher.validate(self.root)

    def test_wrong_trust_key_rejected(self):
        self.write_public_key(self.other_key)
        with self.assertRaises(InvalidSignature):
            publisher.validate(self.root)

    def test_authenticated_wrong_identity_size_or_reserved_rejected(self):
        for offset in (8, 12, 16, 20, 36, 68, 132, 255):
            with self.subTest(offset=offset):
                header = bytearray(self.header)
                header[offset] ^= 1
                signature = self.key.sign(bytes(header), padding.PKCS1v15(), hashes.SHA256())
                self.replace_asset("firmware.sfu", bytes(header) + signature + self.image)
                with self.assertRaises(ValueError):
                    publisher.validate(self.root)

    def test_transport_checksum_and_notes_mismatch_rejected(self):
        self.replace_asset("FIRST_FLASH.md", b"mutated", update_transport_hash=False)
        with self.assertRaisesRegex(ValueError, "Delivery checksum mismatch"):
            publisher.validate(self.root)
        self.replace_asset("FIRST_FLASH.md", self.data["FIRST_FLASH.md"])
        (self.folder / "notes.txt").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Notes checksum mismatch"):
            publisher.validate(self.root)

    def test_path_escape_asset_names_rejected_before_file_read(self):
        original = copy.deepcopy(self.request["assets"])
        for name in ("../firmware.sfu", "../../secret.txt", "/etc/passwd", "C:\\secret.txt", "..\\firmware.sfu", "sub/firmware.sfu"):
            with self.subTest(name=name):
                self.request["assets"] = copy.deepcopy(original)
                self.request["assets"][0]["name"] = name
                self.write_request()
                with self.assertRaisesRegex(ValueError, "Invalid/duplicate asset names"):
                    publisher.validate(self.root)

    def test_unlisted_extra_file_rejected(self):
        (self.folder / "unexpected.txt").write_bytes(b"not in delivery")
        with self.assertRaisesRegex(ValueError, "Unexpected delivery files"):
            publisher.validate(self.root)

    def test_duplicate_asset_rejected(self):
        self.request["assets"].append(copy.deepcopy(self.request["assets"][0]))
        self.write_request()
        with self.assertRaisesRegex(ValueError, "Invalid/duplicate asset names"):
            publisher.validate(self.root)

    def test_asset_symlink_rejected(self):
        asset = self.folder / "FIRST_FLASH.md"
        target = self.root / "outside.txt"
        target.write_bytes(self.data["FIRST_FLASH.md"])
        asset.unlink()
        try:
            asset.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Host does not permit creating symlinks")
        with self.assertRaisesRegex(ValueError, "regular file"):
            publisher.validate(self.root)

    def test_noncanonical_version_and_source_ref_rejected(self):
        for version in ("v0.1.2", "00.1.2", "0.1.2-rc1", "0.1.2/../../escape", "1000.0.0"):
            with self.subTest(version=version):
                self.request["version"] = version
                self.write_request()
                with self.assertRaisesRegex(ValueError, "Invalid version/schema"):
                    publisher.validate(self.root)
        self.request["version"] = "0.1.2"
        self.request["source_commit"] = "main"
        self.write_request()
        with self.assertRaisesRegex(ValueError, "Invalid source revision"):
            publisher.validate(self.root)


if __name__ == "__main__":
    unittest.main()
