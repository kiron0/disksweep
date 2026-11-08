import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_check', ROOT / '.github' / 'scripts' / 'release_check.py')
release_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_check)


class ReleaseDecision(unittest.TestCase):
    def decide(self, version, tags, tag_exists=False, release_exists=False):
        return release_check.decide(version, tags, tag_exists, release_exists, 'abc123')

    def test_newer_version_releases_the_pushed_commit(self):
        result = self.decide('0.1.5', ['v0.1.3', 'v0.1.4'])
        self.assertEqual((result['release'], result['tag'], result['ref'], result['tag_exists']), ('true', 'v0.1.5', 'abc123', 'false'))

    def test_first_release_without_any_tag(self):
        self.assertEqual(self.decide('1.0.0', [])['release'], 'true')

    def test_existing_release_is_skipped(self):
        result = self.decide('0.1.4', ['v0.1.4'], tag_exists=True, release_exists=True)
        self.assertEqual(result['release'], 'false')
        self.assertIn('already exists', result['reason'])

    def test_tag_without_release_is_published_from_the_tag(self):
        result = self.decide('0.1.5', ['v0.1.4', 'v0.1.5'], tag_exists=True)
        self.assertEqual((result['release'], result['ref'], result['tag_exists']), ('true', 'v0.1.5', 'true'))

    def test_older_or_equal_version_than_latest_tag_is_skipped(self):
        for version in ('0.1.3', '0.0.9'):
            with self.subTest(version=version):
                result = self.decide(version, ['v0.1.4', 'v0.2.0-rc1', 'latest'])
                self.assertEqual(result['release'], 'false')
                self.assertIn('not newer than existing v0.1.4', result['reason'])

    def test_numeric_ordering_not_text_ordering(self):
        self.assertEqual(self.decide('0.10.0', ['v0.9.9'])['release'], 'true')
        self.assertEqual(self.decide('0.9.10', ['v0.10.0'])['release'], 'false')

    def test_unstable_version_is_skipped(self):
        for version in ('0.1.5-beta', '01.2.3', '1.2'):
            with self.subTest(version=version):
                self.assertEqual(self.decide(version, [])['release'], 'false')

    def test_version_is_read_from_the_runtime(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        import _core
        self.assertEqual(release_check.read_version(ROOT), _core.VERSION)


if __name__ == '__main__':
    unittest.main()
