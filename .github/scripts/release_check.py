import argparse
from pathlib import Path
import re
import subprocess
import sys

STABLE = re.compile(r'v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)')


def parse(tag):
    match = STABLE.fullmatch(tag)
    return tuple(int(x) for x in match.groups()) if match else None


def decide(version, tags, tag_exists, release_exists, sha):
    tag = 'v' + version
    current = parse(tag)
    if current is None:
        return {'release': 'false', 'tag': tag, 'ref': sha, 'tag_exists': str(tag_exists).lower(),
                'reason': 'Skill version ' + version + ' is not a stable MAJOR.MINOR.PATCH version; skipped.'}
    if release_exists:
        return {'release': 'false', 'tag': tag, 'ref': sha, 'tag_exists': 'true',
                'reason': 'Release ' + tag + ' already exists; skipped.'}
    if tag_exists:
        return {'release': 'true', 'tag': tag, 'ref': tag, 'tag_exists': 'true',
                'reason': 'Tag ' + tag + ' exists without a release; publishing it from the tagged commit.'}
    newer = [t for t in tags if parse(t) is not None and parse(t) >= current]
    if newer:
        latest = max(newer, key=parse)
        return {'release': 'false', 'tag': tag, 'ref': sha, 'tag_exists': 'false',
                'reason': 'Version ' + tag + ' is not newer than existing ' + latest + '; skipped.'}
    return {'release': 'true', 'tag': tag, 'ref': sha, 'tag_exists': 'false',
            'reason': 'New version ' + tag + ' found; releasing commit ' + sha + '.'}


def read_version(root):
    text = (root / 'scripts' / '_core.py').read_text(encoding='utf-8')
    match = re.search(r'^VERSION = "([^"]+)"$', text, re.M)
    if not match:
        raise SystemExit('VERSION not found in scripts/_core.py')
    return match[1]


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--sha', required=True)
    parser.add_argument('--repo', required=True)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    version = read_version(root)
    tags = subprocess.run(['git', 'tag', '--list', 'v*'], cwd=root, capture_output=True, text=True, check=True).stdout.split()
    tag = 'v' + version
    release = subprocess.run(['gh', 'release', 'view', tag, '--repo', args.repo], cwd=root, capture_output=True, text=True)
    if release.returncode != 0 and 'not found' not in (release.stderr + release.stdout).lower():
        raise SystemExit('Cannot query releases: ' + release.stderr.strip())
    result = decide(version, tags, tag in tags, release.returncode == 0, args.sha)
    for key, value in result.items():
        print(key + '=' + value.replace('\n', ' '))
    print(result['reason'], file=sys.stderr)


if __name__ == '__main__':
    main()
