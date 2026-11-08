import os
import stat

import _core as core


def supported():
    return (os.name == 'posix' and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.unlink in os.supports_dir_fd)


class OpenFile:
    def __init__(self, entry):
        core.require(supported(), 'Direct removal requires POSIX directory handles on this platform')
        self.parent = None
        self.handle = None
        self.path = core.absolute(entry['path'])
        self.name = self.path.name
        core.require(core.identity(self.path.lstat()) == entry['identity'], 'File changed since the scan')
        self.parent_context = core.directory_fd(self.path.parent)
        self.parent = self.parent_context.__enter__()
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOCTTY', 0)
            self.handle = os.open(self.name, flags, dir_fd=self.parent)
            metadata = self.snapshot()
            expected = entry['identity']
            core.require(metadata['file_id'] == expected['inode'] and metadata['volume'] == expected['device']
                         and metadata['size'] == expected['size'] and metadata['mtime_ns'] == expected['mtime_ns'],
                         'File identity changed while opening it')
            core.require(os.fstat(self.parent).st_dev == metadata['volume'], 'File crosses a mount boundary')
        except BaseException:
            self.close(); raise

    def snapshot(self):
        value = os.fstat(self.handle)
        named = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
        core.require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1,
                     'Only regular single-link files can be removed')
        core.require(value.st_uid == os.getuid(), 'Only current-user-owned files can be removed')
        core.require((named.st_dev, named.st_ino) == (value.st_dev, value.st_ino), 'File location redirected or changed')
        return {'file_id': value.st_ino, 'volume': value.st_dev, 'size': value.st_size,
                'mtime_ns': value.st_mtime_ns, 'change_time': value.st_ctime_ns,
                'mode': value.st_mode, 'links': value.st_nlink}

    def close(self):
        if self.handle is not None:
            os.close(self.handle); self.handle = None
        if self.parent is not None:
            self.parent = None
            self.parent_context.__exit__(None, None, None)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def mark_for_removal(opened):
    before = opened.snapshot()
    named = os.stat(opened.name, dir_fd=opened.parent, follow_symlinks=False)
    core.require((named.st_dev, named.st_ino) == (before['volume'], before['file_id']), 'File location redirected or changed')
    os.unlink(opened.name, dir_fd=opened.parent)
