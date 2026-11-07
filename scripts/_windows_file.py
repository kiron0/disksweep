"""Local NTFS file handles for explicit, digest-bound Windows removal plans."""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path

import _core as core


class FileTime(c.Structure):
    _fields_ = [('low', w.DWORD), ('high', w.DWORD)]


class FileInfo(c.Structure):
    _fields_ = [('attributes', w.DWORD), ('created', FileTime), ('accessed', FileTime),
                ('written', FileTime), ('volume', w.DWORD), ('size_high', w.DWORD),
                ('size_low', w.DWORD), ('links', w.DWORD), ('id_high', w.DWORD), ('id_low', w.DWORD)]


class BasicInfo(c.Structure):
    _fields_ = [('created', c.c_longlong), ('accessed', c.c_longlong), ('written', c.c_longlong),
                ('changed', c.c_longlong), ('attributes', w.DWORD)]


def _api():
    core.require(os.name == 'nt', 'Direct selected-file removal currently requires Windows and local NTFS')
    kernel = c.WinDLL('kernel32', use_last_error=True)
    security = c.WinDLL('advapi32', use_last_error=True)
    signatures = {
        'CreateFileW': ([w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
        'CloseHandle': ([w.HANDLE], w.BOOL),
        'GetFileInformationByHandle': ([w.HANDLE, c.POINTER(FileInfo)], w.BOOL),
        'GetFileInformationByHandleEx': ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
        'GetFinalPathNameByHandleW': ([w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD], w.DWORD),
        'GetFileType': ([w.HANDLE], w.DWORD),
        'GetDriveTypeW': ([w.LPCWSTR], w.UINT),
        'GetVolumeInformationW': ([w.LPCWSTR, w.LPWSTR, w.DWORD, c.c_void_p, c.c_void_p, c.c_void_p, w.LPWSTR, w.DWORD], w.BOOL),
        'SetFileInformationByHandle': ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
        'GetCurrentProcess': ([], w.HANDLE),
        'LocalFree': ([c.c_void_p], c.c_void_p),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(kernel, name); function.argtypes = arguments; function.restype = result
    security.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    security.OpenProcessToken.restype = w.BOOL
    security.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    security.GetTokenInformation.restype = w.BOOL
    security.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
    security.ConvertSidToStringSidW.restype = w.BOOL
    security.GetSecurityInfo.argtypes = [w.HANDLE, c.c_int, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p,
                                       c.c_void_p, c.c_void_p, c.POINTER(c.c_void_p)]
    security.GetSecurityInfo.restype = w.DWORD
    return kernel, security


def _check(ok):
    if not ok:
        raise c.WinError(c.get_last_error())


def _sid(kernel, security, sid):
    text = w.LPWSTR()
    _check(security.ConvertSidToStringSidW(sid, c.byref(text)))
    try:
        return text.value
    finally:
        kernel.LocalFree(c.cast(text, c.c_void_p))


def _current_user(kernel, security):
    token = w.HANDLE()
    _check(security.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)))
    try:
        size = w.DWORD()
        security.GetTokenInformation(token, 1, None, 0, c.byref(size))
        core.require(0 < size.value < 65536, 'Cannot establish the current Windows user')
        buffer = c.create_string_buffer(size.value)
        _check(security.GetTokenInformation(token, 1, buffer, size, c.byref(size)))
        return _sid(kernel, security, c.cast(buffer, c.POINTER(c.c_void_p))[0])
    finally:
        kernel.CloseHandle(token)


def _owner(kernel, security, handle):
    owner, descriptor = c.c_void_p(), c.c_void_p()
    status = security.GetSecurityInfo(handle, 1, 1, c.byref(owner), None, None, None, c.byref(descriptor))
    core.require(status == 0, 'Cannot establish Windows file ownership')
    try:
        return _sid(kernel, security, owner)
    finally:
        kernel.LocalFree(descriptor)


def _nanoseconds(value):
    return (((value.high << 32) | value.low) - 116444736000000000) * 100


class OpenFile:
    """Exclusive handle; protects the exact file from concurrent opens/renames."""
    def __init__(self, entry):
        self.kernel, self.security = _api()
        self.handle = None
        self.path = core.absolute(entry['path'])
        core.require(not str(self.path).startswith(('\\\\', '//')) and ':' not in self.path.name,
                     'Network paths and alternate data streams cannot be removed')
        core.require(self.kernel.GetDriveTypeW(self.path.anchor) == 3, 'Removal requires a local fixed drive')
        filesystem = c.create_unicode_buffer(64)
        _check(self.kernel.GetVolumeInformationW(self.path.anchor, None, 0, None, None, None, filesystem, 64))
        core.require(filesystem.value == 'NTFS', 'Direct removal currently supports local NTFS only')
        core.require(core.identity(self.path.lstat()) == entry['identity'], 'File changed since the scan')
        handle = self.kernel.CreateFileW('\\\\?\\' + str(self.path), 0x30080, 0, None, 3, 0x00300000, None)
        core.require(handle not in (None, c.c_void_p(-1).value), 'File is locked, inaccessible or unavailable; close the application and rescan')
        self.handle = handle
        try:
            core.require(self.kernel.GetFileType(handle) == 1, 'Only regular disk files can be removed')
            final = c.create_unicode_buffer(32768)
            length = self.kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
            core.require(0 < length < len(final), 'Cannot establish the final file location')
            core.require(os.path.normcase(final.value.removeprefix('\\\\?\\')) == os.path.normcase(str(self.path)),
                         'File location redirected or changed')
            core.require(_owner(self.kernel, self.security, handle) == _current_user(self.kernel, self.security),
                         'Only current-user-owned files can be removed')
            metadata = self.snapshot()
            expected = entry['identity']
            core.require(metadata['file_id'] == expected['inode'] and metadata['volume'] == (expected['device'] & 0xffffffff)
                         and metadata['size'] == expected['size'] and metadata['mtime_ns'] == expected['mtime_ns'],
                         'File identity changed while opening it')
        except BaseException:
            self.close(); raise

    def snapshot(self):
        info, basic = FileInfo(), BasicInfo()
        _check(self.kernel.GetFileInformationByHandle(self.handle, c.byref(info)))
        _check(self.kernel.GetFileInformationByHandleEx(self.handle, 0, c.byref(basic), c.sizeof(basic)))
        core.require(info.links == 1 and not info.attributes & (0x1 | 0x10 | 0x400 | 0x1000 | 0x4000 | 0x40000 | 0x400000),
                     'Read-only, linked, redirected, offline, encrypted or recalled files are protected')
        return {'file_id': (info.id_high << 32) | info.id_low, 'volume': info.volume,
                'size': (info.size_high << 32) | info.size_low, 'mtime_ns': _nanoseconds(info.written),
                'change_time': basic.changed, 'attributes': info.attributes, 'links': info.links}

    def close(self):
        if self.handle is not None:
            self.kernel.CloseHandle(self.handle); self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def mark_for_removal(opened):
    """Called only after approval/digest checks and durable intent in _remove.execute."""
    disposition = w.BOOL(True)
    _check(opened.kernel.SetFileInformationByHandle(opened.handle, 4, c.byref(disposition), c.sizeof(disposition)))
