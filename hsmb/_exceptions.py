# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import struct
import typing

if typing.TYPE_CHECKING:
    from hsmb._header import SMB2Header


class NtStatus(enum.IntEnum):

    STATUS_SUCCESS = 0x00000000
    STATUS_NETWORK_NAME_DELETED = 0xC00000C9
    STATUS_PENDING = 0x00000103
    STATUS_NOTIFY_CLEANUP = 0x0000010B
    STATUS_NOTIFY_ENUM_DIR = 0x0000010C
    STATUS_BUFFER_OVERFLOW = 0x80000005
    STATUS_NO_MORE_FILES = 0x80000006
    STATUS_END_OF_FILE = 0xC0000011
    STATUS_INVALID_EA_NAME = 0x80000013
    STATUS_EA_LIST_INCONSISTENT = 0x80000014
    STATUS_STOPPED_ON_SYMLINK = 0x8000002D
    STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_NO_SUCH_FILE = 0xC000000F
    STATUS_INVALID_DEVICE_REQUEST = 0xC0000010
    STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_BUFFER_TOO_SMALL = 0xC0000023
    STATUS_OBJECT_NAME_INVALID = 0xC0000033
    STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    STATUS_OBJECT_NAME_COLLISION = 0xC0000035
    STATUS_OBJECT_PATH_INVALID = 0xC0000039
    STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
    STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003B
    STATUS_SHARING_VIOLATION = 0xC0000043
    STATUS_EAS_NOT_SUPPORTED = 0xC000004F
    STATUS_EA_TOO_LARGE = 0xC0000050
    STATUS_NONEXISTENT_EA_ENTRY = 0xC0000051
    STATUS_NO_EAS_ON_FILE = 0xC0000052
    STATUS_EA_CORRUPT_ERROR = 0xC0000053
    STATUS_PRIVILEGE_NOT_HELD = 0xC0000061
    STATUS_WRONG_PASSWORD = 0xC000006A
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_INSUFFICIENT_RESOURCES = 0xC000009A
    STATUS_PIPE_NOT_AVAILABLE = 0xC00000AC
    STATUS_PIPE_BUSY = 0xC00000AE
    STATUS_PIPE_DISCONNECTED = 0xC00000B0
    STATUS_PIPE_CLOSING = 0xC00000B1
    STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
    STATUS_NOT_SUPPORTED = 0xC00000BB
    STATUS_BAD_NETWORK_NAME = 0xC00000CC
    STATUS_REQUEST_NOT_ACCEPTED = 0xC00000D0
    STATUS_PIPE_EMPTY = 0xC00000D9
    STATUS_INTERNAL_ERROR = 0xC00000E5
    STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101
    STATUS_NOT_A_DIRECTORY = 0xC0000103
    STATUS_CANCELLED = 0xC0000120
    STATUS_CANNOT_DELETE = 0xC0000121
    STATUS_FILE_CLOSED = 0xC0000128
    STATUS_PIPE_BROKEN = 0xC000014B
    STATUS_USER_SESSION_DELETED = 0xC0000203
    STATUS_NOT_FOUND = 0xC0000225
    STATUS_PATH_NOT_COVERED = 0xC0000257
    STATUS_DFS_UNAVAILABLE = 0xC000026D
    STATUS_NOT_A_REPARSE_POINT = 0xC0000275
    STATUS_SERVER_UNAVAILABLE = 0xC0000466


def unpack_error_response(
    header: "SMB2Header",
    message: typing.Union[bytes, bytearray, memoryview],
    offset: int = 0,
    context: typing.Optional[str] = None,
) -> typing.Tuple["ProtocolError", int]:
    view = memoryview(message)[offset:]

    if len(view) < 9:
        raise MalformedPacket("Error response buffer is out of bounds")

    context_count = struct.unpack("<B", view[2:3])[0]
    byte_count = struct.unpack("<I", view[4:8])[0]

    errors: typing.List = []
    end_idx = 8
    if context_count:
        raise NotImplementedError()  # FIXME

    elif byte_count:
        end_idx += byte_count
        if len(view) < end_idx:
            raise MalformedPacket("Error response error data is out of bounds")

        errors.append(bytes(view[8:end_idx]))

    else:
        end_idx += 1  # There's always at least 1 NULL byte at the end.

    return ProtocolError(header.status, message=context, error_data=errors), end_idx


class SMBError(Exception):
    """Base class for all exception in hsmb."""


class MalformedPacket(SMBError):
    """Failure when unpacking a SMB message from the peer."""


class _SMBErrorRegistry(type):
    __registry: typing.Dict[int, typing.Type] = {}

    def __new__(
        mcls,
        name: str,
        bases: typing.Tuple[typing.Type, ...],
        namespace: typing.Dict[str, typing.Any],
    ) -> "_SMBErrorRegistry":
        cls = super().__new__(mcls, name, bases, namespace)

        code = getattr(cls, "_STATUS_CODE", None)
        if code is not None:
            mcls.__registry[code] = cls

        return cls

    def __call__(
        cls,
        status: typing.Optional[int] = None,
        *args: typing.Any,
        message: typing.Optional[str] = None,
        error_data: typing.Optional[typing.List[typing.Any]] = None,
        **kwargs: typing.Any,
    ) -> object:
        status_code = status if status is not None else getattr(cls, "_STATUS_CODE", 0xFFFFFFFF)
        new_cls = cls.__registry.get(status_code, cls)

        return super(_SMBErrorRegistry, new_cls).__call__(
            status_code, message=message, error_data=error_data, *args, **kwargs
        )


class ProtocolError(SMBError, metaclass=_SMBErrorRegistry):
    """Base class for all SMB status error codes."""

    _BASE_MESSAGE = "Unknown error."

    def __init__(
        self,
        status: int = 0xFFFFFFFF,
        *,
        message: typing.Optional[str] = None,
        error_data: typing.Optional[typing.List[typing.Any]] = None,
    ) -> None:
        self.status = status
        self.error_data = error_data
        self._caller_message = message

    @property
    def message(self) -> str:
        msg = self._BASE_MESSAGE
        if self._caller_message:
            msg += f" {self._caller_message}"

        return msg

    def __str__(self) -> str:
        return self.message


class NetworkNameDelegated(ProtocolError):
    _BASE_MESSAGE = "The network name was deleted."
    _STATUS_CODE = NtStatus.STATUS_NETWORK_NAME_DELETED


class StatusPending(ProtocolError):
    _BASE_MESSAGE = "The operation that was requested is pending completion."
    _STATUS_CODE = NtStatus.STATUS_PENDING


class NotifyCleanup(ProtocolError):
    _BASE_MESSAGE = (
        "Indicates that a notify change request has been completed due to closing the handle that made "
        "the notify change request."
    )
    _STATUS_CODE = NtStatus.STATUS_NOTIFY_CLEANUP


class NotifyEnumDir(ProtocolError):
    _BASE_MESSAGE = (
        "Indicates that a notify change request is being completed and that the information is not "
        "being returned in the caller's buffer. The caller now needs to enumerate the files to find "
        "the changes."
    )
    _STATUS_CODE = NtStatus.STATUS_NOTIFY_ENUM_DIR


class BufferOverflow(ProtocolError):
    _BASE_MESSAGE = "The data was too large to fit into the specified buffer."
    _STATUS_CODE = NtStatus.STATUS_BUFFER_OVERFLOW


class NoMoreFiles(ProtocolError):
    _BASE_MESSAGE = "No more files were found which match the file specification."
    _STATUS_CODE = NtStatus.STATUS_NO_MORE_FILES


class EndOfFile(ProtocolError):
    _BASE_MESSAGE = "The end-of-file marker has been reached. There is no valid data in the file beyond this marker."
    _STATUS_CODE = NtStatus.STATUS_END_OF_FILE


class InvalidEAName(ProtocolError):
    _BASE_MESSAGE = "The specified extended attribute (EA) name contains at least one illegal character."
    _STATUS_CODE = NtStatus.STATUS_INVALID_EA_NAME


class EAListInconsistent(ProtocolError):
    _BASE_MESSAGE = "The extended attribute (EA) list is inconsistent."
    _STATUS_CODE = NtStatus.STATUS_EA_LIST_INCONSISTENT


class StoppedOnSymlink(ProtocolError):
    _BASE_MESSAGE = "The create operation stopped after reaching a symbolic link."
    _STATUS_CODE = NtStatus.STATUS_STOPPED_ON_SYMLINK


class InfoLengthMismatch(ProtocolError):
    _BASE_MESSAGE = (
        "The specified information record length does not match the length that is required for the "
        "specified information class."
    )
    _STATUS_CODE = NtStatus.STATUS_INFO_LENGTH_MISMATCH


class InvalidParameter(ProtocolError):
    _BASE_MESSAGE = "An invalid parameter was passed to a service or function."
    _STATUS_CODE = NtStatus.STATUS_INVALID_PARAMETER


class NoSuchFile(ProtocolError):
    _BASE_MESSAGE = "The file does not exist."
    _STATUS_CODE = NtStatus.STATUS_NO_SUCH_FILE


class InvalidDeviceRequest(ProtocolError):
    _BASE_MESSAGE = "The specified request is not a valid operation for the target device."
    _STATUS_CODE = NtStatus.STATUS_INVALID_DEVICE_REQUEST


class MoreProcessingRequired(ProtocolError):
    _BASE_MESSAGE = (
        "The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not " "complete."
    )
    _STATUS_CODE = NtStatus.STATUS_MORE_PROCESSING_REQUIRED


class AccessDenied(ProtocolError):
    _BASE_MESSAGE = "A process has requested access to an object but has not been granted those access rights."
    _STATUS_CODE = NtStatus.STATUS_ACCESS_DENIED


class BufferTooSmall(ProtocolError):
    _BASE_MESSAGE = "The buffer is too small to contain the entry. No information has been written to the buffer."
    _STATUS_CODE = NtStatus.STATUS_BUFFER_TOO_SMALL


class ObjectNameInvalid(ProtocolError):
    _BASE_MESSAGE = "The object name is invalid."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_NAME_INVALID


class ObjectNameNotFound(ProtocolError):
    _BASE_MESSAGE = "The object name is not found."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_NAME_NOT_FOUND


class ObjectNameCollision(ProtocolError):
    _BASE_MESSAGE = "The object name already exists."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_NAME_COLLISION


class ObjectPathInvalid(ProtocolError):
    _BASE_MESSAGE = "The object path component was not a directory object."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_PATH_INVALID


class ObjectPathNotFound(ProtocolError):
    _BASE_MESSAGE = "The path does not exist."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_PATH_NOT_FOUND


class ObjectPathSyntaxBad(ProtocolError):
    _BASE_MESSAGE = "The object path component was not a directory object."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_PATH_SYNTAX_BAD


class SharingViolation(ProtocolError):
    _BASE_MESSAGE = "A file cannot be opened because the share access flags are incompatible."
    _STATUS_CODE = NtStatus.STATUS_SHARING_VIOLATION


class EASNotSupported(ProtocolError):
    _BASE_MESSAGE = "An operation involving EAs failed because the file system does not support EAs."
    _STATUS_CODE = NtStatus.STATUS_EAS_NOT_SUPPORTED


class EATooLarge(ProtocolError):
    _BASE_MESSAGE = "An EA operation failed because the EA set is too large."
    _STATUS_CODE = NtStatus.STATUS_EA_TOO_LARGE


class NonExistentEAEntry(ProtocolError):
    _BASE_MESSAGE = "An EA operation failed because the name or EA index is invalid."
    _STATUS_CODE = NtStatus.STATUS_NONEXISTENT_EA_ENTRY


class NoEASOnFile(ProtocolError):
    _BASE_MESSAGE = "The file for which EAs were requested has no EAs."
    _STATUS_CODE = NtStatus.STATUS_NO_EAS_ON_FILE


class EACorruptError(ProtocolError):
    _BASE_MESSAGE = "The EA is corrupt and cannot be read."
    _STATUS_CODE = NtStatus.STATUS_EA_CORRUPT_ERROR


class PrivilegeNotHeld(ProtocolError):
    _BASE_MESSAGE = "A required privilege is not held by the client."
    _STATUS_CODE = NtStatus.STATUS_PRIVILEGE_NOT_HELD


class WrongPassword(ProtocolError):
    _BASE_MESSAGE = "The specified password is not correct or the user is locked out."
    _STATUS_CODE = NtStatus.STATUS_WRONG_PASSWORD


class LogonFailure(ProtocolError):
    _BASE_MESSAGE = (
        "The attempted logon is invalid. This is either due to a bad username or authentication " "information."
    )
    _STATUS_CODE = NtStatus.STATUS_LOGON_FAILURE


class PasswordExpired(ProtocolError):
    _BASE_MESSAGE = "The user account password has expired."
    _STATUS_CODE = NtStatus.STATUS_PASSWORD_EXPIRED


class InsufficientResources(ProtocolError):
    _BASE_MESSAGE = "Insufficient system resources exist to complete the API."
    _STATUS_CODE = NtStatus.STATUS_INSUFFICIENT_RESOURCES


class PipeNotAvailable(ProtocolError):
    _BASE_MESSAGE = "An instance of a named pipe cannot be found in the listening state."
    _STATUS_CODE = NtStatus.STATUS_PIPE_NOT_AVAILABLE


class PipeBusy(ProtocolError):
    _BASE_MESSAGE = (
        "The specified pipe is set to complete operations and there are current I/O operations queued "
        "so that it cannot be changed to queue operations."
    )
    _STATUS_CODE = NtStatus.STATUS_PIPE_BUSY


class PipeClosing(ProtocolError):
    _BASE_MESSAGE = "The specified named pipe is in the closing state."
    _STATUS_CODE = NtStatus.STATUS_PIPE_CLOSING


class PipeDisconnected(ProtocolError):
    _BASE_MESSAGE = "The specified named pipe is in the disconnected state."
    _STATUS_CODE = NtStatus.STATUS_PIPE_DISCONNECTED


class FileIsADirectory(ProtocolError):
    _BASE_MESSAGE = (
        "The file that was specified as a target is a directory, and the caller specified that it could "
        "be anything but a directory."
    )
    _STATUS_CODE = NtStatus.STATUS_FILE_IS_A_DIRECTORY


class NotSupported(ProtocolError):
    _BASE_MESSAGE = "The request is not supported."
    _STATUS_CODE = NtStatus.STATUS_NOT_SUPPORTED


class BadNetworkName(ProtocolError):
    _BASE_MESSAGE = "The specified share name cannot be found on the remote server."
    _STATUS_CODE = NtStatus.STATUS_BAD_NETWORK_NAME


class RequestNotAccepted(ProtocolError):
    _BASE_MESSAGE = (
        "No more connections can be made to this remote computer at this time because the computer has "
        "already accepted the maximum number of connections."
    )
    _STATUS_CODE = NtStatus.STATUS_REQUEST_NOT_ACCEPTED


class PipeEmpty(ProtocolError):
    _BASE_MESSAGE = "Used to indicate that a read operation was done on an empty pipe."
    _STATUS_CODE = NtStatus.STATUS_PIPE_EMPTY


class InternalError(ProtocolError):
    _BASE_MESSAGE = "An internal error occurred."
    _STATUS_CODE = NtStatus.STATUS_INTERNAL_ERROR


class DirectoryNotEmpty(ProtocolError):
    _BASE_MESSAGE = "Indicates that the directory trying to be deleted is not empty."
    _STATUS_CODE = NtStatus.STATUS_DIRECTORY_NOT_EMPTY


class StatusNotADirectory(ProtocolError):
    _BASE_MESSAGE = "A requested opened file is not a directory."
    _STATUS_CODE = NtStatus.STATUS_NOT_A_DIRECTORY


class Cancelled(ProtocolError):
    _BASE_MESSAGE = "The I/O request was canceled."
    _STATUS_CODE = NtStatus.STATUS_CANCELLED


class CannotDelete(ProtocolError):
    _BASE_MESSAGE = "An attempt has been made to remove a file or directory that cannot be deleted."
    _STATUS_CODE = NtStatus.STATUS_CANNOT_DELETE


class FileClosed(ProtocolError):
    _BASE_MESSAGE = (
        "An I/O request other than close and several other special case operations was attempted using "
        "a file object that had already been closed."
    )
    _STATUS_CODE = NtStatus.STATUS_FILE_CLOSED


class PipeBroken(ProtocolError):
    _BASE_MESSAGE = "The pipe operation has failed because the other end of the pipe has been closed."
    _STATUS_CODE = NtStatus.STATUS_PIPE_BROKEN


class UserSessionDeleted(ProtocolError):
    _BASE_MESSAGE = "The remote user session has been deleted."
    _STATUS_CODE = NtStatus.STATUS_USER_SESSION_DELETED


class NotFound(ProtocolError):
    _BASE_MESSAGE = "The object was not found."
    _STATUS_CODE = NtStatus.STATUS_NOT_FOUND


class PathNotCovered(ProtocolError):
    _BASE_MESSAGE = "The contacted server does not support the indicated part of the DFS namespace."
    _STATUS_CODE = NtStatus.STATUS_PATH_NOT_COVERED


class DfsUnavailable(ProtocolError):
    _BASE_MESSAGE = "DFS is unavailable on the contacted server."
    _STATUS_CODE = NtStatus.STATUS_DFS_UNAVAILABLE


class NotAReparsePoint(ProtocolError):
    _BASE_MESSAGE = "The NTFS file or directory is not a reparse point."
    _STATUS_CODE = NtStatus.STATUS_NOT_A_REPARSE_POINT


class ServerUnavailable(ProtocolError):
    _BASE_MESSAGE = "The file server is temporarily unavailable."
    _STATUS_CODE = NtStatus.STATUS_SERVER_UNAVAILABLE
