# validators.py
#
# validators for file uploads, etc.

import codecs
import logging
import os
import zipfile

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from helpdesk import settings as helpdesk_settings

logger = logging.getLogger("helpdesk")

_MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10 MB, matches nginx's client_max_body_size

# Magic bytes: the first bytes of a real file of each type.
_SIGNATURES = {
    ".png": b"\x89PNG\r\n\x1a\n",
    ".jpg": b"\xff\xd8\xff",
    ".pdf": b"%PDF-",
    ".doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    ".docx": b"PK\x03\x04",
    ".odt": b"PK\x03\x04",
}
_TEXT_EXTENSIONS = {".txt", ".asc", ".eml"}
_HEAD_SIZE = 8192


def _is_text(head):
    """True if the bytes look like plain UTF-8 text (no NULs, valid UTF-8)."""
    if b"\x00" in head:
        return False
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        # final=False tolerates a multi-byte character cut off at the buffer edge
        decoder.decode(head, final=False)
    except UnicodeDecodeError:
        return False
    return True


def _zip_matches(value, ext):
    """A .docx / .odt must be a ZIP with the internal layout of that format."""
    try:
        with zipfile.ZipFile(value) as z:
            names = z.namelist()
            if ext == ".docx":
                return "[Content_Types].xml" in names and any(
                    n.startswith("word/") for n in names
                )
            if ext == ".odt":
                if "mimetype" not in names:
                    return False
                with z.open("mimetype") as m:
                    return m.read(100) == b"application/vnd.oasis.opendocument.text"
    except (zipfile.BadZipFile, OSError, KeyError):
        return False
    return False


def validate_file_extension(value):
    if not helpdesk_settings.HELPDESK_VALIDATE_ATTACHMENT_TYPES:
        return

    # Explicit app-level size backup. DATA_UPLOAD_MAX_MEMORY_SIZE and
    # FILE_UPLOAD_MAX_MEMORY_SIZE do not cap individual uploaded file size in
    # Django's multipart parser, so this check must be explicit rather than
    # relying on either setting. This is the backup for anything that reaches
    # the app another way (not through nginx, or a misconfigured proxy); nginx's
    # client_max_body_size remains the first line of defence at the edge.
    if value.size > _MAX_ATTACHMENT_SIZE:
        logger.warning("attachment rejected: reason=too_large size=%d", value.size)
        raise ValidationError(_("File is too large."))

    filename = os.path.basename(value.name)
    ext = os.path.splitext(filename)[1].lower()

    # Reject filenames with more than one dot outright (shell.php.png).
    # Logged by reason code only: the raw filename is never written to the
    # log, since an attacker-controlled filename containing a newline could
    # otherwise forge extra log lines.
    if filename.count(".") > 1:
        logger.warning(
            "attachment rejected: reason=multiple_extensions size=%d", value.size
        )
        raise ValidationError(
            _("Filenames with multiple extensions are not allowed: ") + filename
        )

    # Allowlist, fail closed: no extension (or a bare ".") is rejected too.
    if ext not in helpdesk_settings.HELPDESK_VALID_EXTENSIONS:
        logger.warning(
            "attachment rejected: reason=bad_extension ext=%s size=%d", ext, value.size
        )
        raise ValidationError(_("Unsupported file extension: ") + ext)

    # Content check: the bytes must match what the extension claims.
    # The declared Content-Type is never consulted.
    try:
        value.seek(0)
        head = value.read(_HEAD_SIZE)
        value.seek(0)

        if ext in _SIGNATURES:
            ok = head.startswith(_SIGNATURES[ext])
            if ok and ext in (".docx", ".odt"):
                ok = _zip_matches(value, ext)
        elif ext in _TEXT_EXTENSIONS:
            ok = _is_text(head)
        else:
            ok = False  # allowlisted by config but no checker: fail closed
    finally:
        value.seek(0)

    if not ok:
        logger.warning(
            "attachment rejected: reason=content_mismatch ext=%s size=%d",
            ext,
            value.size,
        )
        raise ValidationError(_("File content does not match its extension."))

    logger.info("attachment validated: ext=%s size=%d", ext, value.size)