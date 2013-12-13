# Copyright 2013 - David Maciejak
# mostly based on code from pyexif https://github.com/EdLeafe/pyexif


import os
import json
import subprocess


_EXIFTOOL_INSTALLED = True


def _runproc(cmd, fpath=None):
    if not _EXIFTOOL_INSTALLED:
        raise RuntimeError("Running this class requires that exiftool is installed")
    pipe = subprocess.PIPE
    proc = subprocess.Popen([cmd], shell=True, stdin=pipe, stdout=pipe, stderr=pipe, close_fds=True)
    proc.wait()
    err = proc.stderr.read()
    if err:
        raise RuntimeError(err)
    else:
        return proc.stdout.read()

class ExifTool(object):
    def __init__(self, file_path=None):
        if not os.path.exists(file_path):
            return None
        # Test if the exiftool is installed
        try:
            out = _runproc("exiftool -ver")
        except RuntimeError as e:
            _EXIFTOOL_INSTALLED = False
            raise RuntimeError("exiftool could not be found")
        self.file_path = file_path
        super(ExifTool, self).__init__()

    def getAllTags(self):
        """Returns all tags.
        """
        cmd = """exiftool -j -d "%Y:%m:%d %H:%M:%S" "{self.file_path}" """.format(**locals())
        out = _runproc(cmd, self.file_path)
        ret = json.loads(out)[0]
        if ret:
            #remove some unwanted tags, doing that way as -x seems not working for all tags
            ret.pop("Directory")
            if ret.has_key("Error"):
                ret.pop("Error")
            ret.pop("ExifToolVersion")
            ret.pop("FileName")
            ret.pop("FilePermissions")
            ret.pop("FileSize")
            ret.pop("SourceFile")
        return ret

    def getTag(self, tag, default=None):
        """Returns the value of the specified tag, or the default value
        if the tag does not exist.
        """
        cmd = """exiftool -j -d "%Y:%m:%d %H:%M:%S" -{tag} "{self.file_path}" """.format(**locals())
        out = _runproc(cmd, self.file_path)
        info = json.loads(out)[0]
        ret = info.get(tag, default)
        return ret
