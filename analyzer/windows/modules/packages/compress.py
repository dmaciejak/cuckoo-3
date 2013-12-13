# Copyright (C) 2013 David Maciejak

import os
import subprocess
import tempfile

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Compress(Package):
    """Compress analysis package, decompression based on 7-zip."""

    def start(self, path):
        root = os.environ["TEMP"]
        password = self.options.get("password", None)
        file_name = self.options.get("file", None)
        
        tmp_dir = tempfile.mkdtemp(prefix="cmp", dir=root)

        szip_path = os.path.join(os.getenv("ProgramFiles"), "7-Zip", "7z.exe")
        szip_args = ["e", "-y", "-o{0}".format(tmp_dir)]
        
        if password:
            szip_args.append("-p{0}".format(password)) 
        
        szip_args.append("{0}".format(path))
        if file_name:
            szip_args.append("{0}".format(file_name))
            
        szip_cmd = [szip_path] + szip_args
        try:
            subprocess.call(szip_cmd)
        except:
            raise CuckooPackageError("Failed to extract, is 7z installed on guest ?")
            return None

        #extract may have succeed, trying to get the filename if not provided
        sample_path = None
        if file_name:
            sample_path = os.path.join(tmp_dir, file_name)

        files = [ f for f in os.listdir(tmp_dir) if os.path.isfile(os.path.join(tmp_dir, f)) ]
        if len(files) > 0:
            sample_path = os.path.join(tmp_dir, files[0])

        if not sample_path:
            return None

        free = self.options.get("free", False)
        args = self.options.get("arguments", None)
        dll = self.options.get("dll", None)
        suspended = True
        
        if free:
            suspended = False
        
        p = Process()
        if not p.execute(path=sample_path, args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial process, "
                                     "analysis aborted")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            p.close()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        if self.options.get("procmemdump", False):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True
