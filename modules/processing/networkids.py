# Copyright (C) 2013 David Maciejak
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import sys
import stat
import getpass
import logging
import subprocess
from string import lower

from lib.cuckoo.common.abstracts import Processing 
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_GUEST_PORT
from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

class NetworkIds(Processing):

    #snort sig examples
    #10/24-20:26:36.154317  [**] [1:989:11] BACKDOOR sensepost.exe command shell attempt [**] [Classification: access to a potentially vulnerable web application] [Priority: 2] {TCP} 192.168.56.101:1189 -> 216.119.158.225:80
    #10/28-11:44:43.322380  [**] [1:399:6] ICMP Destination Unreachable Host Unreachable [**] [Classification: Misc activity] [Priority: 3] {ICMP} 217.30.200.195 -> 192.168.56.101

    def _parse_nids_log(self,logfile):    	
        filter = ".*\]\s(.+)\s\[.*\s\[Classification:\s(.*)\]\s\[Priority:\s(\d+)\]\s\{(.+)\}\s([^:\s]+):?(\d+)?\s->\s([^:\s]+):?(\d+)?$"
        regexp = re.compile(filter)
        
        self.nids["total"] = 0
        self.nids["raw"] = []
        self.nids["classification"] = []
        
        f = open(logfile, 'r')
        for line in f.readlines():
            line = line.rstrip('\n')
            if line:
                result = regexp.match(line)
                if result and result.group():
                    signame = result.group(1)
                    classification = result.group(2)
                    priority = result.group(3)
                    protocol = lower(result.group(4))
                    src_ip = result.group(5)
                    src_port = result.group(6)                    
                    dst_ip = result.group(7)
                    dst_port = result.group(8)
                    log.error(dst_ip)
                    if protocol != "tcp" and protocol != "udp":
                        dst_port = -1
                    data = {
                        "sig" : signame,
                        "protocol" : protocol,
                        "dst" : dst_ip,
                        "dst_port": int(dst_port)
                    }                    
                        
                    self.nids["raw"].append(result.group())

                    if len(self.nids["classification"]) > 0:
                        for existing_class in self.nids["classification"]:                       
                            if existing_class["class"] == classification.title():
                                existing_class["data"].append(data)
                    else:
                        self.nids["classification"].append({"class": classification.title(), "data": [data], "priority": int(priority)})
                    
                self.nids["total"] += 1
        f.close()
        return self.nids
        
    def run(self):
        nids_bin_path = self.options.get("snort", "/usr/sbin/snort")
        nids_cfg_path = self.options.get("snortcfg", "/etc/snort/snort.conf")
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task["id"]), "dump.pcap")
        nids_log_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task["id"]), "nids.log")
        self.nids = {}
        self.key = "nids"

        if not os.path.exists(nids_bin_path):
            log.error("NIDS does not exist at path \"%s\"", nids_bin_path)
            return

        mode = os.stat(nids_bin_path)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
            log.error("NIDS is not accessible from this user")
            return

        if not os.path.exists(file_path):
            log.error("PCAP does not exist for TASK %s", str(self.task.id))
            return
	    
        pargs = [nids_bin_path, "-A", "console", "-c", nids_cfg_path, "-r", file_path]

        try:
            user = getpass.getuser()
        except:
            pass
        else:
            pargs.extend(["-u", user])

	sys.stdout = open(nids_log_path, 'w',0)
	
        try:
            process = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	    #writing to standard output
	    for line in process.stdout:
                print line
	    process.wait()
	    if process.returncode != 0:
	        log.error("NIDS failed to exit cleanly, see details below")
                for line in process.stderr:
                    log.error(line.rstrip("\n"))
		return
        except (OSError, ValueError) as e:
            log.exception("Failed to start NIDS on dump file path=%s", file_path)
            return
       
        #check if some sigs matched
	if not os.path.exists(nids_log_path) or os.path.getsize(nids_log_path) <= 0:
	    return
	    
	log.debug("NIDS detection found")
	
	self._parse_nids_log(nids_log_path)
	return self.nids

