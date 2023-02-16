# pylint: disable=invalid-name, useless-super-delegation, missing-class-docstring
from bugchecks.bug import Bug
import lib.return_codes as code

import re

class os_oom(Bug):
    def __init__(self):
        super(os_oom, self).__init__()

        self.system_process_regex = r'Out of memory: Kill[e,d]*? process [^ ]+ \(([^\)]+)\)'
        self.kubelet_process_regex = 'oom event: [^ ]+ ([^ ]+)'
        self.initial_grep_filter = '(memory|oom)'

    def __check_oom(self, line):
        status = code.OK
        process = None
        if 'oom event' in line:
            self.debug("OOM found in line: %s" %line, code.LOG_JEDI)
            status = code.ERROR
            process = re.search(self.kubelet_process_regex, line, re.IGNORECASE)
            if process:
                process = process.groups()[0]
        elif 'Out of memory' in line or 'out of memory' in line:
            self.debug("OOM found in line: %s" %line, code.LOG_JEDI)
            status = code.ERROR
            process = re.search(self.system_process_regex, line, re.IGNORECASE)
            if process:
                process = process.groups()[0]

        return(status, process)

    def __scan_logs(self):
        status = code.OK
        processes = []
        journal = []
        diagnostic_files = []

        kubelet_journal_file = self.local_directory(directory_type='logs')+'/kubelet_journalctl'
        system_journal_file = self.local_directory(directory_type='commands')+'/journalctl'

        try:
            kubelet_journal = self.read_file(kubelet_journal_file)
        except:
            self.debug("Could not read " + file, code.LOG_WARNING)
            kubelet_journal = []

        try:
            system_journal = self.read_file(system_journal_file)
        except:
            self.debug("Could not read " + file, code.LOG_WARNING)
            system_journal = []

        line_number=1
        for line in kubelet_journal:
            oom, process = self.__check_oom(line)
            if oom != code.OK:
                status = code.ERROR
                diagnostic_entry = "%s:%s" %(kubelet_journal_file, line_number)
                diagnostic_files.append(diagnostic_entry)
                if process and process not in processes:
                    processes.append(process)
                if 'kubelet' not in journal:
                    journal.append('kubelet')
            line_number += 1

        line_number=1
        for line in system_journal:
            oom, process = self.__check_oom(line)
            if oom != code.OK:
                status = code.ERROR
                diagnostic_entry = "%s:%s" %(system_journal_file, line_number)
                diagnostic_files.append(diagnostic_entry)
                if process and process not in processes:
                    processes.append(process)
                if 'system' not in journal:
                    journal.append('system')
            line_number += 1

        return(status, processes, journal, diagnostic_files)

    def __scan_node(self):
        status = code.OK
        processes = []
        journal = []
        diagnostic_files = []

        journalcmd = "dmesg -T|egrep -i '%s'" %self.initial_grep_filter
        system_journal = self.run_command(journalcmd).stdout

        if system_journal:
            line_number=1
            for line in system_journal:
                oom, process = self.__check_oom(line)
                if oom != code.OK:
                    diagnostic_files.append("%s:%s" %(journalcmd, line_number))
                    status = code.ERROR
                    if process and process not in processes:
                        processes.append(process)
                    if 'system' not in journal:
                        journal.append('system')
                line_number += 1

        return(status, processes, journal, diagnostic_files)

    def scan(self):
        status = None
        message = None
        processes = None
        diagnostic_files = []
        if self.is_using_local_logs():
            self.debug("Scanning debug logs", code.LOG_DEBUG)
            status, processes, journal, diagnostic_files = self.__scan_logs()
        else:
            self.debug("Performing live scan", code.LOG_DEBUG)
            status, processes, journal, diagnostic_files = self.__scan_node()

        if status != code.OK:
            message = "OOMs in " + ', '.join(journal) + ": [" + ', '.join(processes) + "]"

        self.set_status(
            value = status,
            message = message,
            extra = processes,
            diagnostic_files=diagnostic_files
        )
        return(status)

