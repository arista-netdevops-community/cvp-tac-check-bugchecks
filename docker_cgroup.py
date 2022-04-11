# pylint: disable=invalid-name, useless-super-delegation, arguments-differ, line-too-long
from bugchecks.bug import Bug
import lib.return_codes as code

import time

class docker_cgroup(Bug):
    """ Bugcheck description
    """
    def __init__(self):
        super(docker_cgroup, self).__init__()

        self.grub_template = '/etc/default/grub'
        self.is_configured = False
        self.log_check_files = ['journalctl', 'kube_pod']

    def scan(self):
        value = code.OK
        message = None
        was_checked = True
        is_configured = False
        is_applied = False
        is_affected = False

        if self.is_using_local_logs():
            was_checked = False
            for file in self.log_check_files:
                contents = self.read_file(self.local_directory(directory_type='commands')+'/'+file)
                for line in contents:
                    if 'cannot allocate memory' in line and 'cgroup' in line:
                        is_affected = True
        else:
            is_configured = self.run_command("grep -E ^GRUB_CMDLINE_LINUX.*cgroup.memory=nokmem.* " + self.grub_template).stdout
            is_applied = self.run_command("grep cgroup.memory=nokmem /proc/cmdline").stdout
            is_affected = self.run_command("kubectl describe pods -A|grep -E 'cgroup.*cannot allocate memory'").stdout

        if is_configured:
            self.is_configured = True

        if is_affected:
            message = "Affected. Check /var/log to see if kubelet logs need to be cleaned as well."
            value = code.ERROR
        elif not was_checked:
            message = "Unable to check if the patch has been applied."
        elif not is_configured and not is_applied:
            message = "Vulnerable. Issues might be experienced in the future."
            value = code.WARNING
        elif is_configured and not is_applied:
            message = "Configured, Reboot required."
            value = code.WARNING
        elif not is_configured:
            message = "Vulnerable. Current kernel has the patch applied but configuration is missing."
            value = code.WARNING

        self.set_status(value, message)
        return value

    def patch(self):
        value = code.OK
        message = None

        if not self.is_configured:
            grub_template_backup = self.grub_template + "-" + str(int(time.time())) + ".bkp"
            self.debug('Backing up file ' + self.grub_template + " to " + grub_template_backup, code.LOG_INFO)
            command = "cp " + self.grub_template + " " + grub_template_backup
            multi_host_result = self.run_command(command, all_nodes=True)
            if multi_host_result.exit_code != code.OK:
                for host in multi_host_result.hosts:
                    if eval("multi_host_result."+host+".exit_code") != code.OK:
                        self.debug("Could not backup %s on %s: %s" %(self.grub_template, host, eval("multi_host_result."+host+".stderr")), code.LOG_ERROR)
                value = code.ERROR
                message = "Could not backup %s" %self.grub_template
            else:
                self.debug('Patching file ' + self.grub_template, code.LOG_INFO)
                command = "grep cgroup.memory=nokmem %s|| sed -i -r 's/^GRUB_CMDLINE_LINUX=\"(.*)\"$/GRUB_CMDLINE_LINUX=\"\\1 cgroup.memory=nokmem\"/g' %s" %(self.grub_template, self.grub_template)
                multi_host_result = self.run_command(command, all_nodes=True)
                if multi_host_result.exit_code != code.OK:
                    for host in multi_host_result.hosts:
                        if eval("multi_host_result."+host+".exit_code") != code.OK:
                            self.debug("Couldn't patch file %s on %s: %s" %(self.grub_template, host, eval("multi_host_result."+host+".stderr")), code.LOG_ERROR)
                    value = code.ERROR
                    message = "Couldn't patch file %s" %self.grub_template
                else:
                    self.debug('Generating new grub configuration', code.INFO)
                    command = "grub2-mkconfig -o /boot/grub2/grub.cfg"
                    multi_host_result = self.run_command(command, all_nodes=True)
                    if multi_host_result.exit_code != code.OK:
                        for host in multi_host_result.hosts:
                            if eval("multi_host_result."+host+".exit_code") != code.OK:
                                self.debug("Couldn't generate new grub configuration on %s: %s" %(host, eval("multi_host_result."+host+".stderr")), code.LOG_ERROR)
                        value = code.ERROR
                        message = "Couldn't generate new grub configuration"

        return(value, message)
