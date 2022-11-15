# pylint: disable=line-too-long, consider-using-dict-items
from contextlib import closing
import json
import os
import socket
import requests
import lib.return_codes as code
from lib.debugger import Debugger

class Updater:
    '''Checks for and downloads updated bugcheck versions'''
    def __init__(self, bugcheck_dir, source='github', metadata_address=None, log_level=3):
        self.version = 1
        self.bugcheck_dir = bugcheck_dir
        self.source = source
        self.available = []
        self.needs_bug_engine_update = []
        self.new = []

        self.debug = Debugger('updater', level=log_level)
        self.debug = self.debug.debug

        libdir = '/'.join(bugcheck_dir.split('/')[:-1]) + '/lib'
        with open(libdir+'/core_versions.json', 'r') as versions:
            self.core_versions=json.load(versions)

        if source == 'github':
            self.metadata_address = 'https://raw.githubusercontent.com/arista-netdevops-community/cvp-tac-check-bugchecks/main/files.json'.lower()
        elif metadata_address:
            self.metadata_address = metadata_address

        self.metadata_protocol = self.metadata_address.split(':')[0].lower()

        try:
            self.metadata_port = int(self.metadata_address.split(':')[2].split('/')[0])
        except IndexError:
            if self.metadata_protocol == 'http':
                self.metadata_port = 80
            elif self.metadata_protocol == 'https':
                self.metadata_port = 443
            elif self.metadata_protocol == 'ssh' or self.metadata_protocol == 'git':
                self.metadata_port = 22
            else:
                raise RuntimeError('Unknow metadata protocol')

        # if self.__check_port(host=self.metadata_address.split('/')[2], port=self.metadata_port) != 0:
        #     raise(RuntimeError('Cannot connect to %s' %self.metadata_address))

        self.check_updates(refresh=True)

    def __check_port(self, host, port, timeout_in_seconds=5):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_in_seconds)
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            try:
                result = sock.connect_ex((host, port))
                return(result)
            except socket.gaierror:
                return(code.ERROR)

    def __load_local_bugcheck_metadata(self, bugcheck_dir, bugcheck_id=None):
        metadata = {}
        if not bugcheck_id:
            file_list = [bugcheck_dir + '/' + f for f in os.listdir(bugcheck_dir) if f.endswith('.json')]
        else:
            file_list = [bugcheck_dir + '/' + f for f in os.listdir(bugcheck_dir) if f == '%s.json' %bugcheck_id]
        for file in file_list:
            with open(file, 'r') as rfile:
                bugcheck_id = file.split('/')[-1].split('.')[0]
                bugcheck_metadata = json.load(rfile)
                bugcheck_version = bugcheck_metadata['version']
                try:
                    bug_engine_version = bugcheck_metadata['bug_engine_version']
                except KeyError:
                    bug_node_version = bugcheck_metadata['node_version']

                metadata[bugcheck_id] = {}
                metadata[bugcheck_id]['version'] = bugcheck_version
                if bug_engine_version:
                    metadata[bugcheck_id]['bug_engine_version'] = bug_engine_version
                else:
                    metadata[bugcheck_id]['node_version'] = bug_node_version
                metadata[bugcheck_id]['replaced_by'] = bugcheck_metadata.get('replaced_by')
                metadata[bugcheck_id]['replaces'] = bugcheck_metadata.get('replaces')

        return metadata

    def __load_remote_bugcheck_metadata(self, protocol, address):
        metadata = {}
        if protocol == 'http' or protocol == 'https':
            self.debug("Loading updates json from remote file %s" %address, code.LOG_DEBUG)
            content = requests.get(address, timeout=5, allow_redirects=True).content
            metadata = json.loads(content)
        elif protocol == 'file':
            self.debug("Loading updates json from local file %s" %address, code.LOG_DEBUG)
            with open(address, 'r') as content:
                metadata = json.load(content)
        else:
            raise RuntimeError('Unsupported protocol %s' %protocol)
        return metadata

    def __is_newer_than(self, version1, version2):
        version1 = version1.split('.')
        version2 = version2.split('.')
        if int(version1[0]) > int(version2[0]):
            return True
        elif int(version1[0]) < int(version2[0]):
            return False
        elif int(version1[1]) > int(version2[1]):
            return True
        elif int(version1[1]) < int(version2[1]):
            return False
        elif int(version1[2]) > int(version2[2]):
            return True
        return False

    def check_obsolete(self, bugcheck_id=None):
        '''Checks for bugchecks that have been replaced'''
        obsolete = []
        local_metadata = self.__load_local_bugcheck_metadata(self.bugcheck_dir, bugcheck_id)
        for bugcheck_id in local_metadata:
            replaced_by = local_metadata[bugcheck_id].get('replaced_by')
            if replaced_by:
                if self.local_metadata.get(replaced_by):
                    self.debug("%s has been replaced by %s" %(bugcheck_id, replaced_by), code.LOG_DEBUG)
                    obsolete.append(bugcheck_id)
                else:
                    self.debug("%s has been replaced by %s, but %s is not installed" %(bugcheck_id, replaced_by, replaced_by), code.LOG_INFO)
            else:
                self.debug("%s is not obsolete" %bugcheck_id, code.LOG_JEDIMASTER)
        return obsolete

    def check_updates(self, refresh=False):
        '''Check for updatable bugchecks'''
        self.available = []
        self.needs_bug_engine_update = []
        self.new = []

        self.debug('Checking for updates... ', code.LOG_INFO, eol=False, flush=True)
        try:
            self.local_metadata = self.__load_local_bugcheck_metadata(self.bugcheck_dir)
            if refresh:
                self.remote_metadata = self.__load_remote_bugcheck_metadata(protocol=self.metadata_protocol, address=self.metadata_address)

            local_bug_engine_version = self.local_metadata['bug']['version']
            for bugcheck_id in self.local_metadata:
                if self.remote_metadata.get(bugcheck_id):
                    local_version  = self.local_metadata[bugcheck_id]['version']
                    remote_version = self.remote_metadata[bugcheck_id]['version']
                    if bugcheck_id != 'bug':
                        remote_bug_engine_requirement = self.remote_metadata[bugcheck_id]['bug_engine_version']
                        if self.__is_newer_than(remote_version, local_version):
                            if not self.__is_newer_than(remote_bug_engine_requirement, local_bug_engine_version):
                                self.available.append(bugcheck_id)
                            else:
                                self.debug("%s %s requires Bug engine %s" %(bugcheck_id, remote_version, remote_bug_engine_requirement), code.LOG_DEBUG)
                                self.needs_bug_engine_update.append(bugcheck_id)
                    else:
                        local_node_version = self.core_versions['node']
                        remote_node_requirement = self.remote_metadata[bugcheck_id]['node_version']
                        if self.__is_newer_than(remote_version, local_version):
                            if not self.__is_newer_than(remote_node_requirement, local_node_version):
                                self.available.append(bugcheck_id)
                            else:
                                self.debug("Bug engine %s requires a newer script version." %remote_version, code.LOG_WARNING)
                                self.debug("Please update to the latest version to receive further updates.", code.LOG_WARNING)
                else:
                    self.debug("Bugcheck %s not found in remote repository (are you using a dev release?)" %bugcheck_id, code.LOG_DEBUG)

            for bugcheck_id in [i for i in self.remote_metadata if not i.startswith('_')]:
                if bugcheck_id not in self.local_metadata.keys():
                    superseded = False
                    for local_bugcheck in self.local_metadata:
                        if self.local_metadata[local_bugcheck].get('replaces') and bugcheck_id in self.local_metadata[local_bugcheck].get('replaces'):
                            self.debug("%s has been superseded by %s. Not updating." %(bugcheck_id, local_bugcheck), code.LOG_DEBUG)
                            superseded = True
                    if not superseded:
                        remote_bug_engine_requirement = self.remote_metadata[bugcheck_id]['bug_engine_version']
                        if not self.__is_newer_than(remote_bug_engine_requirement, local_bug_engine_version):
                            self.available.append(bugcheck_id)
                        else:
                            self.debug("New bugcheck %s requires Bug engine %s" %(bugcheck_id, remote_bug_engine_requirement), code.LOG_DEBUG)
                            self.needs_bug_engine_update.append(bugcheck_id)

            for other in [i for i in self.remote_metadata if i.startswith('_')]:
                other_filename = '/'.join(other.split('_')[1:])
                with open(other_filename+'.py') as file:
                    for line in file:
                        if 'self.version =' in line:
                            local_version = int(line.split('=')[1].strip())
                            break
                if local_version and local_version < self.remote_metadata[other]['version']:
                    self.available.append(other_filename)

            obsolete = self.check_obsolete()
            for bugcheck_id in obsolete:
                if bugcheck_id in self.available:
                    self.available.remove(bugcheck_id)
            availability_message = '%s available' %str(len(self.available))
            if len(self.available) > 0:
                availability_message = '%s (%s)' %(availability_message, ', '.join(self.available))
            self.debug(availability_message, code.LOG_INFO, raw_message=True, flush=True)
            self.debug("Checking for obsolete bugchecks... %s found" %len(obsolete), code.LOG_INFO)
            if obsolete:
                self.debug("Removing obsolete bugchecks %s..." %', '.join(obsolete), code.LOG_INFO)
                for bugcheck_id in obsolete:
                    self.delete_bugcheck(bugcheck_id)
            if self.available:
                return True
            return False
        except Exception as error_message:
            self.debug('Error %s' %error_message, code.LOG_WARNING, raw_message=True)

    def delete_bugcheck(self, bugcheck_id):
        '''Removes a bugcheck'''
        retval = False
        file_name = self.bugcheck_dir + '/' + bugcheck_id + '.py'
        metadata_name = self.bugcheck_dir + '/' + bugcheck_id + '.json'
        if bugcheck_id != 'bug' and os.path.isfile(file_name):
            try:
                self.debug("Removing %s" %file_name, code.LOG_INFO)
                os.remove(file_name)
                if os.path.isfile(metadata_name):
                    self.debug("Removing %s" %metadata_name, code.LOG_INFO)
                    os.remove(metadata_name)
                retval = True
            except Exception as error_message:
                self.debug("Error removing %s: %s" %(bugcheck_id, error_message), code.LOG_ERROR)
        else:
            self.debug("Something looks wrong, not removing %s.\nIf you're sure this is ok, remove the .py and .json manually." %bugcheck_id, code.LOG_WARNING)
        return retval

    def update_all(self):
        '''Updates all bugchecks'''
        updated = []
        if 'bug' in self.available:
            if self.update_bugcheck('bug'):
                updated.append('bug')
            self.check_updates()
        for bugcheck in self.available:
            if self.update_bugcheck(bugcheck):
                updated.append(bugcheck)
        self.debug("Checking for obsolete bugchecks...", code.LOG_DEBUG)
        return updated

    def update_bugcheck(self, bugcheck_id, skip_json=False, custom_dir=None):
        '''Downloads and saves a bugcheck'''
        retval = True
        base_address = '/'.join(self.metadata_address.split('/')[:-1])
        if bugcheck_id in self.available:
            if '/' in bugcheck_id:
                skip_json = True
                custom_dir = bugcheck_id.split('/')[0]
                bugcheck_id = bugcheck_id.split('/')[1]
            if skip_json:
                bugcheck_files = [bugcheck_id + '.py']
            else:
                bugcheck_files = [bugcheck_id + '.py', bugcheck_id + '.json']
            for file in bugcheck_files:
                if not custom_dir:
                    local_file = self.bugcheck_dir + '/' + file
                else:
                    local_file = custom_dir + '/' + file
                self.debug('Updating %s... '%file, code.LOG_INFO, eol=False)
                get = requests.get(url=base_address + '/' + file, timeout=5, allow_redirects=True)
                if get.status_code == '200':
                    content = get.content
                    with open(local_file, 'wb') as ufile:
                        ufile.write(content)
                    self.debug('Done', code.LOG_INFO, raw_message=True)
                else:
                    self.debug('Error: %s' %get.status_code, code.LOG_INFO, raw_message=True)
        else:
            self.debug("Unable to update bugcheck %s" %bugcheck_id, code.LOG_WARNING)
            retval = False
        obsoleted = self.check_obsolete(bugcheck_id)
        if obsoleted:
            self.debug("%s has been obsoleted by %s" %(','.join(obsoleted), bugcheck_id), code.LOG_INFO)
        return retval
