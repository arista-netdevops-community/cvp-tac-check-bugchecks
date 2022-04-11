from bugchecks.bug import Bug
import lib.return_codes as code

class cert_permissions(Bug):
  def __init__(self):
    super(cert_permissions, self).__init__()

    self.__init_file_permissions()

  def __init_file_permissions(self):
    expected_file_owner = 'cvp'
    expected_file_group = 'cvp'

    self.cert_directory = '/cvpi/tls/certs'

    self.file = {}
    self.file['aerisadmin.crt'] = {}
    self.file['aerisadmin.crt']['mode'] = '-rw--w----'
    self.file['aerisadmin.crt']['owner'] = expected_file_owner
    self.file['aerisadmin.crt']['group'] = expected_file_group

    self.file['aerisadmin.csr'] = {}
    self.file['aerisadmin.csr']['mode'] = '-rw-rw-r--'
    self.file['aerisadmin.csr']['owner'] = expected_file_owner
    self.file['aerisadmin.csr']['group'] = expected_file_group

    self.file['aerisadmin.key'] = {}
    self.file['aerisadmin.key']['mode'] = '-rw-rw-r--'
    self.file['aerisadmin.key']['owner'] = expected_file_owner
    self.file['aerisadmin.key']['group'] = expected_file_group

    self.file['aerisadmin.pks8'] = {}
    self.file['aerisadmin.pks8']['mode'] = '-rw-rw-r--'
    self.file['aerisadmin.pks8']['owner'] = expected_file_owner
    self.file['aerisadmin.pks8']['group'] = expected_file_group

    self.file['amb-openssl.cnf'] = {}
    self.file['amb-openssl.cnf']['mode'] = '-rw-r--r--'
    self.file['amb-openssl.cnf']['owner'] = expected_file_owner
    self.file['amb-openssl.cnf']['group'] = expected_file_group

    self.file['ambassador.crt'] = {}
    self.file['ambassador.crt']['mode'] = '-rw-r--r--'
    self.file['ambassador.crt']['owner'] = expected_file_owner
    self.file['ambassador.crt']['group'] = expected_file_group

    self.file['ambassador.key'] = {}
    self.file['ambassador.key']['mode'] = '-rw-r--r--'
    self.file['ambassador.key']['owner'] = expected_file_owner
    self.file['ambassador.key']['group'] = expected_file_group

    self.file['ca.crt'] = {}
    self.file['ca.crt']['mode'] = '-rw-------'
    self.file['ca.crt']['owner'] = expected_file_owner
    self.file['ca.crt']['group'] = expected_file_group

    self.file['ca.key'] = {}
    self.file['ca.key']['mode'] = '-rw-------'
    self.file['ca.key']['owner'] = expected_file_owner
    self.file['ca.key']['group'] = expected_file_group

    self.file['kube-cert.pem'] = {}
    self.file['kube-cert.pem']['mode'] = '-rw-rw-rw-'
    self.file['kube-cert.pem']['owner'] = expected_file_owner
    self.file['kube-cert.pem']['group'] = expected_file_group

    self.file['kube-openssl.cnf'] = {}
    self.file['kube-openssl.cnf']['mode'] = '-rw-r--r--'
    self.file['kube-openssl.cnf']['owner'] = expected_file_owner
    self.file['kube-openssl.cnf']['group'] = expected_file_group

    self.file['saml.crt'] = {}
    self.file['saml.crt']['mode'] = '-rw-------'
    self.file['saml.crt']['owner'] = expected_file_owner
    self.file['saml.crt']['group'] = expected_file_group

    self.file['saml.key'] = {}
    self.file['saml.key']['mode'] = '-rw-------'
    self.file['saml.key']['owner'] = expected_file_owner
    self.file['saml.key']['group'] = expected_file_group

    self.file['server.crt'] = {}
    self.file['server.crt']['mode'] = '-rw-------'
    self.file['server.crt']['owner'] = expected_file_owner
    self.file['server.crt']['group'] = expected_file_group

    self.file['server.key'] = {}
    self.file['server.key']['mode'] = '-rw-------'
    self.file['server.key']['owner'] = expected_file_owner
    self.file['server.key']['group'] = expected_file_group

  def __convert_mode(self, modestring):
    mode = 0
    if 'x' in modestring:
      mode = mode+1
    if 'w' in modestring:
      mode = mode+2
    if 'r' in modestring:
      mode = mode+4

    self.debug("%s: %s" %(modestring, str(mode)), code.LOG_JEDI)
    return(str(mode))

  def __get_numerical_mode(self, modestring):
    user = modestring[1]+modestring[2]+modestring[3]
    group = modestring[4]+modestring[5]+modestring[6]
    other = modestring[7]+modestring[8]+modestring[9]

    user = self.__convert_mode(user)
    group = self.__convert_mode(group)
    other = self.__convert_mode(other)

    mode = str(user + group + other)
    self.debug("%s: %s" %(modestring, mode), code.LOG_JEDI)
    return(mode)

  def __scan_logs(self):
    self.debug("Checking cert file permissions and ownership from debug logs is not supported", code.LOG_DEBUG)
    return([code.UNSUPPORTED, None])

  def __scan_node(self):
    status = code.OK
    bad_files = []

    file_list = []
    for filename in self.file:
      file_list.append(self.cert_directory + '/' + filename)
    
    certificate_files = self.run_command('ls -l %s' %' '.join(file_list)).stdout
    for file in certificate_files:
      file_mode = str(file.split()[0].split('.')[0])
      file_owner= str(file.split()[2])
      file_group= str(file.split()[3])
      file_path = str(file.split()[8])
      file_name = str(file_path.split('/')[-1])
      if self.file.get(file_name):
        if file_owner != self.file[file_name]['owner'] or file_group != self.file[file_name]['group'] or file_mode != self.file[file_name]['mode']:
          self.debug("Wrong ownership or mode in file: %s" %file_name, code.LOG_DEBUG)
          self.debug("Owner (actual/expected): %s/%s" %(file_owner,self.file[file_name]['owner']), code.LOG_JEDI)
          self.debug("Group (actual/expected): %s/%s" %(file_group,self.file[file_name]['group']), code.LOG_JEDI)
          self.debug("Mode (actual/expected): %s/%s" %(file_mode,self.file[file_name]['mode']), code.LOG_JEDI)
          status = code.ERROR
          bad_files.append(file_path)

    return([status, bad_files])

  def scan(self, return_files=False):
    status = code.OK
    message = None
    files_with_wrong_permissions = []

    if self.is_using_local_logs():
      self.debug("Scanning debug logs", code.LOG_DEBUG)
      status, files_with_wrong_permissions = self.__scan_logs()
    else:
      self.debug("Performing live scan", code.LOG_DEBUG)
      status, files_with_wrong_permissions = self.__scan_node()

    if status != code.OK:
      if status == code.UNSUPPORTED:
        message = "Scanning not supported in this mode"
      else:
        message = "Files with wrong permissions/ownership: %s" % str(files_with_wrong_permissions)

    self.set_status(status, message, files_with_wrong_permissions)

    if return_files:
      return([status, files_with_wrong_permissions])
    else:
      return(status)

  def patch(self):
    value = None
    message = None

    status, files_with_wrong_permissions = self.scan(return_files=True)
    for file in files_with_wrong_permissions:
      file_name = file.split('/')[-1]
      expected_owner = self.file[file_name]['owner']
      expected_group = self.file[file_name]['group']
      expected_mode = self.__get_numerical_mode(self.file[file_name]['mode'])

      try:
        self.debug('Fixing %s ownership: %s:%s' %(file, expected_owner, expected_group), code.LOG_DEBUG)
        result = self.run_command('chown %s:%s %s' %(expected_owner, expected_group, file))
        if result.exit_code != code.OK:
          value = result.exit_code
          message = result.stderr
        else:
          self.debug('Fixing %s permissions: %s' %(file, expected_mode), code.LOG_DEBUG)
          result = self.run_command('chmod %s %s' %(expected_mode, file))
          value = result.exit_code
          message = result.stderr
      except Exception as e:
        value = code.ERROR
        message = 'Error setting %s ownership and permissions: %s' % (file, e)

    return(value, message)