import base64
import getpass
import json
import re
import os
import socket
import subprocess
import tempfile
import time
from OpenSSL import crypto
from warnings import warn
from datetime import timedelta, datetime
from timeit import default_timer as timer

import yaml
import lib.return_codes as code
from lib.debugger import Debugger

class Bug(object):
  """ Base class used to represent a bugcheck. It contains several helper methods
  intended to make writing bugchecks and interacting with the logs or
  cluster nodes easy.

  The object has a bug_version number intended to help keeping track of major
  changes in its methods and avoid breaking bugchecks. The scheme is
  "major_version.minor_version.patch_version" and changes in them mean:
      major_version: changes to existing method calls or returns have changed.
      minor_version: new methods have been added but no breaking changes from
          previous versions were made.
      patch_version: there were internal changes in existing methods but no
          changes in their return values. This is aimed and improvements and
          bug fixes.
  """
  def __init__(self):
    """ Initializes the class, creating a minimal empty configuration.
    """
    self.config = {}
    self.status = {}
    self.configure(
      bootstrap = True,
      connection = None,
      debugcmddir = None,
      debuglogdir = None,
      description = None,
      logsfrom = None,
      name = None,
      timeout = None
    )

    self.set_status(
      value=code.OK,
      message=None,
      has_run=False
    )

  def certificates(self):
    retval = self.__certificates(self)
    return(retval)

  class __certificates:
    """This class encapsulates certificate operations"""
    class certificate:
      def __init__(self, cert, type='file'):
        if type == 'file':
          with open(cert) as file:
            self.contents = file.read()
        elif type == 'contents':
          self.contents = cert

        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, self.contents)
        date_format, encoding = "%Y%m%d%H%M%SZ", "ascii"

        self.start_date = datetime.strptime(certificate.get_notBefore().decode(encoding), date_format)
        self.end_date = datetime.strptime(certificate.get_notAfter().decode(encoding), date_format)
        self.fingerprint = certificate.digest('sha1')
        self.certificate = certificate

      def verify(self, ca_cert):
        try:
          store = crypto.X509Store()
          store.add_cert(ca_cert.certificate)
          store_ctx = crypto.X509StoreContext(store, self.certificate)
          result = store_ctx.verify_certificate()
        except AttributeError:
          with tempfile.NamedTemporaryFile(delete=False) as ca_file:
            with tempfile.NamedTemporaryFile(delete=False) as cert_file:
              ca_file.write(ca_cert.contents)
              cert_file.write(self.contents)
          try:
            subprocess.check_output(['openssl verify -CAfile %s %s' %(ca_file.name, cert_file.name)], shell=True)
            result = True
          except subprocess.CalledProcessError:
            result = False
          finally:
            os.system('rm -f %s %s' %(ca_file.name, cert_file.name))
        if result:
          return True
        else:
          return False

    def __init__(self, parent):
        self.certificates = {}
        self.parent = parent
        self.__read_certs()

    def __read_certs(self):
      cert_dir = '/cvpi/tls/certs/'
      filesystem_certs = [ f for f in os.listdir(cert_dir) if f.endswith('.crt') or f.endswith('.cert') or f.endswith('.pem')]
      k8s_tlscerts = self.parent.run_command('kubectl get secrets --field-selector type="kubernetes.io/tls" -oname|cut -f2- -d/').stdout
      k8s_opaquecerts = self.parent.run_command('kubectl get secrets --field-selector type="Opaque" -oname|cut -f2- -d/').stdout

      for file in filesystem_certs:
        if not self.certificates.get(file):
          self.certificates[file] = {}
        try:
          self.certificates[file]['filesystem'] = self.certificate(cert_dir + file)
        except Exception as error_message:
          self.parent.debug("Could not load certificate from file %s: %s" %(cert_dir + file, error_message), code.LOG_WARNING)

      for file in k8s_tlscerts:
        if file == 'ambassador-tls-origin':
          certname = 'ambassador.crt'
        else:
          certname = file
        if not self.certificates.get(certname):
          self.certificates[certname] = {}
        file_contents = '\n'.join(self.parent.run_command("kubectl get secret %s -o 'go-template={{ index .data \"tls.crt\"}}'|base64 -d" %file).stdout).strip()
        try:
          self.certificates[certname]['k8s'] = self.certificate(file_contents, type='contents')
        except Exception as error_message:
          self.parent.debug("Could not load certificate %s from secret %s: %s" %(certname, file, error_message), code.LOG_WARNING)
      for file in k8s_opaquecerts:
        file_contents = '\n'.join(self.parent.run_command("kubectl get secret %s -o yaml" %file).stdout)
        file_contents = yaml.safe_load(file_contents)
        for certname in [k for k in file_contents['data'].keys() if k.endswith('.crt') or k.endswith('.cert') or k.endswith('.pem')]:
          if not self.certificates.get(certname):
            self.certificates[certname] = {}
          try:
            file_contents = base64.b64decode(file_contents['data'][certname])
          except Exception as error_message:
            self.parent.debug("Could not decode %s from secret %s: %s" %(certname, file, error_message), code.LOG_WARNING)
          else:
            try:
              self.certificates[certname]['k8s'] = self.certificate(file_contents, type='contents')
            except Exception as error_message:
              self.parent.debug("Could not load certificate %s from secret %s: %s" %(certname, file, error_message), code.LOG_WARNING)

    def get(self, certname, source=None):
      cert = self.certificates.get(certname)
      if cert and not source:
        cert = self.certificates[certname].get('k8s')
        if not cert:
          cert = self.certificates[certname].get('filesystem')
      elif cert and source:
        cert = self.certificates[certname].get(source)
      return cert

    def list(self):
      certs = list(self.certificates.keys())
      return certs

    def sources(self, cert):
      retval = self.certificates.get(cert)
      if retval:
        retval = retval.keys()
      return retval

    def is_close_to_expiration(self, cert_name, source='filesystem', days=30):
      retval = True
      if self.certificates.get(cert_name):
        if self.certificates[cert_name].get(source):
          threshold = self.certificates[cert_name][source].end_date - timedelta(days=days)
          if datetime.now() < threshold:
            retval = False
      else:
        raise(RuntimeError('Certificate %s not found' %cert_name))
      return retval

    def cert_is_expired(self, cert_name, source='filesystem'):
      retval = True
      if self.certificates.get(cert_name):
        if self.certificates[cert_name].get(source):
          if datetime.now() < self.certificates[cert_name][source].end_date:
            retval = False
      else:
        raise(RuntimeError('Certificate %s not found' %cert_name))
      self.parent.debug("%s (%s) is expired: %s" %(cert_name, source, retval), code.LOG_JEDI)
      return retval

    def cert_starts_in_future(self, cert_name, source='filesystem'):
      retval = True
      if self.certificates.get(cert_name):
        if self.certificates[cert_name].get(source):
          if datetime.now() > self.certificates[cert_name][source].start_date:
            retval = False
      else:
        raise(RuntimeError('Certificate %s not found' %cert_name))
      self.parent.debug("%s (%s) starts in future: %s" %(cert_name, source, retval), code.LOG_JEDI)
      return retval

    def cert_chain_is_valid(self, cert_name, source='filesystem'):
      retval = True
      if self.certificates.get('ca.crt') and self.certificates.get(cert_name):
        retval = self.certificates[cert_name][source].verify(self.get('ca.crt'))
      else:
        raise(RuntimeError('Certificate %s or ca.crt not found' %cert_name))
      self.parent.debug("%s (%s) chain is valid: %s" %(cert_name, source, retval), code.LOG_JEDI)
      return retval

    def certs_are_similar(self, cert_a_name, cert_b_name, cert_a_source='filesystem', cert_b_source='filesystem'):
      retval = False
      if self.certificates.get(cert_a_name) and self.certificates.get(cert_b_name):
        if self.certificates[cert_a_name].get(cert_a_source) and self.certificates[cert_b_name].get(cert_b_source):
          if self.certificates[cert_a_name][cert_a_source].fingerprint == self.certificates[cert_b_name][cert_b_source].fingerprint:
            retval = True
      else:
        raise(RuntimeError('Certificate %s or %s not found' %(cert_a_name, cert_b_name)))
      self.parent.debug("%s (%s) is similar to %s (%s): %s" %(cert_a_name, cert_a_source, cert_b_name, cert_b_source, retval), code.LOG_JEDI)
      return retval

    def is_valid(self, certname, validate_chain=True, validate_startdate=True, validate_expiration=True, validate_sources=True):
      class result:
        def __init__(self):
            self.result = True
            self.failed = []
      
      retval = result()
      for source in self.sources(certname):
        if validate_expiration:
          if self.cert_is_expired(certname, source):
            retval.result = False
            retval.failed.append('expiration date (%s)' %source)
          elif self.is_close_to_expiration(certname, source):
            retval.result = False
            retval.failed.append('close to expiration (%s)' %source)
        if validate_startdate and self.cert_starts_in_future(certname, source):
          retval.result = False
          retval.failed.append('start date (%s)' %source)
        if validate_chain and not self.cert_chain_is_valid(certname, source):
          retval.result = False
          retval.failed.append('invalid chain (%s)' %source)
      if validate_sources and len(self.sources(certname)) == 2:
        if not self.certs_are_similar(cert_a_name=certname, cert_a_source='filesystem', cert_b_name=certname, cert_b_source='k8s'):
          retval.result = False
          retval.failed.append('k8s secret and cert file contents are different')
      self.parent.debug("%s validation result: %s" %(certname, retval.result), code.LOG_DEBUG)
      return retval

  def __filter_logs(self, lines, filename=None):
    #Filter lines according to timestamps and returns a list of lines that match the criteria.
    #FIXME: This function is very slow
    output = []
    linedate = None
    logsfrom = self.config['logsfrom']
    syslog_date = re.compile(r'(\d{4})-(\d{2})-(\d{2})')
    syslog_hour = re.compile(r'(\d{2}):(\d{2}):(\d{2})')
    journal_date = re.compile(r'^(jan|feb|mar|apr|may|jun|jul|ago|sep|oct|nov|dec) \d{2}', re.IGNORECASE)
    journal_hour = syslog_hour
    go_date = re.compile(r'^[A-Z](\d{4})')
    go_hour = syslog_hour
    starttime = time.time()

    if not filename:
      filename='logs'

    if logsfrom:
      self.debug("Filtering %s by date: %s " %(filename, str(time.ctime(logsfrom))), code.LOG_INFO)
      previous_elapsed = 0
      for line in lines:
        elapsed = int(time.time()-starttime)
        if elapsed % 10 == 0 and elapsed != previous_elapsed:
          self.debug("Still working (%ss elapsed)" %elapsed, code.LOG_INFO)
          previous_elapsed = elapsed
        fields = line.split()
        if fields:
          try:
            if syslog_date.match(fields[0]) and syslog_hour.match(fields[1]):
              # Syslog format (^2020-08-20 18:58:27)
              self.debug('Syslog-style date in line: ' + line, code.LOG_JEDIMASTER)
              linedate=time.strptime(fields[0] + " " + fields[1].split(',')[0], "%Y-%m-%d %H:%M:%S")
              linedate=time.mktime(linedate)
            elif journal_date.match(fields[0] + " " + fields[1]) and journal_hour.match(fields[2]):
              # Journalctl format: (^Jul 24 11:35:19.017949)
              self.debug('Journalctl-style date in line: ' + line, code.LOG_JEDIMASTER)
              # Assume the date is from the current year
              year = time.ctime().split()[4]
              linedate=time.strptime(year + "-" + fields[0] + "-" + fields[1] + " " + fields[2].split('.')[0], "%Y-%b-%d %H:%M:%S")
              linedate=time.mktime(linedate)
            elif go_date.match(fields[0]) and go_hour.match(fields[1]):
              # GO format: (^E0820 18:58:27.964890)
              self.debug('GO-style date in line: ' + line, code.LOG_JEDIMASTER)
              # Assume the date is from the current year
              year = time.ctime().split()[4]
              month = fields[0][1]+fields[0][2]
              day = fields[0][3]+fields[0][4]
              linedate=time.strptime(year + "-" + month + "-" + day + " " + fields[1].split('.')[0], "%Y-%m-%d %H:%M:%S")
              linedate = time.mktime(linedate)
            else:
              # Append lines anyway if date couldn't be read and previous date was already in range
              if linedate:
                if linedate >= logsfrom:
                  self.debug("Assuming previous date %s on line: %s" %(time.ctime(linedate),line), code.LOG_JEDI)
                  output.append(line)
              else:
                self.debug("Unknown time format in line: %s" %line, code.LOG_JEDIMASTER)
          except IndexError:
            self.debug("Unknown time format in line: %s" %line, code.LOG_JEDIMASTER)
            if linedate:
              if linedate >= logsfrom:
                self.debug("Assuming previous date %s on line: %s" %(time.ctime(linedate),line), code.LOG_JEDI)
                output.append(line)
          if linedate:
            if linedate >= logsfrom:
              output.append(line)
            else:
              self.debug("Skipping line due to date filters: " + line, code.LOG_JEDIMASTER)
              pass
    else:
      self.debug("Bypassing date filtering", code.LOG_DEBUG)
      output = lines

    elapsed = int(time.time()-starttime)
    self.debug("Filtering %s took %s seconds" %(filename, elapsed), code.LOG_DEBUG)
    return(output)

  def __filter_k8s_elements(self, elements, filter):
    # Filters elements obtained using the __read_k8s_describe method. Currently filtering is only implemented for pods.
    resources = {}
    for element in elements:
      if elements[element]['type'] == 'pod' or elements[element]['type'] == 'pods':
        if elements[element].get('Init Containers'):
          for container in elements[element].get('Init Containers'):
            try:
              if (elements[element]['Init Containers'][container]['State']['value'] != 'Running' and elements[element]['Init Containers'][container]['State']['Reason'] == filter) or elements[element]['Init Containers'][container]['State']['value'] == filter or elements[element]['Status'] == filter:
                resources[container] = elements[element]
            except KeyError as error_message:
              raise RuntimeError("Error reading %s attributes: %s" %(container, error_message))
        for container in elements[element].get('Containers'):
          try:
            if (elements[element]['Containers'][container]['State']['value'] != 'Running' and elements[element]['Containers'][container]['State']['Reason'] == filter) or elements[element]['Containers'][container]['State']['value'] == filter or elements[element]['Status'] == filter:
              resources[container] = elements[element]
          except KeyError as error_message:
            raise RuntimeError("Error reading %s attributes: %s" %(container, error_message))

    self.debug(resources, code.LOG_JEDI)
    return(resources)

  def __read_k8s_element_from_describe_line(self,line):
    # Parses a line from the kubectl describe output
    element = line.split(":")[0].strip()
    try:
      value = ' '.join(line.split(":")[1:]).strip()
    except TypeError:
      value = None
    return(element, value)

  def __read_k8s_describe(self, kubectl_describe_contents, describe_type):
    # Reads a kubectl describe output and return the contents in a dictionary
    elements = {}
    for line in kubectl_describe_contents:
      if line.startswith('Name:'):
        name = line.split()[1]
        elements[name] = {}
        elements[name]['type'] = describe_type
      if re.match('^[a-zA-Z]+.*:', line):
        one, value = self.__read_k8s_element_from_describe_line(line)
        if value:
          elements[name][one] = value
        else:
          elements[name][one] = {}
      else:
        if re.match('^  [a-zA-Z]+.*:', line):
          two, value = self.__read_k8s_element_from_describe_line(line)
          if value:
            if type(elements[name][one]) is dict:
              elements[name][one][two] = value
            else:
              old_value = elements[name][one]
              elements[name][one] = {}
              elements[name][one]['value'] = old_value
              elements[name][one][two] = value
          else:
            elements[name][one][two] = {}
        if re.match('^    [a-zA-Z]+.*:', line):
          three, value = self.__read_k8s_element_from_describe_line(line)
          if value:
            if type(elements[name][one][two]) is dict:
              elements[name][one][two][three] = value
            else:
              old_value = elements[name][one][two]
              elements[name][one][two] = {}
              elements[name][one][two]['value'] = old_value
              elements[name][one][two][three] = value
          else:
            elements[name][one][two][three] = {}
        if re.match('^      [a-zA-Z]+.*:', line):
          four, value = self.__read_k8s_element_from_describe_line(line)
          if value:
            if type(elements[name][one][two][three]) is dict:
              elements[name][one][two][three][four] = value
            else:
              old_value = elements[name][one][two][three]
              elements[name][one][two][three] = {}
              elements[name][one][two][three]['value'] = old_value
              elements[name][one][two][three][four] = value
          else:
            elements[name][one][two][three][four] = {}
        if re.match('^        [a-zA-Z]+.*:', line):
          five, value = self.__read_k8s_element_from_describe_line(line)
          if value:
            if type(elements[name][one][two][three][four]) is dict:
              elements[name][one][two][three][four][five] = value
            else:
              old_value = elements[name][one][two][three][four]
              elements[name][one][two][three][four] = {}
              elements[name][one][two][three][four]['value'] = old_value
              elements[name][one][two][three][four][five] = value
          else:
            elements[name][one][two][three][four][five] = {}
        if re.match('^          [a-zA-Z]+.*:', line):
          six, value = self.__read_k8s_element_from_describe_line(line)
          if value:
            if type(elements[name][one][two][three][four][five]) is dict:
              elements[name][one][two][three][four][five][six] = value
            else:
              old_value = elements[name][one][two][three][four][five]
              elements[name][one][two][three][four][five] = {}
              elements[name][one][two][three][four][five]['value'] = old_value
              elements[name][one][two][three][four][five][six] = value
          else:
            self.debug("Not recursing any further", code.LOG_WARNING)
    return(elements)

  def __compat_run(self, *popenargs, **kwargs):
    # Wrapper around subprocess for python2.7/3 compatibility
    input = kwargs.pop("input", None)
    check = kwargs.pop("handle", False)

    if input is not None:
      if 'stdin' in kwargs:
        raise ValueError('stdin and input arguments may not both be used.')
      kwargs['stdin'] = subprocess.PIPE

    process = subprocess.Popen(*popenargs, **kwargs)
    try:
      stdout, stderr = process.communicate(input)
    except:
      process.kill()
      process.wait()
      raise
    retcode = process.poll()
    if check and retcode:
      raise subprocess.CalledProcessError(
        retcode, process.args, output=stdout, stderr=stderr)
    return retcode, stdout, stderr

  def __run_local_command(self, command):
    #Runs a command on the current host and returns the stdout and stderr
    self.debug("Running local command %s" %command, code.LOG_JEDI)
    stdout = None
    stderr = None
    try:
      output = subprocess.run(command, shell=True, capture_output=True)
      stdout = output.stdout.splitlines()
      stderr = output.stderr.splitlines()
      exit_code = output.returncode
    except AttributeError:
      self.debug("Falling back to compatibility mode", code.LOG_DEBUG)
      output = self.__compat_run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      stdout = output[1].splitlines()
      stderr = output[2].splitlines()
      exit_code = output[0]
      self.debug("stdout: %s" %stdout, code.LOG_JEDIMASTER)
      self.debug("stderr: %s" %stdout, code.LOG_JEDIMASTER)

    return([stdout, stderr, exit_code])

  def __run_remote_command(self, command, connection=None, timeout=None):
    #Runs a command over a SSH connection and returns the stdout and stderr
    if self.config.get('timeout') and not timeout:
      command = 'timeout %s %s' %(self.config['timeout'], command)
      timeout = self.config.get('timeout')
    elif timeout == 'inf':
      timeout = None
    elif timeout:
      command = 'timeout %s %s' %(timeout, command)

    self.debug("Running remote command %s" %command, code.LOG_JEDI)
    if connection:
      try:
        stdin, stdout, stderr = connection.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
      except Exception as e:
        self.debug("Could not run %s: %s" %(command, e), code.LOG_ERROR)
        return([None, None, None])

      try:
        stdout = stdout.read().decode().strip().splitlines()
      except UnicodeDecodeError:
        self.debug("Invalid stdout while running %s: %s" %(command, stdout), code.LOG_WARNING)
        stdout = []

      try:
        stderr = stderr.read().decode().strip().splitlines()
      except UnicodeDecodeError:
        self.debug("Invalid stderr while running %s: %s" %(command, stdout), code.LOG_WARNING)
        stderr = []

    else:
      self.debug("No connection available to run %s" %(command), code.LOG_ERROR)
      return([None, None, None])

    return([stdout,stderr,exit_code])

  def apish(self, method, dataset, path, action, key, ts=None):
    """ Fetches or alters entries in hbase.

    This is able to modify internal CVP values and break functionality, so
    use with caution!!

    Args:
        method (str): The method to be used to interact with the database. The values are the following:
            - get : issue a GET request to fetch a specific state from a path of a dataset
            - publish : put/update/delete data from path
        dataset (str): Represents the unique identifier of an object. The values are the following:
            - analytics : the dataset where turbines write versioned and aggregated switch data
            - cvp : the dataset where the provisioning apps write states, such as configlets, containers, mappers, etc.
            - {SN} : each switch has its own dataset, which is the serial number of the device
        path (str): Path to query given as a linux-style path and treated as relative to the current
            location unless preceded with a forward slash.
            If any of the components is not a string or if it is a string containing forward
            slashes, the path should be provided in json format:
            e.g. '["foo", {"int": 1}]'
        action (str): The action to be chosen for the publish method. The values are the following:
            - delete : Key to delete (multiple flags allowed).
                      Keys are mainly specified in its json representation, though non-json input is
                      treated as a string key for backwards compatibility.
                      Examples:
                        '"some string"' # json string targeting key 'some string'
                        "some string"   # non-json input targeting key 'some string'
                        '{"foo":"bar"}' # json object targetting a complex key
            - update : Notification update to publish (multiple flags allowed).
                      Provide in json format (e.g. '{"key": "foo", "value": {"int": 2}}') (default {})
        key (str): Specific key to select (multiple flags allowed).
            Keys are mainly specified in its json representation, though non-json input is
            treated as a string key for backwards compatibility.
            Examples:
              '"some string"' # json string targeting key 'some string'
              "some string"   # non-json input targeting key 'some string'
              '{"foo":"bar"}' # json object targetting a complex key
        ts (str): Timestamp. Default value is current time for publish command. Valid formats are:
            - RFC3339: 2006-01-02T15:04:05.999999999Z
            - Nanoseconds: 1136214245999999999
    """
    if ts is None and key is None and method == 'get':
      command = "/cvpi/tools/apish %s -d %s -p %s" %(method, dataset, path)
    elif ts is None and key is not None and method == 'get':
      command = "/cvpi/tools/apish %s -d %s -p %s --key %s" %(method, dataset, path, key)
    elif ts is not None and method == 'publish':
      command = "/cvpi/tools/apish %s -d %s -p %s --%s %s -t %s" %(method, dataset, path, action, key, ts)
    elif ts is None and method == 'publish':
      command = "/cvpi/tools/apish %s -d %s -p %s --%s %s" %(method, dataset, path, action, key)

    result = self.run_command(command)

    if result.stderr:
      self.debug("Command %s returned errors: %s" %(command, result.stderr), code.LOG_DEBUG)

    self.debug(result.stdout, code.LOG_JEDI)

    return(result.stdout)

  def configure(
    self,
    filecache=None,
    bootstrap=False,
    cluster_store=None,
    connection=None,
    debug_level=None,
    debugcmddir=None,
    debuglogdir=None,
    description=None,
    logsfrom=None,
    log_to_file=False,
    metadata_json=None,
    name=None,
    node_config=None,
    read_files_only_from_last_service_restart=None,
    timeout=None
  ):
    """ Set the bug class properties

    Args:
        filecache (FileCache object): File cache
        metadata_json (str): JSON file containing bugcheck metadata
        bootstrap (bool): Whether or not we're doing initial configuration of the module. Setting to True
            will cause version compatibility validation to be skipped.
        connection (paramiko.client.SSHClient object): SSH connection to use when running remote commands
        debug_level (int): Debugging messages level
        debugcmddir (str): Path to the cvpi_commands directory extracted from cvpi_debug_all file
        debuglogdir (str): Path to the cvpi_logs directory extracted from the cvpi_debug_all file
        description (str): Bugcheck description. Will be overwritten by metadata if one is provided
        logsfrom (int): Unix timestamp of the starting date to use when filtering log files
        name (str): Name of the bugcheck. Will be overwritten by metadata if one is provided
        node_config (dict): Dictionary containing the node's configuration
        read_files_only_from_last_service_restart (bool): Only return file contents generated after the last
            service restart if possible. Default: False
    """
    file = None
    metadata = {}
    # Basic metadata support
    if name:
      self.config['name'] = name
    elif not self.config.get('name'):
      self.config['name'] = None
    if description:
      self.config['description'] = description
    elif not self.config.get('description'):
      self.config['description'] = None

    if read_files_only_from_last_service_restart != None:
      self.config['read_files_only_from_last_service_restart'] = read_files_only_from_last_service_restart
    elif not self.config.get('read_files_only_from_last_service_restart'):
      self.config['read_files_only_from_last_service_restart'] = False
    
    bug_json = os.path.dirname(os.path.realpath(__file__)) + '/bug.json'
    file = open(bug_json, 'r')
    metadata = json.load(file)
    self.bug_version = metadata['version']
    if timeout or not self.config.get('timeout'):
      self.config['timeout'] = timeout

    # Extended metadata
    if metadata_json:
      self.debug("Loading metadata from JSON file: %s" %metadata_json, code.LOG_DEBUG)
      file = open(metadata_json, 'r')
      metadata = json.load(file)
      self.debug("%s" %metadata, code.LOG_JEDI)
      for key in metadata:
        self.config[key] = metadata[key]

    # Compatibility check
    if not bootstrap:
      if self.config.get('bug_engine_version'):
        version_requirement = self.config['bug_engine_version'].split('.')
        current_version = self.bug_version.split('.')
        if int(version_requirement[0]) != int(current_version[0]):
          raise(RuntimeError('This bugcheck requires Bug %s.x.x (currently using %s)' %(version_requirement[0], self.bug_version)))
        elif int(version_requirement[1]) > int(current_version[1]):
          raise(RuntimeError('This bugcheck requires Bug %s.%s.x (currently using %s)' %(version_requirement[0], version_requirement[1], self.bug_version)))
      else:
        raise(RuntimeError("No bug_engine_version declared. Refusing to load."))

    # Connection to remote nodes
    if connection:
      self.config['connection'] = connection
    elif not self.config.get('connection'):
      self.config['connection'] = None

    if cluster_store is not None:
      self.cluster_store = cluster_store

    if filecache:
        self.filecache=filecache

    # Directories used when reading logs
    if debugcmddir:
      self.config['debugcmddir'] = debugcmddir
    elif not self.config.get('debugcmddir'):
      self.config['debugcmddir'] = None
    if debuglogdir:
      self.config['debuglogdir'] = debuglogdir
    elif not self.config.get('debuglogdir'):
      self.config['debuglogdir'] = None

    # Log filtering configuration
    if logsfrom:
      self.config['logsfrom'] = logsfrom
    elif not self.config.get('logsfrom'):
      self.config['logsfrom'] = None

    # Node configuration
    if node_config:
      self.config['node_config'] = node_config
    elif not self.config.get('node_config'):
      self.config['node_config'] = {}

    # Logging level settings
    if not self.config.get('debug'):
      self.config['debug'] = {}
    if debug_level:
      self.config['debug']['level'] = debug_level
    elif not self.config['debug'].get('level'):
      self.config['debug']['level'] = code.LOG_ERROR
    
    if log_to_file and self.get_node_name():
      self.config['logfile'] = '.logs/' + self.get_node_name() + '-' + self.__class__.__name__ + ".log"
    elif not self.config.get('logfile'):
      self.config['logfile'] = None

    try:
      self.debug = Debugger(id=self.get_node_name(), level=self.config['debug']['level'], name='bugcheck', target=self.config['name'], logfile=self.config['logfile'])
      self.debug = self.debug.debug
      self.debug("%s: configured (bug version: %s)" % (self.get_node_name(),self.bug_version), code.LOG_DEBUG)
    except Exception as e:
      print("Error configuring logging: %s" %e)
      raise

    self.debug("%s: %s" % (self.config['name'], str(self.config)), code.LOG_JEDI)

  def cvp_is(self, compare, version):
    """ Compare if a provided version is newer, newer or equal, older, older or equal than or equal to the node's CVP version.

    Args:
        compare (str): Comparision operator. Valid operators are:
            >: Newer (higher) than
            >=: Newer (higher) or equal than
            <: Older (lower) than
            <=: Older (lower) or equal than
            ==: Equal than
        version (str): CVP version to compare the one running on the node to.

    Raises:
        SyntaxError: Invalid comparison operator

    Returns:
        bool: Indicates whether the currently running version on the cluster/log files being analyzed
            matches the requested operator and version.
    """
    result = False
    try:
      version_major = int(version.split('.')[0])
      version_minor = int(version.split('.')[1])
      version_patch = int(version.split('.')[2])
    except Exception as e:
      self.debug("Couldn't resolve CVP version %s: %s" % (version, e), code.LOG_ERROR)
      raise

    current_version = self.cvp_version().split('-')[0]
    try:
      current_version_major = int(current_version.split('.')[0])
      current_version_minor = int(current_version.split('.')[1])
      current_version_patch = int(current_version.split('.')[2])
    except Exception as e:
      self.debug("Unknown CVP version %s: %s" % (current_version, e), code.LOG_ERROR)
      raise

    if compare == 'newer' or compare == '>':
      if current_version_major > version_major:
        result = True
      elif current_version_major == version_major:
        if current_version_minor > version_minor:
          result = True
        elif current_version_minor == version_minor:
          if current_version_patch > version_patch:
            result = True
    elif compare == 'newer or equal' or compare == '>=':
      if current_version_major >= version_major:
        if current_version_major > version_major:
          result = True
        elif current_version_major == version_major:
          if current_version_minor >= version_minor:
            if current_version_minor > version_minor:
              result = True
            elif current_version_minor == version_minor:
              if current_version_patch >= version_patch:
                result = True
    elif compare == 'older' or compare == '<':
      if current_version_major < version_major:
        result = True
      elif current_version_major == version_major:
        if current_version_minor < version_minor:
          result = True
        elif current_version_minor == version_minor:
          if current_version_patch < version_patch:
            result = True
    elif compare == 'older or equal' or compare == '<=':
      if current_version_major <= version_major:
        if current_version_major < version_major:
          result = True
        elif current_version_major == version_major:
          if current_version_minor <= version_minor:
            if current_version_minor < version_minor:
              result = True
            elif current_version_minor == version_minor:
              if current_version_patch <= version_patch:
                result = True
    elif compare == 'equal' or compare == '=' or compare == '==':
      if version == current_version:
        result = True
    else:
      raise(SyntaxError("Invalid comparison: %s" % str(compare)))
    self.debug("CVP %s is %s than/to %s: %s" % (current_version, compare, version, str(result)), code.LOG_JEDI)
    return(result)

  def cvp_version(self):
    """ Returns the CVP version running on the current node.

    Returns:
        str: CVP version number running on the current node.
    """
    if self.is_using_local_logs():
      file = self.read_file(self.local_directory(directory_type='logs')+'/env/etc/cvpi/env')
      for line in file:
        if 'CVP_VERSION' in line:
          version = line.split('=')[1].strip()
    else:
      version = self.run_command('su - cvp -c "cvpi version"|grep version|cut -f3 -d" "|cut -f1 -d-', silence_cvpi_warning=True).stdout
      version = version[0]

    self.debug(version, code.LOG_DEBUG)
    return(version)

  def cvpi(self, action, services=['all'], queue=False, allow_failure=False):
    """ Interacts with the cvpi command. Using this is highly encouraged instead
    of directly running cvpi commands with run_command() as additional checks and
    capabilties are implemented.

    Args:
        action (str): cvpi action to execute. Valid values are:
            - init
            - reset
            - restart
            - start
            - status
            - stop
        services (list): Services to execute the action on.
        queue (bool): Do not execute the action immediatelly. Instead queue the action
            for later execution. This is intended to reduce the number of restarts while
            executing bugchecks patches. NOTE: This is not yet implemented.
        allow_failure (bool): Do not display an error message when the command fails.
            Default: False

    Returns:
        results (object): Object containing the results of the performed actions. The object
            has the following variables that can be accessed:
                - results (dict): Contains detailed information about the action execution.
                    Each action in each service has a run_command() output object that can be
                    accessed.
                - failed (list): List of failed actions. Contains tuples of [service, action]
                - successful (list) List of successful actions. Contains tuples of [service, action]
    """
    class action_result(object):
      def __init__(self, results):
        self.results = results
        self.failed = []
        self.successful = []

        for service in result:
          for action in result[service]:
            if result[service][action].exit_code != code.OK:
              self.failed.append([service, action])
            else:
              self.successful.append([service, action])

    result = {}
    failed = []
    allowed_actions = ['init', 'reset', 'restart', 'start', 'status', 'stop']

    if action not in allowed_actions:
      raise(RuntimeError("Action %s is not allowed. Valid actions are: %s" %(action, allowed_actions)))
    elif not isinstance(action, str):
      raise(RuntimeError("Actions must be strings"))
    elif action == 'restart':
      action = ['stop', 'start']
    else:
      action = [action]

    for run in action:
      for service in services:
        result[service] = {}
        self.debug("Preparing command for service %s, action: %s" %(run, service), code.LOG_JEDI)
        command = 'cvpi --prompt=false -v=%s %s %s' %(self.config['debug']['level'], run, service)
        command = 'su - cvp -c "%s"' %command

        if queue:
          self.debug("Queueing not implemented. Executing command immediately.", code.LOG_DEBUG)

        if service == 'all' and run == 'stop':
          self.debug("Stopping all services. Killing cvpiBoot.sh", code.LOG_DEBUG)
          self.run_command("killall -9 cvpiBoot.sh")

        self.debug("Running %s" %command, code.LOG_JEDI)
        result[service][run] = self.run_command(command, silence_cvpi_warning=True, timeout='inf')
        self.debug("%s output: %s" %(command, result[service][run].stdout), code.LOG_JEDI)

    results = action_result(result)    

    if results.failed and not allow_failure:
      self.debug("Errors while executing actions: %s" %results.failed, code.LOG_DEBUG)

    return(results)

  def get_cluster_mode(self):
    """ Returns the mode of the CVP cluster.

    Returns:
        str: Current clustering mode. This can be either "singlenode" or "multinode"
    """
    mode = self.config['node_config']['cluster_mode']
    return(mode)

  def get_info(self):
    """ Returns the bug object configuration

    Returns:
        dict: Internal bugcheck configuration parameters.
    """
    exclude_keys = [
      'connection',
      'debug', 
      'debugcmddir', 
      'debuglogdir', 
      'node_config'
    ]
    r = {}
    r = self.config.copy()
    r['status'] = self.status.copy()

    for key in exclude_keys:
      if r.get(key):
        del r[key]

    self.debug("%s" % str(r), code.LOG_JEDI)
    return(r)

  def get_k8s_resources(self, resource_type, filter=None):
    """ Gets a list of kubernetes resources running on the cluster, as viewed from the current node.

    Args:
        resource_type (str): Type of kubernetes resource to return.
        filter (str): Filter to apply to resources. Currently filtering is only implemented for pods, and will
            look for the keyword in the pod status or state.

    Returns:
    dict: Resources matching the provided type and filter.
        Each element will contain all its attributes present on the kubectl describe
        output.
    """
    resources={}
    if self.is_using_local_logs():
      if resource_type != 'pod' and resource_type != 'pods':
        self.debug("Cannot read k8s type %s from local logs" %resource_type, code.LOG_DEBUG)
        raise(TypeError)
      else:
        elements = self.read_file(self.local_directory(directory_type='commands')+'/kube_pod')
        elements = self.__read_k8s_describe(elements, resource_type)
    else:
      elements = self.run_command("kubectl describe %s" %resource_type).stdout
      if elements:
        elements = self.__read_k8s_describe(elements, resource_type)

    if filter and elements:
      elements = self.__filter_k8s_elements(elements, filter)

    for element in elements:
      resources[element] = elements[element]
      self.debug("%s: %s" %(elements[element]['type'], elements[element]['Name']), code.LOG_JEDI)

    return(resources)

  def get_node_name(self):
    """ Returns the name of the current node.

    Returns:
        str: Node hostname or None if it couldn't be determined.
    """
    if self.config['node_config'].get('host'):
      return(self.config['node_config']['host'])
    else:
      return(None)

  def get_node_role(self):
    """ Returns the role of the current node.

    Returns:
        str: Current node's role in the cluster. Currently this can be 'primary', 'secondary' or 'tertiary'.
    """
    return(self.config['node_config']['role'])

  def get_status(self, section=None):
    self.debug(self.status, code.LOG_JEDI)
    if section:
      return(self.status.get(section))
    else:
      return(self.status)

  def is_current_node(self):
    """ Returns whether or not we're looking at the host we're currently running on.

    Bugchecks MUST NOT rely on this function and if you intend to run commands
    always use the run_command() method instead.

    Returns:
        bool: True if the bugcheck is checking the same node the script is currently
            running on, False otherwise.
    """
    if self.config['node_config'].get('host') == socket.gethostname():
      self.debug("True", code.LOG_JEDI)
      return(True)
    else:
      self.debug("False", code.LOG_JEDI)
      return(False)

  def is_using_local_logs(self):
    """ Returns whether or not we're reading from cvpi_debug_all log files. A True return should
    be interpreted as "reading from logs" and a False as "performing a live check".

    Returns:
        bool: Whether or not the bugcheck is checking cvpi_debug_all logs.
    """
    if self.config.get('node_config').get('debuglogdir') or self.config.get('node_config').get('debugcmddir'):
      self.debug("True", code.LOG_JEDI)
      return(True)
    else:
      self.debug("False", code.LOG_JEDI)
      return(False)

  def local_command_output_directory(self):
    """ When using log files return the local command outputs directory. This should
    be used when reading files from cvpi_debug_all logs, and will refer to the
    current node's cvpi_commands directory. This is deprecated and will be removed
    on Bug 4.0.0.

    Returns:
        str: Path to the current node's cvpi_commands directory. Empty if not reading a
            cvpi_debug_logs bundle.
    """
    warn("Please use self.local_directory(directory_type='commands'); deprecated=2.4.0; removed=4.0.0", DeprecationWarning, stacklevel=2)
    return(self.local_directory('commands'))

  def local_logs_directory(self):
    """ When using log files return the local logs directory. This should be used
    when reading files from cvpi_debug_all logs, and will refer to the current
    node's cvpi_logs directory. This is deprecated and will be removed on Bug 4.0.0.

    Returns:
        str: Path to the current node's cvpi_logs directory. Empty if not reading a
            cvpi_debug_logs bundle.
    """
    warn("Please use self.local_directory(directory_type='logs'); deprecated=2.4.0; removed=4.0.0", DeprecationWarning, stacklevel=2)
    return(self.local_directory('logs'))

  def local_directory(self, directory_type):
    """ When using log files return the directory of the requested type.

    Args:
        directory_type: type of the directory to return. Valid types are:
            - logs: will return the current node's cvpi_logs directory.
            - commands: will return the current node's cvpi_commands directory.
            - root: will return the root directory of the uncompressed log files.

    Returns:
        str: Path to the requested directory. Empty if not reading a cvpi_debug_logs bundle.
    """
    supported_directories = ['logs', 'commands', 'root']
    if directory_type not in supported_directories or not self.is_using_local_logs():
      return("")
    if directory_type == 'logs':
      return(self.config.get('node_config').get('debuglogdir'))
    elif directory_type == 'commands':
      return(self.config.get('node_config').get('debugcmddir'))
    elif directory_type == 'root':
      local_dir = '/'.join(self.config.get('node_config').get('debuglogdir').split('/')[:-2])
      return(local_dir)
    else:
      return("")

  def post_scan(self):
    """ Stub post_scan function. Bugchecks should override this if they intend to
    implement a post_scan() method. post_scan is invoked after scanning is done in all nodes.

    Returns:
        None: None
        str: No post_scan action available message
    """
    value = None
    message = 'No post-scan actions defined'
    return(value, message)

  def patch(self, force=False):
    """ Stub patch function. Bugchecks should override this if they intend to
    implement a patch() method.

    Returns:
        None: None
        str: No patch action available message
    """
    value = None
    message = 'No patch action available'
    return(value, message)

  def pre_patch(self):
    """ Performs useful generic checks intended to be run before patching. This
    is used internally and normally shouldn't be overriden.

    This function will prevent patches from being applied in the following conditions:
      - Checking debug logs
      - CVP version doesn't match the expected conditions. This can be broken down to the following:
        - Bugcheck has both a introduced_in and fixed_in declaration and the CVP version is not higher or equal than introduced_in and lower than fixed_in;
        - Bugcheck has a introduced_in declaration and the CVP version is not higher or equal than that;
        - Bugcheck has a fixed_in declaration and the CVP version is not lower than that;
      - Bugcheck scan() returned OK

    Returns:
        bool: Whether or not the patch() should be performed.
        str: Informative message describing the reason for allow.
    """
    if self.config.get('patch'):
      user = self.config['patch'].get('privileges')
      if user and getpass.getuser() not in ['root', user]:
        return([False, "User %s cannot patch" %getpass.getuser()])
      if self.config['patch'].get('component_requirements') and not self.is_using_local_logs():
        failed_requirements = self.cvpi(action='status', services=[self.config['patch']['component_requirements']]).failed
        if failed_requirements:
          return([False, "Not scanning due to running component requirements not met: %s" %failed_requirements])

    if self.is_using_local_logs():
      return([False, "Cannot patch while checking debug logs"])
    if self.config.get('conditions'):
      if len(self.config['conditions']) > 0:
        allow = False
      for condition in self.config['conditions']:
        if condition.get('introduced_in') or condition.get('fixed_in'):
          if not allow:
            if condition.get('introduced_in') and condition.get('fixed_in'):
              if self.cvp_is('>=', condition['introduced_in']) and self.cvp_is('<', condition['fixed_in']):
                allow = True
            elif condition.get('introduced_in') and self.cvp_is('>=', condition.get('introduced_in')):
              allow = True
            elif condition.get('fixed_in') and self.cvp_is('<', condition.get('fixed_in')):
              allow = True
        else:
          self.debug('Allowing scan as no introduced_in or fixed_in declarations were present.', code.LOG_DEBUG)
          allow = True
      if not allow:
        return([False, "CVP %s is not affected" %self.cvp_version()])
    if self.get_status(section='code') == code.OK:
      return([False, "No issue was detected"])

    return([True, None])

  def pre_scan(self):
    """ Performs useful generic checks intended to be run before scanning. This
    is used internally and normally shouldn't be overriden.

    This function will prevent scanning in the following conditions:
      - CVP version doesn't match the expected conditions. This can be broken down to the following:
        - Bugcheck has both a introduced_in and fixed_in declaration and the CVP version is not higher or equal than introduced_in and lower than fixed_in;
        - Bugcheck has a introduced_in declaration and the CVP version is not higher or equal than that;
        - Bugcheck has a fixed_in declaration and the CVP version is not lower than that;

    Returns:
        bool: Whether or not the scan() should be performed.
        str: Informative message describing the reason for allow.
    """
    if self.config.get('scan'):
      if not self.is_using_local_logs():
        user = self.config['scan'].get('privileges')
        if user and (getpass.getuser() not in ['root', user] and self.config['node_config'].get('username') not in ['root', user]):
          return([False, "User %s cannot scan" %getpass.getuser()])
      if self.config['scan'].get('component_requirements') and not self.is_using_local_logs():
        failed_requirements = self.cvpi(action='status', services=[self.config['scan']['component_requirements']]).failed
        if failed_requirements:
          return([False, "Not scanning due to running component requirements not met: %s" %failed_requirements])

    if self.config.get('conditions'):
      if len(self.config['conditions']) > 0:
        allow = False
      for condition in self.config['conditions']:
        if condition.get('introduced_in') or condition.get('fixed_in'):
          if not allow:
            if condition.get('introduced_in') and condition.get('fixed_in'):
              if self.cvp_is('>=', condition['introduced_in']) and self.cvp_is('<', condition['fixed_in']):
                allow = True
            elif condition.get('introduced_in') and self.cvp_is('>=', condition.get('introduced_in')):
              allow = True
            elif condition.get('fixed_in') and self.cvp_is('<', condition.get('fixed_in')):
              allow = True
        else:
          self.debug('Allowing scan as no introduced_in or fixed_in declarations were present.', code.LOG_DEBUG)
          allow = True
      if not allow:
        return([False, "CVP %s is not affected" %self.cvp_version()])

    return([True, None])

  def read_file(self, filename, force_time_filter=False, from_last=None, grep=None):
    """ Retrives a file's content. It will also perform filtering according to the
    timestamp if a log start date has been previously set and the filename
    matches a list of expected log filename patterns.

    As an alternative to filtering you may also use the from_last parameter, providing
    a string to act as a delimiter and retrive contents only from that line onwards.
    This is particularly useful when you want to retrieve logs since the last time a
    service was restarted.

    The following are considered log files:
      - *log
      - *out
      - journalctl
      - kubelet_journalctl
      - coredns

    Args:
        filename (str): Path to the file
        force_time_filter (bool): Force running the file's contents through the timestamp filtering function
            even if the file is not considered a log file. Default: False
        from_last (str): Return only the contents after the last occurrence of STRING.
        grep (str): Return only lines matching this regex.

    Returns:
        list: File lines
    """
    class log_delimiter(object):
      def __init__(self, bug):
        self.logfile = {}
        self.logfile[bug.local_directory(directory_type='logs')+'/hbasemaster'] = 'server.Server: Started'
        self.logfile[bug.local_directory(directory_type='logs')+'/elasticsearch-server/es-cluster.log'] = '] started'
        self.logfile[bug.local_directory(directory_type='logs')+'/aaa/aaa.stderr.log'] = 'Initializing auth providers map'
        self.logfile[bug.local_directory(directory_type='logs')+'/user/user-upgrade.log'] = 'Upgrading user component'

      def get_delimiter(self, logfile):
        delimiter = None
        for definition in self.logfile.keys():
          if definition in logfile:
            delimiter = self.logfile[definition]
        return(delimiter)

    delimiter = None
    log_suffixes = ['log', 'out', 'journalctl', 'kubelet_journalctl', 'coredns']

    if self.config['read_files_only_from_last_service_restart']:
      if from_last:
        delimiter = from_last
      else:
        delimiter = log_delimiter(self)
        delimiter = delimiter.get_delimiter(filename)
      if not delimiter:
        self.debug("No delimiter found for %s" %filename , code.LOG_DEBUG)
    else:
      self.debug("Bypassing service last restart filtering", code.LOG_DEBUG)

    if delimiter and grep:
      if grep.startswith('(') and (grep.endswith(')') and not grep.endswith(r'\)')):
        grep = grep.split('(')[1].split(')')[0].split('|')
      else:
        grep = [grep]
      grep.append(delimiter)
      grep = '|'.join(grep)
      grep = '(%s)' %grep
      self.debug("Formatted regex search: %s" %grep, code.LOG_JEDI)

    try:
      if self.is_using_local_logs():
        if grep:
          output = self.filecache.get(filename=filename, filter_string=grep)
        else:
          output = self.filecache.get(filename=filename)

        if output == False:
          file = open(filename)
          output = file.read().splitlines()
          file.close()
          self.filecache.put(filename=filename, contents=output)

          if grep:
            newout = []
            for line in output:
              if re.search(grep, line):
                newout.append(line)
            self.debug("%s lines removed (%s remaining) after grepping %s" %(len(output)-len(newout), len(newout), grep), code.LOG_DEBUG)
            output = newout
            self.filecache.put(filename=filename, contents=output, filter_string=grep)
      else:
        output = self.filecache.get(filename=filename, filter_string=grep)
        if output == False:
          if grep:
            output = self.run_command('egrep \'%s\' %s' %(grep, filename)).stdout
          else:
            output = self.run_command('cat %s' %filename).stdout
          self.filecache.put(filename=filename, filter_string=grep, contents=output)
        else:
          self.debug("Re-used cached contents for %s" %filename, code.LOG_DEBUG)
    except Exception as e:
      self.debug("Could not read %s: %s" %(filename, e), code.LOG_DEBUG)
      return([])

    if filename.split('.')[-1].split('/')[-1] in log_suffixes or force_time_filter:
      output = self.__filter_logs(output, filename=filename)
    else:
      self.debug("Skipping timestamp filtering for %s" %filename, code.LOG_DEBUG)

    if delimiter:
      self.debug("Found delimiter for %s: %s" %(filename, delimiter), code.LOG_DEBUG)
      output.reverse()
      index = [i for i, s in enumerate(output) if delimiter in s]
      if index:
        self.debug("Delimiter string \"%s\" found with indexes %s" %(delimiter, index), code.LOG_DEBUG)
        output = output[:index[0]]
      else:
        self.debug("Couldn't find any occurrences of %s." %delimiter, code.LOG_DEBUG)
      output.reverse()

    self.debug(output, code.LOG_JEDIMASTER)
    return(output)

  def run_command(self, command, silence_cvpi_warning=False, cacheable=False, all_nodes=False, timeout=None):
    """ Runs a command on the current node. This should be used only when running a
    live check.

    Args:
        command (str): Command to run on the node
        silence_cvpi_warning (bool): Do not print a warning message when running cvpi
            commands. This shouldn't be normally used by bugchecks. Default: False

    Returns:
        Output object: object containing the following attributes:
          - members (list): list of hosts the command ran on. Each member is an Output object on its own, containing the attributes below.
          - stdout (list): Lines generated on the host's stdout if running on a single host, ['{multiple}'] if running on multiple hosts
          - stderr (list): Lines generated on the host's stderr if running on a single host, ['{multiple}'] if running on multiple hosts
          - exit_code (int): Exit code of the command if running on a single host. If running on multiple hosts it will contain the value of a non-OK return from members or OK if all members return OK.
    """
    class Output(object):
      def __init__(self, **kwargs):
        hosts = kwargs.get('hosts')
        if hosts:
            self.hosts = list(kwargs['hosts'].keys())
            for host in hosts:
                setattr(self, host, Output(
                    stdout=kwargs['hosts'][host].get('stdout'),
                    stderr=kwargs['hosts'][host].get('stderr'),
                    exit_code=kwargs['hosts'][host].get('exit_code'),
                ))

        if kwargs.get('stdout'):
            self.stdout = kwargs['stdout']
        elif hosts and len(hosts) > 1:
            self.stdout = ['{multiple}']
        elif hosts and len(hosts) == 1:
            for host in hosts:
                self.stdout = hosts[host]['stdout'] if hosts[host].get('stdout') else []
        else:
            self.stdout = []

        if kwargs.get('stderr'):
            self.stderr = kwargs['stderr']
        elif hosts and len(hosts) > 1:
            self.stderr = ['{multiple}']
        elif hosts and len(hosts) == 1:
            for host in hosts:
                self.stderr = hosts[host]['stderr'] if hosts[host].get('stderr') else []
        else:
            self.stderr = []

        if kwargs.get('exit_code'):
            self.exit_code = kwargs['exit_code']
        elif hosts:
            self.exit_code = 0
            for host in hosts:
                host_exit_code = int(hosts[host]['exit_code']) if hosts[host].get('exit_code') else 0
                if host_exit_code != 0:
                    self.exit_code = host_exit_code
        else:
            self.exit_code = 0

    retval = None
    stdout = []
    target_host = self.config['node_config'].get('host')
    current_host = socket.gethostname()
    force_ssh = self.config['node_config']['force_ssh']

    if 'cvpi ' in command and not silence_cvpi_warning:
      warn("cvpi commands should use the cvpi() method", DeprecationWarning, stacklevel=2)
    if 'cat ' in command:
      warn("Please consider using the read_file() method", DeprecationWarning, stacklevel=2)

    if self.is_using_local_logs():
      target_host = '%--LOCAL--%'

    self.debug("Running command %s" %command, code.LOG_DEBUG)
    self.debug("Target Host: %s" %target_host, code.LOG_JEDI)
    self.debug("Local Host: %s" %current_host, code.LOG_JEDI)
    if cacheable:
      retval = self.filecache.get(filename=command)

    if (cacheable and retval == False) or not cacheable:
      start = timer()
      if cacheable:
        self.filecache.lock(filename=command)

      cmdresult = {}
      if all_nodes:
        for member in self.config['node_config']['cluster'].members:
          if member.get_name() == current_host and not force_ssh:
            self.debug("Running command on %s (local)" %member.get_name(), code.LOG_DEBUG)
            stdout, stderr, exit_code = self.__run_local_command(command)
          else:
            self.debug("Running command on %s (connection: %s)" %(member.get_name(), member.config.get('connection')), code.LOG_DEBUG)
            stdout, stderr, exit_code = self.__run_remote_command(command, connection=member.config.get('connection'), timeout=timeout)
          cmdresult[member.get_name()] = {}
          cmdresult[member.get_name()]['stdout'] = stdout
          cmdresult[member.get_name()]['stderr'] = stderr
          cmdresult[member.get_name()]['exit_code'] = exit_code
      else:
        if (target_host == current_host or not target_host or target_host == '%--LOCAL--%') and not force_ssh:
          stdout, stderr, exit_code = self.__run_local_command(command)
        else:
          stdout, stderr, exit_code = self.__run_remote_command(command, connection=self.config.get('connection'), timeout=timeout)
        cmdresult[target_host] = {}
        cmdresult[target_host]['stdout'] = stdout
        cmdresult[target_host]['stderr'] = stderr
        cmdresult[target_host]['exit_code'] = exit_code

      retval = Output(hosts=cmdresult)

      end = timer()
      elapsed = timedelta(microseconds=end-start)
      if cacheable:
        self.filecache.put(filename=command, contents=retval)
        self.filecache.unlock(filename=command)
        self.debug("Cached command output after %sus" %elapsed, code.LOG_JEDI)
    else:
      self.debug("Retrieved %s contents from %s: %s" %(command, self.filecache, retval), code.LOG_DEBUG)

    if not all_nodes and retval.stderr:
      self.debug("Command %s returned errors: %s" %(command, retval.stderr), code.LOG_DEBUG)

    return(retval)

  def save_cluster_value(self, value, keyname=None):
    '''Saves a cluster-wide accessible value'''
    retval = False
    if self.config.get('name'):
      if not keyname:
        keyname = self.config['name']
      self.debug("Storing %s key %s: %s" %(self.get_node_role(), keyname, value), code.LOG_DEBUG)
      self.cluster_store.save(node=self.get_node_role(), key=keyname, value=value)
    return retval

  def get_cluster_values(self, keyname=None):
    class Return_Value:
      def __init__(self, primary=None, secondary=None, tertiary=None):
        self.primary=primary
        self.secondary=secondary
        self.tertiary=tertiary
    retval = Return_Value()
    if not keyname:
      keyname=self.config.get('name')
    retval.primary = self.cluster_store.primary.get(keyname)
    retval.secondary = self.cluster_store.secondary.get(keyname)
    retval.tertiary = self.cluster_store.tertiary.get(keyname)
    return retval

  def scan(self):
    """ Stub scan() method. This MUST be overriden by the bugcheck otherwise it will
    only raise an error and the bugcheck won't be run.

    Raises:
        NotImplementedError: A scan action was not defined on the bugcheck
    """
    raise(NotImplementedError("A scan action was not defined"))

  def set_status(self, value, message, extra=[], has_run=True):
    """ Sets the status of a bugcheck. Every bugcheck should use this at the end of
    the run.

    Args:
        value (int): Represents the success status of the bugcheck. It's highly recommended to
            import return_codes and use the static values defined there instead of
            manually setting a value. The values are the following:
              - OK (0): No issue exists.
              - WARNING (1): An issue may exist (no confirmation was possible) or a
                  value is close to a threshold and warrants attention.
              - ERROR (2): An issue was found.
              - INFO (3): No issue was found but some note should be displayed to
                  the user.
              - UNAVAILABLE (-1): The bugcheck could not be performed due to a file
                  or value being unavailable.
              - UNSUPPORTED (-2): The bugcheck isn't supported. This can be used for
                  bugchecks that only check logs or live clusters but not both.
        message (str): Message that will be displayed for the user when checking the bugcheck
            status.
        extra: Extra information to store. This is usually a list of affected services,
            pods or files, but can be anything.
        has_run: Indicates whether or not a bugcheck has been run at least once. This is
            intended to be used to help debugging and shouldn't be normally set.
    """
    self.status['code'] = value
    self.status['message'] = message
    self.status['extra'] = extra
    self.status['has_run'] = has_run
    self.debug("Status set: " + str(self.status), code.LOG_DEBUG)

