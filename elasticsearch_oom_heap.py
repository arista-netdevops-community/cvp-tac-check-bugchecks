from bugchecks.bug import Bug
import lib.return_codes as code
import re

class elasticsearch_oom_heap(Bug):
  def __init__(self):
    super(elasticsearch_oom_heap, self).__init__()
    self.elasticsearch_conf = '/cvpi/elasticsearch/conf/jvm.options'
    self.xms_regex = '^-Xms([0-9]*)g'
    self.xmx_regex = '^-Xmx([0-9]*)g'

  def scan(self):
    value = code.OK
    message = None
    logfile = None

    if self.is_using_local_logs():
      logfile = self.local_directory(directory_type='logs')+'/elasticsearch-server/es-cluster.log'
      logs = self.read_file(logfile)
    else:
      logs = self.run_command("kubectl logs -l 'app=elasticsearch-server'|grep OutOfMemoryError").stdout

    if logs:
      for line in logs:
        if 'OutOfMemoryError: Java heap space' in line:
          value = code.ERROR
          message = "%s" %line

    self.set_status(value, message)
    return(value)

  def patch(self):
    value = code.OK
    message = None

    conf = self.read_file(self.elasticsearch_conf)
    new_conf = []

    for line in conf:
      xms = re.search(self.xms_regex, line)
      xmx = re.search(self.xmx_regex, line)
      if xms:
        xms = int(xms.groups()[0])
        xms = xms * 2
        line = '-Xms%sg\n' %xms
      elif xmx:
        xmx = int(xmx.groups()[0])
        xmx = xmx * 2
        line = '-Xmx%sg\n' %xmx
      new_conf.append(line)
    new_conf = ''.join(new_conf)
    self.debug("Generated new configuration: %s" %new_conf, code.LOG_DEBUG)
    
    self.debug("Stopping Elasticsearch", code.LOG_INFO)
    result = self.cvpi(action='stop', services=['elasticsearch'])
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return(value, message)
    
    self.debug("Backing up existing configuration", code.LOG_INFO)
    self.run_command("su - cvp -c 'cp %s %s.bkp'" %(self.elasticsearch_conf, self.elasticsearch_conf))

    self.debug("Applying new configuration", code.LOG_INFO)
    self.run_command("echo -e '%s' > %s" %(new_conf, self.elasticsearch_conf))

    self.debug("Starting CVP", code.LOG_INFO)
    result = self.cvpi(action='start')
    if result.failed:
      value = code.ERROR
      message = "Actions failed: %s" %result.failed
      return(value, message)

    return(value, message)