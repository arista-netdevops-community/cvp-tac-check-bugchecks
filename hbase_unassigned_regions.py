from bugchecks.bug import Bug
import lib.return_codes as code
import os
import re

class hbase_unassigned_regions(Bug):
  def __init__(self):
    super(hbase_unassigned_regions, self).__init__()

  def __scan_logs(self):
    unassigned_regions_regex = r'.*\.(.*)\.[,]?'
    value = code.OK
    affected_regions = []
    logfile = None
    for root, dirs, files in os.walk(self.local_directory(directory_type='logs')+'/hbasemaster/'):
      for file in files:
        if file.endswith('.log'):
          logfile = file

    if logfile:
      self.debug("Found hbase master log file: %s" %logfile, code.LOG_DEBUG)
      file = self.read_file(self.local_directory(directory_type='logs')+'/hbasemaster/'+logfile)
      if file:
        for line in file:
          if 'CatalogJanitor' in line and 'unknown_server' in line:
            regions = line.split('unknown_server')[1:]
            for regionline in regions:
              region = re.search(unassigned_regions_regex, regionline)
              if region:
                region = region.groups()[0]
                if region not in affected_regions:
                  affected_regions.append(region)
              else:
                self.debug("Couldn't determine region in line: %s" % regionline, code.LOG_WARNING)
    else:
      self.debug("No hbase master log file found in node", code.LOG_DEBUG)

    if affected_regions:
      self.debug("%s affected regions found in %s lines" %(len(affected_regions),len(file)), code.LOG_DEBUG)
      value = code.ERROR
    elif logfile:
      self.debug("No affected regions found in %s lines" %len(file), code.LOG_DEBUG)

    return([value, affected_regions])

  def __scan_node(self):
    check_command = 'hbase hbck 2>/dev/null|grep "not deployed on any region server"'
    value = code.OK
    affected_regions = []

    regions = self.run_command(check_command).stdout
    if regions and regions != '':
      for region in regions:
        region = region.split()[8]
        region = region.split('/')[7]
        affected_regions.append(region)

    if affected_regions:
      value = code.ERROR

    return([value, affected_regions])

  def scan(self):
    value = code.OK
    message = None
    regions = []

    if self.is_using_local_logs():
      value, regions = self.__scan_logs()
    else:
      value, regions = self.__scan_node()

    if value != code.OK:
      count = len(regions)
      message = '%s affected regions: ' %count+', '.join(regions)

    self.set_status(value, message, regions)
    return(value)

  def patch(self):
    value = code.OK
    message = []
    for region in self.get_status(section='extra'):
      self.debug("Assigning region %s" %region, code.LOG_INFO)
      if self.cvp_is('>=', '2021.2.2'):
        check_command = "su - cvp -c 'HBASE_CLASSPATH_PREFIX=/cvpi/hbase/hbase-operator-tools/hbase-hbck2/hbase-hbck2-1.2.0.jar hbase org.apache.hbase.HBCK2 assigns %s'" %region
      elif self.cvp_is('>=', '2021.2.0'):
        check_command = "su - cvp -c 'HBASE_CLASSPATH_PREFIX=/cvpi/hbase/hbase-operator-tools/hbase-hbck2/hbase-hbck2-1.1.0.jar hbase org.apache.hbase.HBCK2 assigns %s'" %region
      elif self.cvp_is('>=', '2021.1.0'):
        check_command = "su - cvp -c 'HBASE_CLASSPATH_PREFIX=/cvpi/hbase/hbase-operator-tools/hbase-hbck2/hbase-hbck2-1.0.0.jar hbase org.apache.hbase.HBCK2 assigns %s'" %region
      else:
        check_command = "su - cvp -c 'echo assign %s| hbase shell -n'" %region
      self.run_command(check_command)
      message.append(region)
    return(value, message)
