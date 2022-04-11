import lib.return_codes as code
from bugchecks.cvpi_resources import cvpi_resources

class os_loadaverage(cvpi_resources):
  def __init__(self):
    super(os_loadaverage, self).__init__()

  def __scan_logs(self):
    load_average = []
    file = self.read_file(self.local_directory(directory_type='commands')+'/top')
    for line in file:
      if 'load average' in line:
        load_average = line.split(',')
        index = int([i for i in range(len(load_average)) if load_average[i].find('load average') != -1][0])
        load_5 = float(' '.join(load_average[index:]).strip().split()[2])
        load_10 = float(' '.join(load_average[index:]).strip().split()[3])
        load_15 = float(' '.join(load_average[index:]).strip().split()[4])
        load_average = [load_5, load_10, load_15]
    return(load_average)
  
  def __scan_node(self):
    load_average = self.run_command('cat /proc/loadavg').stdout
    load_average = load_average[0].split()
    load_average = [float(load_average[0]), float(load_average[1]), float(load_average[2])]
    return(load_average)

  def scan(self):
    value = code.OK
    message = None

    self.debug("Running parent's scan()", code.LOG_DEBUG )
    super(os_loadaverage, self).scan()

    self.debug("Getting parent's status", code.LOG_DEBUG)
    cpus = super(os_loadaverage, self).get_status(section='extra')['cpu']

    warn_threshold = cpus
    error_threshold = round(float(1.5)*cpus, 3)

    if self.is_using_local_logs():
      self.debug("Scanning debug logs", code.LOG_DEBUG)
      load_average = self.__scan_logs()
    else:
      self.debug("Performing live scan", code.LOG_DEBUG)
      load_average = self.__scan_node()

    self.debug("Load average: %s" %str(load_average), code.LOG_JEDI)

    highest_load = max(load_average)
    if highest_load >= error_threshold:
      message = "Very High Load Average: " + str(highest_load) + " >= " + str(error_threshold)
      value = code.ERROR
    elif highest_load >= warn_threshold:
      message = "High Load Average: " + str(highest_load) + " >= " + str(warn_threshold)
      value = code.WARNING

    self.set_status(value, message, load_average)
    return(value)
