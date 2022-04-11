from bugchecks.bug import Bug
import lib.return_codes as code

class kafka_lag(Bug):
  def __init__(self):
      super(kafka_lag, self).__init__()

      self.config['lag_warning_threshold'] = 500
      self.config['lag_error_threshold'] = 1000

  def scan(self):
    value = code.OK
    message = None
    lag_highest_value = 0
    
    if self.cvp_is('<', '2021.2.0'):
      check_command = "su - cvp -c '/cvpi/apps/aeris/kafka/bin/kafka-consumer-groups.sh --bootstrap-server 127.0.0.1:9092 --describe --group postDB_dispatcher|grep -v TOPIC'"
      check_index = 5
    else:
      check_command = "kubectl exec -it kafka-0 -- sh -c 'KAFKA_LOG4J_OPTS= KAFKA_OPTS= JMX_PORT= bin/kafka-consumer-groups.sh --bootstrap-server 127.0.0.1:9092 --describe --group postDB_dispatcher|grep -v TOPIC'"
      check_index = 4

    if self.is_using_local_logs():
      self.debug("Scanning debug logs", code.LOG_DEBUG)
      output = self.read_file(self.local_directory(directory_type='commands')+'/kafka_dispatcher_consumer')
    else:
      self.debug("Performing live scan", code.LOG_DEBUG)
      output = self.run_command(check_command).stdout

    for line in output:
      if line and 'postDB' in line:
        contents = line.split()
        try:
          lag = int(contents[check_index])
        except ValueError:
          lag = 0
        except:
          self.debug("Error parsing line: " + line, code.LOG_WARNING)
          self.debug("CVP version: " + self.cvp_version(), code.LOG_DEBUG)
          self.debug("Check index: " + check_index, code.LOG_DEBUG)
          lag = 0
        if lag > lag_highest_value:
          self.debug("High kafka lag in line: " + line, code.LOG_JEDI)
          self.debug("Parsed lag: " + str(lag), code.LOG_JEDI)
          lag_highest_value = lag

    if lag_highest_value >= self.config['lag_error_threshold']:
      value = code.ERROR
      message = "High kafka lag: " + str(lag_highest_value)
    elif lag_highest_value >= self.config['lag_warning_threshold']:
      value = code.WARNING
      message = "High kafka lag: " + str(lag_highest_value)
    else:
      message = "Kafka lag: " + str(lag_highest_value)

    self.set_status(value, message, lag_highest_value)
    return(value)
