from bugchecks.bug import Bug
import lib.return_codes as code

class k8s_pods_failed(Bug):
  def __init__(self):
    super(k8s_pods_failed, self).__init__()

  def scan(self):
    value = code.OK
    message = None
    affected_pods = []

    pods = self.get_k8s_resources(resource_type='pods', filter="Failed")
    if pods:
      value = code.ERROR
      for pod in pods:
        affected_pods.append(pod)
      message = ', '.join(affected_pods)

    self.set_status(value, message, affected_pods)
    return(value)
