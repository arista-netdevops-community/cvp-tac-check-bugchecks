import re
from bugchecks.bug import Bug
import lib.return_codes as code

class cvp_image_missingdefault(Bug):
  def __init__(self):
    super(cvp_image_missingdefault, self).__init__()
    self.preloaded_regex=[
      r'.*Preloaded default images are: (\[.*\]$)',
      r'.*Images need to be added: (\[.*\]$)'
    ]
    self.image_extract_regex=r'{\"([a-zA-Z\-0-9\.]*)'

  def scan(self):
    value = code.OK
    message = None
    default_images = []
    missing_images = []

    if self.is_using_local_logs:
      image_log = self.local_directory(directory_type='logs')+"/image/image.stderr.log"
      image_log = self.read_file(image_log)
    else:
      image_log = self.run_command('kubectl logs -l app=image --prefix').stdout

    if image_log:
      for line in image_log:
        for regex in self.preloaded_regex:
          preload = re.search(regex, line)
          if preload:
            preload = preload.groups()[0]
            self.debug("Found image load line: %s" %preload, code.LOG_JEDI)
            preload = re.findall(self.image_extract_regex, preload)
            if len(preload) > 0:
              self.debug("Images found in line: %s" %preload, code.LOG_JEDIMASTER)
              for image in preload:
                if image not in default_images:
                  default_images.append(image)
            else:
              self.debug("Load line found but no images could be extracted: %s" %line, code.LOG_DEBUG)
      for line in image_log:
        for image in default_images:
          if 'Unable to find image with name: '+image in line:
            self.debug("Missing image line: %s, %s" %(image, line), code.LOG_JEDI)
            if image not in missing_images:
              missing_images.append(image)
      for line in image_log:
        for image in default_images:
          if 'Successfully upserted image: '+image in line:
            try:
              self.debug("Image %s was loaded. Removing from missing list." %image, code.LOG_JEDI)
              missing_images.remove(image)
            except ValueError:
              pass
      if missing_images:
        value = code.ERROR
        message = "Missing images: %s" %missing_images
    else:
      value = code.UNAVAILABLE
      message = "Image service logs not available."

    self.set_status(value, message)
    return(value)
