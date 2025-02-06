package main

deny["Image should not be latest."] {
  startswith(input.kind, "CronJob")
  container := input.spec.jobTemplate.spec.template.spec.containers[_]
  endswith(container.image, "latest")
}

warn["ImagePullPolicy: Always."] {
  startswith(input.kind, "CronJob")
  container := input.spec.jobTemplate.spec.template.spec.containers[_]
  container.imagePullPolicy == "Always"
}

deny["CPU request should be defined."] {
  startswith(input.kind, "CronJob")
  container := input.spec.jobTemplate.spec.template.spec.containers[_]
  not container.resources.requests.cpu
}

deny["CPU limit should be defined."] {
  startswith(input.kind, "CronJob")
  container := input.spec.jobTemplate.spec.template.spec.containers[_]
  not container.resources.limits.cpu
}

deny["Memory request should be defined."] {
  startswith(input.kind, "CronJob")
  container := input.spec.jobTemplate.spec.template.spec.containers[_]
 not container.resources.requests.memory
}

deny["Memory limit should be defined."] {
  startswith(input.kind, "CronJob")
  container := input.spec.jobTemplate.spec.template.spec.containers[_]
  not container.resources.limits.memory
}
