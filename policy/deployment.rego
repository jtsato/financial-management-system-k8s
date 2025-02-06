package main

deny["Image with 'latest' tag."] {
  startswith(input.kind, "Deployment")
  container := input.spec.template.spec.containers[_]
  endswith(container.image, "latest")
}

warn["ImagePullPolicy: Always."] {
  startswith(input.kind, "Deployment")
  container := input.spec.template.spec.containers[_]
  container.imagePullPolicy == "Always"
}

deny["Readiness probe should be defined."] {
  startswith(input.kind, "Deployment")
  container := input.spec.template.spec.containers[_]
  not container.readinessProbe
}

deny["Liveness probe should be defined."] {
  startswith(input.kind, "Deployment")
  container := input.spec.template.spec.containers[_]
  not container.livenessProbe
}

warn["Liveness initialDelaySeconds should be defined."] {
  startswith(input.kind, "Deployment")
  container := input.spec.template.spec.containers[_]
  container.livenessProbe
  not container.livenessProbe.initialDelaySeconds
}

deny["CPU request should be defined."] {
  startswith(input.kind, "Deployment")
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.cpu
}

deny["CPU limit should be defined."] {
  startswith(input.kind, "Deployment")
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.cpu
}

deny["Memory request should be defined."] {
  startswith(input.kind, "Deployment")
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.memory
}

deny["Memory limit should be defined."] {
  startswith(input.kind, "Deployment")
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
}

warn["maxUnavailable being 0 can avoid performance issues."] {
  startswith(input.kind, "Deployment")
  maxUnavailable := input.spec.strategy.rollingUpdate.maxUnavailable
  is_string(maxUnavailable)
  not re_match("^0%?$", maxUnavailable)
}

warn["maxUnavailable being 0 can avoid performance issues."] {
  startswith(input.kind, "Deployment")
  maxUnavailable := input.spec.strategy.rollingUpdate.maxUnavailable
  is_number(maxUnavailable)
  maxUnavailable != 0
}

deny["readinessProbe.timeoutSeconds variable with a value greater than the default readinessProbe.periodSeconds (10)."] {
   startswith(input.kind, "Deployment")
   container := input.spec.template.spec.containers[_]
   not container.readinessProbe.periodSeconds
   container.readinessProbe.timeoutSeconds
   container.readinessProbe.timeoutSeconds > 10
}

deny["readinessProbe.timeoutSeconds variable greater than readinessProbe.periodSeconds."] {
   startswith(input.kind, "Deployment")
   container := input.spec.template.spec.containers[_]
   container.readinessProbe.periodSeconds
   container.readinessProbe.timeoutSeconds
   container.readinessProbe.timeoutSeconds > container.readinessProbe.periodSeconds
}

deny["livenessProbe.timeoutSeconds variable with a value greater than the default livenessProbe.periodSeconds (10)."] {
   startswith(input.kind, "Deployment")
   container := input.spec.template.spec.containers[_]
   not container.livenessProbe.periodSeconds
   container.livenessProbe.timeoutSeconds
   container.livenessProbe.timeoutSeconds > 10
}

deny["livenessProbe.timeoutSeconds variable greater than livenessProbe.periodSeconds."] {
   startswith(input.kind, "Deployment")
   container := input.spec.template.spec.containers[_]
   container.livenessProbe.periodSeconds
   container.livenessProbe.timeoutSeconds
   container.livenessProbe.timeoutSeconds > container.livenessProbe.periodSeconds
}
