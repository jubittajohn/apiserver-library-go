# apiserver-library-go

Kubernetes/Kubernetes-dependent helpers for kube-apiserver and openshift-apiserver.

## Overview

This library provides common functionality and helpers for building and extending Kubernetes API servers in the OpenShift ecosystem. It wraps and extends upstream `k8s.io/apiserver` with OpenShift-specific admission plugins, authorization logic, validation, and security context constraints.

### What does this library do?

- **Admission control**: Image policy enforcement and resource quota admission
- **Security Context Constraints**: OpenShift's pod security admission system with granular controls
- **Authorization**: OAuth scope to RBAC conversion and authorization helpers
- **Validation**: OpenShift-specific user/group name validation
- **Utilities**: Label selectors, configuration flag helpers, and build tooling

### Why does this exist?

This library exists because:

- OpenShift has specific security requirements (Security Context Constraints) that extend beyond Kubernetes Pod Security Standards
- OpenShift needs admission control for image policies (registry restrictions, signature verification)
- OpenShift uses OAuth scopes that need to be converted to RBAC rules
- Common functionality needs to be shared between kube-apiserver and openshift-apiserver without duplication

## Getting Started

### Building

```bash
make build
```

### Testing

```bash
# Run all tests
make test

# Run unit tests only
make test-unit
```

### Using this library

```go
import (
    "github.com/openshift/apiserver-library-go/pkg/admission/imagepolicy"
    "github.com/openshift/apiserver-library-go/pkg/securitycontextconstraints/sccmatching"
)

// Example: Use SCC matcher to find applicable SCCs for a user
matcher := sccmatching.NewDefaultSCCMatcher(sccLister, authorizer)
applicableSCCs, err := matcher.FindApplicableSCCs(ctx, namespace, userInfo)
```

## Contributing

When making changes to this library, you must provide "proof PRs" that bump this dependency in downstream repos and demonstrate that presubmit tests pass. This ensures that changes to this library don't break dependent projects.

Typical proof PR workflow:
1. Make your changes in this repo
2. Create PRs in dependent repos (e.g., `openshift/kubernetes`, `openshift/openshift-apiserver`) that bump the dependency
3. Verify that presubmit tests pass in those repos
4. Reference the proof PRs in your PR description
