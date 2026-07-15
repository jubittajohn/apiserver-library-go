# Agent Guidelines

This document provides guidance for AI agents working with the apiserver-library-go codebase. It focuses on best practices, common patterns, and agent-specific workflows.

## Quick Start for Agents

1. **Understand this is a library** - Changes affect downstream OpenShift API servers, not just this repo
2. **Code generation is limited** - Only applies to `pkg/admission/imagepolicy/apis/imagepolicy/v1` types; most packages don't need it
3. **Testing uses reactor pattern** - Fake Kubernetes clients with reactors mock API interactions

## Common Tasks & Workflows

### Making Code Changes

1. **Identify the component** - Explore `pkg/` directories to locate relevant package (see File Organization below)
2. **Read existing tests** - Pattern examples in `*_test.go` files show expected behavior
3. **Check if code generation applies** - Only `pkg/admission/imagepolicy/apis/imagepolicy/v1` uses generated DeepCopy methods
4. **Run verification** - Always run `make verify` before committing

### Adding New API Types

1. Add the type definition in the appropriate `pkg/` subdirectory
2. Add `// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object` comment if implementing `runtime.Object`
3. Run `make update-generated-deep-copies` to generate DeepCopy methods
4. Add unit tests for the new type
5. Verify with `make verify-generated-deep-copies`

### Testing Changes

**Unit Tests**:
```bash
# Run all tests
make test

# Run specific package tests
go test ./pkg/securitycontextconstraints/...

# Run specific test
go test -run TestSCCAdmission ./pkg/securitycontextconstraints/sccadmission
```

**Test Patterns**:
- Use fake clients from `k8s.io/client-go/testing`
- Add reactors to mock API server responses
- Test both success and error paths
- Validate admission decisions, not just code execution

Example reactor pattern:
```go
client := fake.NewSimpleClientset()
client.PrependReactor("create", "pods", func(action testing.Action) (bool, runtime.Object, error) {
    // Mock response logic
    return true, createdPod, nil
})
```

### Working with SCC Components

Security Context Constraints are the most complex subsystem. Key patterns:

**Validation Flow**:
1. `sccmatching/` - Find applicable SCCs for a pod
2. `sccdefaults/` - Apply defaults from selected SCC
3. Component validators (`capabilities/`, `user/`, `selinux/`, etc.) - Validate specific security dimensions
4. `sccadmission/` - Final admission decision

**Common Changes**:
- Adding new security validations → Add to appropriate component validator
- Changing SCC selection logic → Modify `sccmatching/`
- Adding SCC defaults → Extend `sccdefaults/`

### Updating Dependencies

**Kubernetes Version Bumps**:
1. Update `go.mod` with new k8s.io versions
2. Run `go mod tidy && go mod vendor`
3. Update imports if API paths changed
4. Regenerate deep-copy code: `make update-generated-deep-copies`
5. Fix breaking API changes
6. Run full test suite

**OpenShift API Updates**:
- Follow same pattern as Kubernetes updates
- Check `github.com/openshift/api` changelog for breaking changes

## Code Style & Conventions

### File Organization
- One admission plugin per directory under `pkg/admission/`
- Validators separate from admission logic
- Utilities in `util/` subdirectories
- Tests alongside implementation (`foo.go` → `foo_test.go`)

### Naming Conventions
- Admission plugins: `Register()` function for plugin registration
- Validators: `Validate()` or `ValidateX()` methods
- Fake clients: `fake.NewSimpleClientset()`
- Test fixtures: `validPod()`, `restrictedSCC()`, etc.

### Error Handling
- Return `field.ErrorList` for validation errors (provides structured paths)
- Use `admission.NewForbidden()` for admission denials
- Include context in error messages (which SCC, which field, why invalid)

### Comments
- Package comments required for all `pkg/` subdirectories
- Document non-obvious validation rules (especially SCC logic)
- Reference Kubernetes/OpenShift docs for complex concepts
- Update comments when behavior changes

## Critical Patterns to Follow

### 1. Informer-Based Caching
Components watch Kubernetes resources via informers, not direct API calls:

```go
sccInformer := factory.Security().V1().SecurityContextConstraints()
lister := sccInformer.Lister()
```

**Why**: Reduces API server load, provides fast local reads, ensures consistency.

### 2. Lock Factory for Concurrency
Quota admission uses per-resource locks to prevent race conditions:

```go
lockFactory := &QuotaLockFactory{}
lock := lockFactory.GetLock(quotaName)
lock.Lock()
defer lock.Unlock()
```

**Why**: Allows concurrent operations on different quotas while protecting shared state.

### 3. Admission Interface Implementation
All admission plugins implement `admission.Interface`:

```go
type MyPlugin struct {
    *admission.Handler
    // ...
}

func (p *MyPlugin) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
    // Admission logic
}
```

**Why**: Standard contract for Kubernetes admission chain.

### 4. Field Path Construction
Validation errors use field paths for precise error reporting:

```go
allErrs := field.ErrorList{}
allErrs = append(allErrs, field.Invalid(field.NewPath("spec", "containers").Index(0).Child("securityContext", "runAsUser"), uid, "must not be root"))
```

**Why**: Kubectl and API clients show exact location of validation failures.

## Things Agents Should NOT Do

1. **Don't edit generated files** - Files with `// Code generated` headers (especially `zz_generated.deepcopy.go`)
2. **Don't skip code generation** - Changes to types MUST run `make update-generated-deep-copies`
3. **Don't assume storage access** - This library reads via informers, never writes to etcd
4. **Don't break downstream** - OpenShift API servers depend on stable interfaces
5. **Don't ignore OWNERS** - Changes to some packages require specific approver review
6. **Don't hardcode Kubernetes versions** - Use version-agnostic client interfaces
7. **Don't add external dependencies lightly** - Vendored deps affect all consumers

## Debugging Tips for Agents

### Understanding Test Failures

**Reactor not triggered**:
- Check resource type matches (e.g., "pods" not "pod")
- Check verb matches ("create", "update", "get", "list")
- Ensure reactor is prepended, not appended (order matters)

**Generated code mismatch**:
```bash
make update-generated-deep-copies
git diff  # Should show the missing changes
```

**Field validation errors**:
- Look at `field.ErrorList` details for exact path
- Check if error is from validator or admission plugin
- Verify field path construction uses correct nesting

### Common Build Issues

**Missing code generation**:
```
Error: DeepCopyInto method missing
Fix: make update-generated-deep-copies
```

**Vendor out of sync**:
```
Error: missing package in vendor/
Fix: go mod vendor
```

**Import cycle**:
- Check for circular dependencies between packages
- Common in admission plugins importing each other
- Solution: Extract shared types to separate package

## Integration Points

### With Kubernetes API Server
This library integrates into the admission chain:
```
API Request → Authentication → Authorization → Admission (this library) → Validation → Storage
```

### With OpenShift API Server
OpenShift-specific admission plugins run alongside Kubernetes ones:
```
Generic Admission → Image Policy → SCC Admission → Resource Quota → Storage
```

### With RBAC
SCC admission checks RBAC permissions:
```go
sar := &authorizationv1.SubjectAccessReview{
    Spec: authorizationv1.SubjectAccessReviewSpec{
        User: userInfo.GetName(),
        ResourceAttributes: &authorizationv1.ResourceAttributes{
            Verb:     "use",
            Resource: "securitycontextconstraints",
            Name:     sccName,
        },
    },
}
```

## Resources for Agents

### Key Files to Reference
- `pkg/securitycontextconstraints/sccadmission/admission.go` - Main SCC admission logic
- `pkg/admission/imagepolicy/admission.go` - Image policy admission example
- `pkg/securitycontextconstraints/sccmatching/matcher.go` - SCC selection algorithm

### Useful Commands
```bash
# Full build and test
make

# Just verification
make verify

# Update generated code
make update-generated-deep-copies

# Specific package tests
go test ./pkg/securitycontextconstraints/... -v

# Check vendored dependencies
go mod verify
```

### External Documentation

- Kubernetes Admission Controllers: [https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- OpenShift SCC Documentation: [https://docs.openshift.com/container-platform/latest/authentication/managing-security-context-constraints.html](https://docs.openshift.com/container-platform/latest/authentication/managing-security-context-constraints.html)
- client-go Informers: [https://github.com/kubernetes/client-go/blob/master/examples/workqueue/main.go](https://github.com/kubernetes/client-go/blob/master/examples/workqueue/main.go)

## Review Checklist for Agents

Before submitting changes, verify:

- [ ] Unit tests added for new functionality  
- [ ] Existing tests pass: `make test`
- [ ] Code generation up to date: `make verify-generated-deep-copies`
- [ ] No manual edits to generated files
- [ ] Error messages include helpful context
- [ ] Field paths constructed correctly for validation errors
- [ ] RBAC integration tested for authorization changes
- [ ] Breaking changes documented and justified
- [ ] OWNERS approval required for sensitive packages

## Contact & Support

- **Issues**: [https://github.com/openshift/apiserver-library-go/issues](https://github.com/openshift/apiserver-library-go/issues)
- **Pull Requests**: Require OWNERS approval (see OWNERS file)
- **Slack**: OpenShift Kubernetes team channels
