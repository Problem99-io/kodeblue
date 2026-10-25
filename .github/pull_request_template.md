## What and why

<!-- What this changes, and the problem it solves. Link the issue: "Fixes #123". -->

## How it was tested

<!-- Tests added, and anything you ran by hand (on which distribution). -->

## Checklist

- [ ] `go vet ./...` and `go test ./...` pass
- [ ] A detection change has a test for the case it catches and, where it applies, the benign case it must not flag
- [ ] Agent prompts in `blue/` and the docs match the new behaviour
- [ ] The security model holds: servers only dial out, agents stay read-only, containment goes through the root helper and its policy
