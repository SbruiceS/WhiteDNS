# Security policy

WhiteDNS is owned by Cosinfotech Solutions. Report a defect in the tool to sbruicesingh@haclon.in. Do not send attack traffic to prove a report.

Repository rules:

- `main` accepts changes only through a pull request.
- A pull request needs a review from the code owner.
- Force-push and deletion of `main` are rejected.
- Required status checks must pass before merge when a workflow is present.
- Signed commits are requested. Unsigned commits can still be blocked by the branch rule once signing is required in the GitHub setting.
- Secrets do not belong in the tree. A token pasted into a chat or a commit must be revoked.
- The license grants use, not the right to change the source. A fork is not an authorized release.

These files do not replace GitHub branch protection. Protection is set on the repository settings for `main`.
