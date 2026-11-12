Found while inventorying goodqa#15745, 2026-11-11.

POST /v1/orgs/:org/agent-browsers/sessions with the user's GoodQA user token returns 403 forbidden "Use a granted organization agent key" (apps/api/src/modules/agent-browsers/service.ts browserProject refuses userTokenId). Under the user-token rule an agent acting as the owner should be able to lease its own browser without a separate agent key. This is likely an intentional step-up (grants are an admin decision), so removing it needs a sourced decision and a security review. Smallest safe subset: allow the owner's user token to open and control only leases it created itself, on origins within the owner's own grant policy, with the same audit, caps and revocation. Workaround today: a user token holding agent_browser_grants creates a key grant.

Related: GET /v1/orgs/:org/machines returns user_token_non_delegable (goodqa#15638).

Source: user:baab765b-d85c-46b4-b7b9-588eb912c770/829b74e2-581e-4887-a3f7-8b8e16a45701 "goodqa should have a proper internal rapidly usable parallel headed browser you can use and control" ; parent goodqa#15745.
