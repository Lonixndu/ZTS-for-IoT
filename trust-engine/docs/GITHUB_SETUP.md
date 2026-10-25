# GitHub setup

Use [START_HERE_WINDOWS.md](../START_HERE_WINDOWS.md), especially Steps 2-4 and 14.

The current target is the existing group repository `https://github.com/Lonixndu/ZTS-for-IoT.git`, with this component in the top-level `trust-engine` folder. Create `feature/adaptive-trust-integration`, copy the component into that folder, and place `integration/trust-engine-ci.yml` at the repository root as `.github/workflows/trust-engine.yml`.

Do not create another repository for this version, copy over another member's component, or commit local credentials/databases. The complete guide explains the commands, authentication, staging review and pull request.
