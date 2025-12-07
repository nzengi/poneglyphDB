# Branch Protection Guide

## What is Branch Protection?

Branch protection is a GitHub feature that prevents the `main` branch from being accidentally or maliciously modified.

## Why is it Important?

1. **Force Push Protection**: Prevents accidentally breaking history with `git push --force`
2. **Deletion Protection**: Prevents the branch from being accidentally deleted
3. **Status Check Requirement**: Makes CI/CD tests mandatory before merging
4. **Code Review**: Requires pull requests to be reviewed before merging
5. **Linear History**: Ensures clean commit history

## How to Set Up on GitHub?

### Step 1: Repository Settings

1. Go to your GitHub repository
2. Click on the **Settings** tab
3. Click on **Branches** in the left menu

### Step 2: Add Branch Protection Rule

1. Click **Add rule** or **Add branch protection rule** button
2. Enter `main` in the **Branch name pattern** field

### Step 3: Protection Settings

Configure the following settings:

#### ✅ Basic Protections

- [x] **Require a pull request before merging**

  - [x] Require approvals: `1` (or more)
  - [x] Dismiss stale pull request approvals when new commits are pushed
  - [x] Require review from Code Owners (if you have a CODEOWNERS file)

- [x] **Require status checks to pass before merging**

  - [x] Require branches to be up to date before merging
  - Select status checks:
    - `CI` (ci.yml workflow)
    - `Clippy` (if there's a separate check)
    - `Tests` (if there's a separate check)

- [x] **Require conversation resolution before merging**

  - All comments in PR must be resolved

- [x] **Require signed commits** (optional but recommended)

  - Requires commits to be signed with GPG

- [x] **Require linear history**
  - Requires rebase instead of merge commits

#### ✅ Advanced Protections

- [x] **Do not allow bypassing the above settings**

  - Even admins cannot bypass these rules

- [x] **Restrict who can push to matching branches**

  - Only specific people/teams can push

- [x] **Allow force pushes** → ❌ **DISABLED**
- [x] **Allow deletions** → ❌ **DISABLED**

### Step 4: Save

- Click **Create** or **Save changes** button

## Recommended Settings (for PoneglyphDB)

```yaml
Branch: main
Protection Rules:
  ✅ Require pull request reviews (1 approval)
  ✅ Require status checks:
     - CI (ci.yml)
     - Code Coverage (coverage.yml)
  ✅ Require branches to be up to date
  ✅ Require conversation resolution
  ✅ Require linear history
  ✅ Do not allow bypassing
  ❌ Allow force pushes
  ❌ Allow deletions
```

## CODEOWNERS File (Optional)

You can create a `.github/CODEOWNERS` file in the repository root to require reviews for specific files:

```
# Global owners
* @nzengi

# Core ZKP code requires expert review
/poneglyphdb-core/src/zkp/ @nzengi
/poneglyphdb-core/src/circuit/ @nzengi

# Documentation
/docs/ @nzengi
README.md @nzengi
```

## Summary

After branch protection rules are configured:

- ✅ Direct pushes to `main` branch are blocked
- ✅ All changes must come through pull requests
- ✅ CI/CD tests must pass before merging
- ✅ At least 1 review is required
- ✅ Force push and deletion are prevented

This is a **mandatory** security measure for a secure project.
