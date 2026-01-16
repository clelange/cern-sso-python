# Release Checklist

Use this checklist when preparing for a release.

## Pre-Release Steps

- [ ] **Update version numbers**
  - [ ] Update `__version__` in `src/cern_sso/__init__.py`
  - [ ] Update `version` in `pyproject.toml`
  - [ ] Ensure both versions match exactly

- [ ] **Update documentation**
  - [ ] Update `README.md` if any API changes
  - [ ] Update minimum CLI version if changed
  - [ ] Update usage examples if needed

- [ ] **Code quality**
  - [ ] Run `ruff check src/ tests/` - no errors
  - [ ] Run unit tests: `pytest tests/ --ignore=tests/integration/`
  - [ ] Run integration tests (if secrets available): `pytest tests/integration/`

- [ ] **Review changes**
  - [ ] Review `git diff main...<branch>` for breaking changes
  - [ ] Ensure all new features are documented
  - [ ] Check for any TODO or FIXME comments

## Release Steps

- [ ] **Merge to main**
  - [ ] Ensure all tests pass on main branch
  - [ ] Create pull request to merge feature branch to main
  - [ ] Wait for CI to pass
  - [ ] Merge pull request
  - [ ] Pull latest main: `git checkout main && git pull`

- [ ] **Create git tag**
  - [ ] Tag the release: `git tag -a v0.2.0 -m "Release v0.2.0 - Add keytab support"`
  - [ ] Push tag: `git push origin v0.2.0`

- [ ] **Create GitHub Release**
  - [ ] Go to https://github.com/clelange/cern-sso-python/releases/new
  - [ ] Choose the tag (e.g., v0.2.0)
  - [ ] Title: "v0.2.0"
  - [ ] Click "Generate release notes" button
  - [ ] Review and edit auto-generated notes if needed
  - [ ] Publish release

- [ ] **Wait for PyPI publishing**
  - [ ] Check workflow: https://github.com/clelange/cern-sso-python/actions/workflows/publish.yml
  - [ ] Wait for "Publish Python 🐍 distribution 📦 to PyPI" job to complete
  - [ ] Verify package appears: https://pypi.org/project/cern-sso-python/

## Post-Release Steps

- [ ] **Verify PyPI package**
  - [ ] Install from PyPI: `pip install cern-sso-python`
  - [ ] Test basic functionality
  - [ ] Check version: `python -c "import cern_sso; print(cern_sso.__version__)"`

- [ ] **Announce**
  - [ ] Update GitHub Discussions or Issues if needed
  - [ ] Update project documentation if applicable
  - [ ] Tag relevant issues/PRs with milestone

- [ ] **Prepare for next release**
  - [ ] Create new feature branch for next version
  - [ ] Update version to next dev version (optional)
