# Release Automation

The GitHub Actions workflow at [`.github/workflows/release.yml`](../.github/workflows/release.yml) runs the local parser tests, builds a source distribution and wheel, uploads the build artifacts, creates a GitHub Release, and publishes to PyPI through trusted publishing.

It runs automatically only for version tags matching `v*`. A maintainer can use **Run workflow** to test the build on demand, but that manual path never creates a GitHub Release or publishes to PyPI. The workflow contains no PyPI token; configure the project as a trusted publisher in PyPI and protect the `pypi` GitHub environment before creating a release tag.

> Test builds do not publish packages. Do not create a version tag until the release notes, package version, and PyPI trusted-publisher configuration have been reviewed.

## Release checklist

1. Update `pyproject.toml`, `hunt_sift/__init__.py`, and `CHANGELOG.md` with the intended version.
2. Run `python3 -m unittest discover -s tests -v` locally.
3. Confirm the examples and documentation contain no real targets, private artifacts, or credentials.
4. Configure PyPI trusted publishing for this repository and the `pypi` environment.
5. Create and push a reviewed tag such as `v0.5.0`.
