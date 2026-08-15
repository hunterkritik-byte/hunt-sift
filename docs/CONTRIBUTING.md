# Contributing

Contributions should preserve Hunt Sift’s offline-first boundary. New importers may parse a user-selected local artifact and generate contextual review leads. They must not add scanners, request replay, target discovery, browser automation, payload generation, credential storage, shell execution, or automatic reporting.

Please include a small local fixture or temporary-file test for every parser change. Prefer observations that explain their uncertainty over labels that imply a confirmed vulnerability. Before opening a pull request, run `python3 -m unittest discover -s tests -v` and review the project security policy.
