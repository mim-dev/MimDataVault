//
//  TODO.md
//  MimDataVault
//
//  Copyright (c) 2025 Luther Stanton
//
//  This source code is licensed under the MIT license found in the
//  LICENSE file in the root directory of this source tree.
//
  

# TODO

A running list of tasks and polish items for this project.
(Use ✅ for done, ⬜ for pending, ➡️ for in-progress.)

---

## Code Tasks
- ➡️Implement core KEK/DEK encryption logic
- ⬜ Add unit tests for `kekExists` and related helpers
- ⬜ Review string formatting helpers (`kekTag`, etc.)
- ⬜ Audit `private` vs `internal` scope for helpers
- ⬜ Verify error handling granularity (separate `do/catch` blocks)

---

## Documentation
- ⬜ Add `CONTRIBUTING.md`
  - Document function parameter conventions (labels vs `_`)
  - Commit message and branching guidelines
  - Style guide (naming, formatting, etc.)
- ⬜ Add `README.md` usage examples
- ⬜ Inline doc comments for public functions

---

## Project Hygiene
- ⬜ Establish SwiftLint rules (formatting, naming)
- ⬜ Set up CI for builds & tests
- ⬜ Add license header to source files
- ⬜ Add versioning / changelog process

---

## Future Enhancements
- ⬜ Explore property wrappers for tagged keys
- ⬜ Add benchmarking to measure KEK/DEK performance
- ⬜ Consider moving helpers into a small internal utility module
- ⬜ Profile in Release to confirm inlining behavior

---
