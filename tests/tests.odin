// Aggregator package: exists so `odin test tests -all-packages` discovers and
// runs the tests of every subpackage. @(require) forces inclusion of packages
// this file does not otherwise reference. Run from the repo root — golden
// fixture paths are relative to the working directory.
package tests

@(require) import "../pgerr"
@(require) import "../pgproto"
@(require) import "../pgconn"
@(require) import "../pgmap"
@(require) import ".."
