# Sandbox check — what only this repository can lint in the docs.
#
# The shared documentation site checks the pages when a release is bumped into
# it (links, anchors, images, the Markdown). Three things it lets through are
# checked here, and each fails silently without this: front matter and the
# source paths a page's `code` list names; a colon that Jx reads as a directive
# and uses to delete the text after it; and a diagram with no alt text. The
# script says why for each.
#
#   nix build .#checks.<system>.docs-lint
{ pkgs, src }:
pkgs.runCommand "docs-lint-check"
  {
    nativeBuildInputs = [ (pkgs.python3.withPackages (ps: [ ps.pyyaml ])) ];
    checker = ./docs-lint.py;
    inherit src;
  }
  ''
    python3 -I $checker $src
    touch $out
  ''
