# AUR Packaging

These files are templates for publishing Specter to the Arch User Repository.
Each AUR package lives in its own separate git repository, so do not push this
directory to AUR as-is.

## Package split

- `specter`: stable package built from tagged GitHub releases
- `specter-git`: rolling package built from the main branch

## Stable package flow

1. Create and push a tag such as `v0.1.0`.
2. Copy `packaging/aur/specter/PKGBUILD` into a clean local clone of your AUR
   repo named `specter`.
3. Run `updpkgsums` in that AUR repo.
4. Run `makepkg -si` to test the package locally.
5. Run `makepkg --printsrcinfo > .SRCINFO`.
6. Commit `PKGBUILD` and `.SRCINFO`, then push to AUR.

## VCS package flow

1. Copy `packaging/aur/specter-git/PKGBUILD` into a clean local clone of your
   AUR repo named `specter-git`.
2. Run `makepkg -si` to test the package locally.
3. Run `makepkg --printsrcinfo > .SRCINFO`.
4. Commit `PKGBUILD` and `.SRCINFO`, then push to AUR.

## Useful commands

```bash
git clone ssh://aur@aur.archlinux.org/specter.git
git clone ssh://aur@aur.archlinux.org/specter-git.git
makepkg -si
makepkg --printsrcinfo > .SRCINFO
namcap PKGBUILD .SRCINFO
```

## Notes

- `yay -S specter` only works after the `specter` AUR package exists.
- If the `specter` name is already taken, use a different package name such as
  `x3r0day-specter` or `specter-scanner`.
- The stable package should use a real checksum. Run `updpkgsums` before
  publishing it.
