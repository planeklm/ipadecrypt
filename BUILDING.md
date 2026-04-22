# Building ipadecrypt

ipadecrypt has two parts:

- **`ipadecrypt` CLI** - Go binary that runs on your computer.
- **Helper** - a small arm64 iOS binary (`helper.arm64`) that runs on the jailbroken device. Consumed by the CLI using `go:embed`.

For regular development you only need the CLI; the prebuilt helper is committed at `internal/device/helper.arm64`. Rebuilding the helper requires Docker.

## Prerequisites

### CLI only (cross-platform)

- Go 1.25+

### Helper

The helper is built inside a prebuilt Docker image published at `ghcr.io/londek/ipadecrypt-toolchain:latest` (~750 MB). The image is defined by [`helper/Dockerfile`](helper/Dockerfile) and pushed by the `toolchain` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) on every CI run - tagged by the Dockerfile's hash, plus `:latest` on `main`.

What's inside:

- `clang` + `lld` (from [apt.llvm.org](https://apt.llvm.org))
- [`ldid`](https://github.com/ProcursusTeam/ldid) (Procursus fork) for ad-hoc iOS code signing
- iPhoneOS SDK from [`xybp888/iOS-SDKs`](https://github.com/xybp888/iOS-SDKs), trimmed to what this project needs

The image is version-pinned via `ARG`s at the top of the Dockerfile (`LLVM_VERSION`, `LDID_REV`, `SDKS_COMMIT`, `SDK_VERSION`, `IOS_DEPLOYMENT_TARGET`). Because the build always runs on `linux/amd64` - via Rosetta / QEMU on Apple Silicon, natively on Linux - the compiler binary is the same bytes everywhere, and so is its output. That's what makes the drift check meaningful.

## Build the CLI

```sh
go build -o ipadecrypt ./cmd/ipadecrypt
```

For an optimized release-style build:

```sh
go build -trimpath -ldflags="-s -w" -o ipadecrypt ./cmd/ipadecrypt
```

This reuses `internal/device/helper.arm64` from the repo - no iOS toolchain needed.

## Build the helper

Only needed when you change `helper/helper.c` or `helper/entitlements.plist`.

```sh
./helper/build.sh
```

Produces `helper/dist/helper.arm64`. Copy it into place for `go:embed`:

```sh
cp helper/dist/helper.arm64 internal/device/helper.arm64
```

First run pulls the published toolchain image (~750 MB, 1–2 min from GHCR's CDN). Subsequent runs hit Docker's local image cache and are seconds.

Inside the container, `clang` compiles `helper.c` with `-target arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}`, `ld64.lld` links the Mach-O, and `ldid` signs it with the entitlements. The entitlements grant `task_for_pid-allow` and `get-task-allow`, which is how the helper gets at the target app's task port on-device.

## The drift check

CI (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the exact same `./helper/build.sh` - same Dockerfile, same pinned toolchain, same container - and byte-compares the fresh output against the committed `internal/device/helper.arm64`. If they don't match, the PR fails with `helper.arm64 drift detected`.

In practice this means: **if you touch `helper.c` or `entitlements.plist`, rebuild and commit the new `internal/device/helper.arm64` in the same PR**. If you don't, CI catches it.

The drift is meaningful because the canonical build environment is reproducible, not because we got lucky - the whole point of the container is that there's no difference between your build and CI's.

## Bumping the toolchain

When you want to pull in a newer LLVM, a newer SDK, or a newer ldid:

1. Edit the relevant `ARG` in [`helper/Dockerfile`](helper/Dockerfile).
2. Build the image locally (published `:latest` still reflects the old Dockerfile until your PR merges):

   ```sh
   IPADECRYPT_TOOLCHAIN_IMAGE=build ./helper/build.sh
   ```
3. `cp helper/dist/helper.arm64 internal/device/helper.arm64`
4. Commit `Dockerfile` and `internal/device/helper.arm64` together, push PR.
5. CI's `toolchain` job rebuilds and publishes the new image under a Dockerfile-hash tag. The `helper` job then pulls that exact image and runs the drift check. PR goes green when the committed `helper.arm64` matches what CI built from the new image.
6. On merge to `main`, the toolchain job additionally retags the image as `:latest`. Local `./helper/build.sh` invocations pick up the new image automatically on next run.

## First-time publishing setup

The toolchain image has to exist in GHCR before anyone can pull it. One-time setup by the repo owner:

1. Push the CI workflow to `main` (or trigger CI via any PR). The `toolchain` job builds and pushes the image to GHCR as part of the CI run.
2. Go to `https://github.com/<owner>?tab=packages`, find `ipadecrypt-toolchain`, Package settings → **Change visibility → Public**. After this, anyone can `docker pull` without auth.
