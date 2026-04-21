<div align="center">

# ipadecrypt

**End-to-end FairPlay decrypter for App Store apps.**
*Give it a bundle ID, get a decrypted `.ipa`. And yes - it happily decrypts iOS 26 apps.*

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat-square&logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/platform-macOS-000?style=flat-square&logo=apple)](https://www.apple.com/macos/)
[![iOS](https://img.shields.io/badge/iOS-14--26-007AFF?style=flat-square&logo=ios)](https://www.apple.com/ios/)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](#license)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/londek/ipadecrypt/pulls)

<img width="80%" src="https://github.com/user-attachments/assets/ba8dbd32-a2fb-49cc-afee-3aa88050718e" />

</div>

---

```sh
ipadecrypt bootstrap
ipadecrypt decrypt com.example.app
```

## The trick

You don't have to *run* an encrypted iOS app to decrypt it. After `posix_spawn` with `POSIX_SPAWN_START_SUSPENDED`, grab a `task_for_pid` port, and `mach_vm_read` the `__TEXT` segment. The kernel's fault handler runs FairPlay's decrypter on the target's behalf and hands back plaintext. So we kind of simplified the problem of decrypting .ipa to bare minimum. It's my braindead way of calling `mremap_encrypted` without `mremap_encrypted`.

## Requirements

### On your Mac
- macOS (Apple Silicon or Intel)
- Go 1.24+ for building from source
- Jailbroken iPhone

### On the jailbroken iPhone / iPad
All installable through Sileo:

| Package | Purpose |
|---|---|
| **OpenSSH** | SSH server - ipadecrypt drives the device over SSH |
| **AppSync Unified** | Bypasses installd's signature check (add repo `https://lukezgd.github.io/repo`) |
| **appinst** | Installs modified IPAs on the device |
| **zip** | Packages the decrypted IPA on-device |

> Tested on iOS 16.7.11 / palera1n rootless / iPhone 8 Plus. iOS 14 through 17 on A10–A14 devices are expected to work.

## Install

Download a prebuilt binary from the [releases page](https://github.com/londek/ipadecrypt/releases/latest).

Using go install:

```sh
go install github.com/londek/ipadecrypt/cmd/ipadecrypt@latest
```

From source:

```sh
git clone https://github.com/londek/ipadecrypt
cd ipadecrypt
go build ./cmd/ipadecrypt
```

## Usage

### First-time setup

```sh
ipadecrypt bootstrap
```

A four-step interactive wizard:

1. **App Store sign-in** - prompts for Apple ID; handles 2FA. Credentials stay local in `~/.ipadecrypt/config.json`.
2. **Device connect** - SSH host / user / password; probes iOS version + arch.
3. **Prerequisites** - verifies AppSync, `appinst`, and `zip` are installed.
4. **Helper install** - uploads a small embedded helper binary.

### Decrypt an app

```sh
ipadecrypt decrypt <bundle-id>
```

## License

MIT.

## Prior art

- [majd/ipatool](https://github.com/majd/ipatool) - the Apple Configurator impersonation the App Store client is based on.
- [34306/TrollDecryptJB](https://github.com/34306/TrollDecryptJB) - `task_for_pid` + `mach_vm_read` from a suspended spawn, entitlement set.
- [akemin-dayo/AppSync](https://github.com/akemin-dayo/AppSync) - installd signature-bypass tweak + `appinst`.
- [JohnCoates/flexdecrypt](https://github.com/JohnCoates/flexdecrypt) - the pre-iOS-16 approach that stopped working and prompted the pivot.

## AI Disclaimer

This project was developed with the assistance of AI tools. While I can't guarantee the accuracy of all AI-generated content, I have overviewed creation process and then reviewed, tested the code to ensure it meets the project's requirements.
