# KeepassXC PKCS#11 support wrapper

This is a wrapper around [KeepassXC](https://keepassxc.org/) that allows to use PKCS#11 smart cards to decrypt Keepass
databases that are encrypted with the [CertKeyProvider](https://github.com/markbott/CertKeyProvider) plugin on Windows
Keepass2 installations.

The software has been tested with a [Telesec TCOS 3](https://www.telesec.de/de/produkte/tcos-smartcards/ueberblick/)
Net Key 3.0 smart cards on Ubuntu 21.10.

## Usage

Define the environment variable `PKCS11_LIB` with the path to your PKCS#11 module (i.e.
`/usr/lib/tcos_smartcard/libpkcs11tcos3NetKey64-1.8.0.so`). Run

`keepassxc-p11-wrapper <database>.kdbx`

You will be prompted for your smart card User PIN. If your certificate is found in the `<database>.p7mkey` file right
next to your `<database>.kdbx` KeepassXC will start and open the password database automatically.

### Configuration options

You can specify the PKCS#11 module that should be used by specifying the `-p11module` command line parameter or by
setting the environment variable `PKCS11_LIB` to the absolute file path of the module's .so file.

You may add a `-debug` command line parameter to enable more verbose output.

You may add a `-slot` command line parameter to specify a different smart card reader via its number (a list of
readers is printed when running with the `-debug` command line parameter). Look for lines like

`DEBU[0003] slot 0: Alcor Micro AU9540 00 00`

and use the number after `slot`. The first slot found is used by default.

## Build

To build the software you need [Go](https://go.dev/) >= 1.17. Run

`go build ./cmd/keepassxc-p11-wrapper`

to build the binary.

## License

The software is released under the terms of the MIT license as written in the [LICENSE](LICENSE) file.

A fork of https://github.com/paultag/go-pkcs7 is used until https://github.com/paultag/go-pkcs7/pull/1 is merged.
