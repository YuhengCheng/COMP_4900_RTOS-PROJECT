s.c is the secureboot implementation
put this in the same folder as
hash.bin -> hash of the kernel
publickey.bin-> publickey of dilithium 5
sign.bin -> signature generated offline
within the .efi should be EFI//boot//verif_kernel.efi
openssl dgst -sha3-512 -binary verif_kernel.efi > hash.bin

on an ubuntu image, download git and gcc arch linux gnu

clone edk git, write .inf file to build it all
define the package
link openquantum safe using cmake
build it, copy it to a sd card then load

gen_keys_generate keys
rsaboot.c was the benchmarking for rsa test
secure_boot.c was the benchmarking for openquantumsafe crystal dilithium 5 testing.
