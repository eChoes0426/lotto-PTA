global-incdirs-y += .

srcs-y += crypto_vrf.c
srcs-y += crypto_verify.c
srcs-y += ed25519_ref10.c
srcs-y += prove.c
srcs-y += verify.c
srcs-y += keypair.c
srcs-y += randombytes.c
srcs-y += sha512EL.c
srcs-y += convert.c


cflags-remove-y += -Wold-style-definition
cflags-remove-y += -Wswitch-default
cflags-remove-y += -Wstrict-prototypes
cflags-y += $(call cc-option,-Wno-deprecated-non-prototype)
