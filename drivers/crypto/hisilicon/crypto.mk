ifeq ($(CFG_HISILICON_CRYPTO_DRIVER), y)
$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

$(call force, CFG_CRYPTO_DRV_ACIPHER,y,Mandated by CFG_HISILICON_CRYPTO_DRIVER)
$(call force, CFG_CRYPTO_DRV_HASH,y,Mandated by CFG_HISILICON_CRYPTO_DRIVER)
$(call force, CFG_CRYPTO_DRV_MAC,y,Mandated by CFG_HISILICON_CRYPTO_DRIVER)
$(call force, CFG_CRYPTO_DRV_CIPHER,y,Mandated by CFG_HISILICON_CRYPTO_DRIVER)
$(call force,CFG_CRYPTO_DRV_AUTHENC,y,Mandated by CFG_HISILICON_CRYPTO_DRIVER)
$(call force,CFG_CRYPTO_PBKDF2,y,Mandated by CFG_HISILICON_CRYPTO_DRIVER)
$(call force,CFG_CRYPTO_HW_PBKDF2,y,Mandated by CFG_HISILICON_CRYPTO_DRIVER)

ifeq ($(CFG_HISILICON_ACC_V3), y)
$(call force, CFG_CRYPTO_DRV_DH,y,Mandated by CFG_HISILICON_ACC_V3)
$(call force,CFG_CRYPTO_DRV_ECC,y,Mandated by CFG_HISILICON_ACC_V3)
$(call force,CFG_CRYPTO_DRV_RSA,y,Mandated by CFG_HISILICON_ACC_V3)
endif

endif
