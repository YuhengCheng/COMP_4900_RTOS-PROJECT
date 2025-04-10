#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/FileHandleLib.h>
#include <Library/ShellCEntryLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <oqs/oqs.h>

#define LOAD_FROM_FILE(filename, buffer, size) \
    LoadFile(ImageHandle, filename, (VOID**)&buffer, &size)

EFI_STATUS
LoadFile(
    EFI_HANDLE ImageHandle,
    CHAR16 *FileName,
    VOID **Buffer,
    UINTN *BufferSize
) {
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Volume;
    EFI_FILE_PROTOCOL *Root, *File;
    EFI_STATUS Status;

    Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);
    if (EFI_ERROR(Status)) return Status;

    Status = gBS->HandleProtocol(LoadedImage->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID**)&Volume);
    if (EFI_ERROR(Status)) return Status;

    Status = Volume->OpenVolume(Volume, &Root);
    if (EFI_ERROR(Status)) return Status;

    Status = Root->Open(Root, &File, FileName, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) return Status;

    // Get file size
    EFI_FILE_INFO *FileInfo;
    UINTN InfoSize = sizeof(EFI_FILE_INFO) + 200;
    FileInfo = AllocateZeroPool(InfoSize);
    Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, FileInfo);
    if (EFI_ERROR(Status)) {
        File->Close(File);
        return Status;
    }

    *BufferSize = FileInfo->FileSize;
    *Buffer = AllocateZeroPool(*BufferSize);
    if (*Buffer == NULL) {
        File->Close(File);
        return EFI_OUT_OF_RESOURCES;
    }

    Status = File->Read(File, BufferSize, *Buffer);
    File->Close(File);
    return Status;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    EFI_STATUS Status;

    OQS_SIG *sig = OQS_SIG_new("Dilithium5");
    if (sig == NULL) {
        Print(L"OQS Dilithium5 init failed.\n");
        return EFI_ABORTED;
    }

    // Load boot image hash
    uint8_t *boot_image_hash;
    UINTN hash_len;
    Status = LOAD_FROM_FILE(L"hash.bin", boot_image_hash, hash_len);
    if (EFI_ERROR(Status)) {
        Print(L"Failed to load hash.bin: %r\n", Status);
        return Status;
    }

    // Load public key
    uint8_t *public_key;
    UINTN pubkey_len;
    Status = LOAD_FROM_FILE(L"publickey.bin", public_key, pubkey_len);
    if (EFI_ERROR(Status) || pubkey_len != OQS_SIG_dilithium_5_length_public_key) {
        Print(L"Failed to load publickey.bin\n");
        return Status;
    }

    // Load signature
    uint8_t *signature;
    UINTN sig_len;
    Status = LOAD_FROM_FILE(L"sig.bin", signature, sig_len);
    if (EFI_ERROR(Status) || sig_len != OQS_SIG_dilithium_5_length_signature) {
        Print(L"Failed to load sig.bin\n");
        return Status;
    }

    // Verify
    int ret = OQS_SIG_verify(sig, boot_image_hash, hash_len, signature, sig_len, public_key);
    if (ret == OQS_SUCCESS) {
        Print(L"Signature verified.\n");

        // Load verified payload
        EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
        Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);
        if (EFI_ERROR(Status)) return Status;

        CHAR16 *NextImagePath = L"\\EFI\\BOOT\\verif_kernel.efi";
        EFI_DEVICE_PATH_PROTOCOL *DevicePath = FileDevicePath(LoadedImage->DeviceHandle, NextImagePath);
        if (DevicePath == NULL) {
            Print(L"Failed to construct device path.\n");
            return EFI_NOT_FOUND;
        }

        EFI_HANDLE NextImageHandle;
        Status = gBS->LoadImage(FALSE, ImageHandle, DevicePath, NULL, 0, &NextImageHandle);
        if (EFI_ERROR(Status)) {
            Print(L"Image load failed: %r\n", Status);
            return Status;
        }

        Status = gBS->StartImage(NextImageHandle, NULL, NULL);
        if (EFI_ERROR(Status)) {
            Print(L"Image Start failed: %r\n", Status);
            return Status;
        }

    } else {
        Print(L"Signature verification failed.\n");
        Status = EFI_SECURITY_VIOLATION;
    }

    // Free resources
    OQS_SIG_free(sig);
    FreePool(boot_image_hash);
    FreePool(public_key);
    FreePool(signature);

    return Status;
}
