#include "helpers.h"

// ============================================================
// CODM ESP — read-only kernel driver (derived from laith)
// IOCTL protocol must match um/client.cpp and common/protocol.h
// ============================================================

namespace driver {
    namespace codes {
        // FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FILE_SPECIAL_ACCESS
        constexpr ULONG attach =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG read =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG get_module =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG get_pid =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG batch_read =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG enum_modules =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);

        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
        SIZE_T information = 0;

        PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);
        if (!stack_irp || !irp->AssociatedIrp.SystemBuffer) {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        switch (stack_irp->Parameters.DeviceIoControl.IoControlCode) {
        case codes::attach:
            status = handle_attach(irp, &information);
            break;

        case codes::get_pid:
            status = handle_get_pid(irp, &information);
            break;

        case codes::get_module:
            status = handle_get_module(irp, &information);
            break;

        case codes::read:
            status = handle_read(irp, &information);
            break;

        case codes::batch_read:
            status = handle_batch_read(irp, stack_irp, &information);
            break;

        case codes::enum_modules:
            status = handle_enum_modules(irp, stack_irp, &information);
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            information = 0;
            break;
        }

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = information;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
}

// Real driver entry (called by kdmapper via IoCreateDriver)
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);

    // Initialize cache lock
    ExInitializeFastMutex(&cache_lock);

    // Device name
    UNICODE_STRING device_name = {};
    RtlInitUnicodeString(&device_name, L"\\Device\\laithdriver");

    PDEVICE_OBJECT device_object = nullptr;
    NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

    if (!NT_SUCCESS(status)) {
        debug_print("Failed to create device object\n");
        return status;
    }

    // Symbolic link
    UNICODE_STRING symbolic_link = {};
    RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\laithdriver");

    status = IoCreateSymbolicLink(&symbolic_link, &device_name);
    if (!NT_SUCCESS(status)) {
        debug_print("Failed to create symbolic link\n");
        IoDeleteDevice(device_object);
        return status;
    }

    // Buffered IO for small data transfers
    SetFlag(device_object->Flags, DO_BUFFERED_IO);

    driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

    ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

    debug_print("CODM ESP driver loaded\n");
    return STATUS_SUCCESS;
}

// Entry point (kdmapper calls this)
NTSTATUS DriverEntry() {
    debug_print("CODM ESP: DriverEntry called\n");

    UNICODE_STRING driver_name = {};
    RtlInitUnicodeString(&driver_name, L"\\Driver\\laithdriver");

    return IoCreateDriver(&driver_name, &driver_main);
}
