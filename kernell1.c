#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <stdio.h>

#pragma warning(disable:4189)
#pragma warning(disable:4100)
#pragma warning(disable:4133)

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT g_ServerPort = NULL;
PFLT_PORT g_ClientPort = NULL;

UNICODE_STRING gBaitFilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\Downloads\\important.hwp");

VOID MiniFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_ClientPort) {
        FltCloseClientPort(gFilterHandle, &g_ClientPort);
    }

    if (g_ServerPort) {
        FltCloseCommunicationPort(g_ServerPort);
    }

    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
    }
}

NTSTATUS MiniFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

NTSTATUS CreateBaitFile(PFLT_FILTER Filter, PFLT_INSTANCE Instance)
{
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;

    InitializeObjectAttributes(&objAttr, &gBaitFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    return FltCreateFile(
        Filter,
        Instance,
        &fileHandle,
        GENERIC_WRITE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        0
    );
}

NTSTATUS ListFilesWithMinifilter(
    PFLT_FILTER Filter,
    PFLT_INSTANCE Instance,
    PUNICODE_STRING DirectoryPath,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnLength
)
{
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE dirHandle;
    NTSTATUS status;

    InitializeObjectAttributes(&objAttr, DirectoryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = FltCreateFile(
        Filter,
        Instance,
        &dirHandle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        0
    );

    if (!NT_SUCCESS(status)) return status;

    status = FltQueryDirectoryFile(
        Instance,
        dirHandle,
        OutputBuffer,
        OutputBufferLength,
        FileDirectoryInformation,
        TRUE,
        NULL,
        TRUE,
        NULL
    );

    if (NT_SUCCESS(status)) *ReturnLength = (ULONG)ioStatus.Information;

    ZwClose(dirHandle);
    return status;
}

NTSTATUS MiniFilterConnectNotify(
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG SizeOfContext,
    PVOID* ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    g_ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

NTSTATUS MiniFilterMessageNotify(
    PVOID PortCookie,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength
)
{
    UNREFERENCED_PARAMETER(PortCookie);

    UNICODE_STRING dirPath;
    RtlInitUnicodeString(&dirPath, (PWSTR)InputBuffer);

    CreateBaitFile(gFilterHandle, NULL); // NULL Instance로 호출됨, 필요 시 전달 방식 수정

    return ListFilesWithMinifilter(
        gFilterHandle,
        NULL,
        &dirPath,
        OutputBuffer,
        OutputBufferLength,
        ReturnOutputBufferLength
    );
}

FLT_PREOP_CALLBACK_STATUS MiniFilterPreWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    PFLT_FILE_NAME_INFORMATION fileInfo;
    NTSTATUS status;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
        &fileInfo
    );

    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltParseFileNameInformation(fileInfo);

    if (RtlCompareUnicodeString(&fileInfo->Name, &gBaitFilePath, TRUE) == 0) {
        FltReleaseFileNameInformation(fileInfo);

        if (g_ClientPort != NULL) {
            CHAR message[] = "RANSOMWARE_DETECTED";
            SIZE_T replyLength = 0;

            status = FltSendMessage(
                gFilterHandle,
                &g_ClientPort,
                message,
                sizeof(message),
                NULL,
                &replyLength,
                NULL
            );

            if (!NT_SUCCESS(status)) {
                DbgPrint("FltSendMessage failed: 0x%08X\n", status);
            }
        }
        else {
            DbgPrint("Client port is NULL. Message not sent.\n");
        }

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(fileInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_WRITE, 0, MiniFilterPreWriteOperation, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    MiniFilterUnload,
    MiniFilterInstanceSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&uniString, L"\\MiniFilterPort");
    InitializeObjectAttributes(&oa, &uniString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = FltCreateCommunicationPort(
        gFilterHandle,
        &g_ServerPort,
        &oa,
        NULL,
        MiniFilterConnectNotify,
        NULL,
        NULL,
        1
    );

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    return FltStartFiltering(gFilterHandle);
}
