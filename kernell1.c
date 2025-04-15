#include <stdio.h>
#include <ntddk.h>
#include "header.h"

//���� ��� ��ȸ
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
    UNICODE_STRING fileName = *DirectoryPath;
    PFILE_OBJECT fileObject = NULL;

    InitializeObjectAttributes(&objAttr,
        &fileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    // ���͸� ����
    status = FltCreateFile(Filter,
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
        0);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ���͸����� ���� ��� ��ȸ
    status = FltQueryDirectoryFile(Instance,
        dirHandle,
        NULL,
        NULL,
        &ioStatus,
        OutputBuffer,
        OutputBufferLength,
        FileDirectoryInformation,
        TRUE,
        NULL,
        TRUE);

    if (NT_SUCCESS(status)) {
        *ReturnLength = (ULONG)ioStatus.Information;
    }

    ZwClose(dirHandle);
    return status;
}

//Communication Port ����
PFLT_PORT g_ServerPort = NULL;
PFLT_PORT g_ClientPort = NULL;

NTSTATUS MiniFilterConnectNotify(
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG SizeOfContext,
    PVOID* ConnectionCookie
)
{
    g_ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

//���� ��û ó��
NTSTATUS MiniFilterMessageNotify(
    PVOID PortCookie,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength
)
{
    UNICODE_STRING dirPath;
    RtlInitUnicodeString(&dirPath, (PWSTR)InputBuffer);

    return ListFilesWithMinifilter(
        gFilterHandle,      // ��ϵ� ���� �ڵ�
        gInstance,          // ��û�� ������ �ν��Ͻ�
        &dirPath,
        OutputBuffer,
        OutputBufferLength,
        ReturnOutputBufferLength
    );
}

