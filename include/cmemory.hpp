#ifndef CMEMORY_HPP
#define CMEMORY_HPP

#include <cstring>
#include <string>

#include <windows.h>

class CMemory
{
    private:
        HWND m_processHwnd;
        DWORD m_processId;
        HANDLE m_processHandle;

    public:
        CMemory();
        ~CMemory();

        void Close();

        HWND GetProcessHwnd();
        DWORD GetProcessId();
        HANDLE GetProcessHandle();

        void SetProcessHwnd(HWND hwnd);
        void SetProcessId(DWORD processId);
        void SetProcessHandle(HANDLE processHandle);

        void EnableDebugPrivileges();

        bool IsForegroundWindowCurrentProcessId();

        void SetProcessByHwnd(HWND hwnd);
        void SetProcessById(DWORD processId);

        DWORD SetProtection(DWORD address, DWORD type, unsigned int size);

        template <class T>
        void WriteAny(DWORD address, T value);

        template <class T>
        T ReadAny(DWORD address);

        void WriteChar(DWORD address, unsigned char* value, unsigned int size);

        void WriteString(DWORD address, std::string value);
        std::string ReadString(DWORD address, unsigned int size);

        void WriteNops(DWORD address, unsigned int size);

        template <class T>
        T ReadStructFromPointer(DWORD pointer);
};

CMemory::CMemory()
{
    EnableDebugPrivileges();
}

CMemory::~CMemory()
{
    Close();
}

void CMemory::Close()
{
    CloseHandle(m_processHandle);
}

HWND CMemory::GetProcessHwnd()
{
    return m_processHwnd;
}

DWORD CMemory::GetProcessId()
{
    return m_processId;
}

HANDLE CMemory::GetProcessHandle()
{
    return m_processHandle;
}

void CMemory::SetProcessHwnd(HWND hwnd)
{
    m_processHwnd = hwnd;
}

void CMemory::SetProcessId(DWORD processId)
{
    m_processId = processId;
}
void CMemory::SetProcessHandle(HANDLE processHandle)
{
    m_processHandle = processHandle;
}

void CMemory::EnableDebugPrivileges()
{
    HANDLE token;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        TOKEN_PRIVILEGES tp;
        TOKEN_PRIVILEGES tpPrevious;

        DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

        LUID luid;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        {
            tp.PrivilegeCount           = 1;
            tp.Privileges[0].Luid       = luid;
            tp.Privileges[0].Attributes = 0;

            AdjustTokenPrivileges
            (
                token,
                FALSE,
                &tp,
                sizeof(TOKEN_PRIVILEGES),
                &tpPrevious,
                &cbPrevious
            );

            tpPrevious.PrivilegeCount            = 1;
            tpPrevious.Privileges[0].Luid        = luid;
            tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    
            AdjustTokenPrivileges
            (
                token,
                FALSE,
                &tpPrevious,
                cbPrevious,
                NULL,
                NULL
            );
        }
    }

    CloseHandle(token);
}

bool CMemory::IsForegroundWindowCurrentProcessId()
{
    HWND foregroundHwnd = GetForegroundWindow();

    DWORD foregroundProcessId;
    GetWindowThreadProcessId(foregroundHwnd, &foregroundProcessId);

    return (foregroundProcessId == GetCurrentProcessId());
}

void CMemory::SetProcessByHwnd(HWND hwnd)
{
    m_processHwnd = hwnd;

    GetWindowThreadProcessId(m_processHwnd, &m_processId);

    m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, m_processId);
}

void CMemory::SetProcessById(DWORD processId)
{
    m_processId = processId;

    m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, m_processId);
}

DWORD CMemory::SetProtection(DWORD address, DWORD type, unsigned int size)
{
    DWORD oldProtection;
    VirtualProtectEx(m_processHandle, reinterpret_cast<void*>(address), size, type, &oldProtection);
    return oldProtection;
}

template <class T>
void CMemory::WriteAny(DWORD address, T value)
{
    WriteProcessMemory(m_processHandle, reinterpret_cast<void*>(address), &value, sizeof(value), 0);
}

template <class T>
T CMemory::ReadAny(DWORD address)
{
    T buffer;
    ReadProcessMemory(m_processHandle, reinterpret_cast<void*>(address), &buffer, sizeof(buffer), 0);
    return buffer;
}

void CMemory::WriteChar(DWORD address, unsigned char* value, unsigned int size)
{
    WriteProcessMemory(m_processHandle, reinterpret_cast<void*>(address), value, size, 0);
}

void CMemory::WriteString(DWORD address, std::string value)
{
    unsigned int j = 0;

    for (std::size_t i = 0; i < value.size(); i++)
    {
        WriteProcessMemory(m_processHandle, reinterpret_cast<void*>(address + j), &value[i], 1, 0);
        j++;
    }

    unsigned char nullTerminator = 0x00;
    WriteProcessMemory(m_processHandle, reinterpret_cast<void*>(address + j), &nullTerminator, sizeof(nullTerminator), 0);
}

std::string CMemory::ReadString(DWORD address, unsigned int size)
{
    char *buffer = new char[size + 1];

    ReadProcessMemory(m_processHandle, reinterpret_cast<void*>(address), buffer, size, 0);

    std::string result = buffer;

    delete[] buffer;

    return result;
}

void CMemory::WriteNops(DWORD address, unsigned int size)
{
    char *nops = new char[size];

    unsigned char nop = 0x90;

    for (unsigned int i = 0; i < size; i++)
    {
        std::memcpy(&nops, &nop, sizeof(nop));
    }

    WriteProcessMemory(m_processHandle, reinterpret_cast<void*>(address), &nops, sizeof(nops), 0);

    delete[] nops;
}

template <class T>
T CMemory::ReadStructFromPointer(DWORD pointer)
{
    DWORD address;
    ReadProcessMemory(m_processHandle, reinterpret_cast<void*>(pointer), &address, sizeof(address), 0);

    T structure;
    ReadProcessMemory(m_processHandle, reinterpret_cast<void*>(address), &structure, sizeof(structure), 0);
    return structure;
}

#endif // CMEMORY_HPP
