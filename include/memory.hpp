#ifndef MEMORY_HPP
#define MEMORY_HPP

#include <string>

#include <windows.h>

class memory
{
    private:
        HWND m_process_hwnd;
        DWORD m_process_id;
        HANDLE m_process_handle;

    public:
        memory();
        ~memory();

        void close();

        HWND get_process_hwnd();
        DWORD get_process_id();
        HANDLE get_process_handle();

        void set_process_hwnd(HWND hwnd);
        void set_process_id(DWORD process_id);
        void set_process_handle(HANDLE process_handle);

        void enable_debug_privileges();

        bool is_foreground_window_current_process_id();

        void set_process_by_hwnd(HWND hwnd);
        void set_process_by_id(DWORD process_id);

        DWORD set_protection(DWORD address, DWORD type, int size);

        template <class T>
        void write_any(DWORD address, T value);

        template <class T>
        T read_any(DWORD address);

        void write_char(DWORD address, unsigned char* value, int size);

        void write_string(DWORD address, std::string value);
        std::string read_string(DWORD address, int size);

        void write_nops(DWORD address, int size);
};

memory::memory()
{
    enable_debug_privileges();
}

memory::~memory()
{
    close();
}

void memory::close()
{
    CloseHandle(m_process_handle);
}

HWND memory::get_process_hwnd() { return m_process_hwnd; }

DWORD memory::get_process_id() { return m_process_id; }

HANDLE memory::get_process_handle() { return m_process_handle; }

void memory::set_process_hwnd(HWND hwnd) { m_process_hwnd = hwnd; }
void memory::set_process_id(DWORD process_id) { m_process_id = process_id; }
void memory::set_process_handle(HANDLE process_handle) { m_process_handle = process_handle; }

void memory::enable_debug_privileges()
{
    HANDLE token;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        TOKEN_PRIVILEGES tp;
        TOKEN_PRIVILEGES tp_previous;

        DWORD cb_previous = sizeof(TOKEN_PRIVILEGES);

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
                &tp_previous,
                &cb_previous
            );

            tp_previous.PrivilegeCount            = 1;
            tp_previous.Privileges[0].Luid        = luid;
            tp_previous.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    
            AdjustTokenPrivileges
            (
                token,
                FALSE,
                &tp_previous,
                cb_previous,
                NULL,
                NULL
            );
        }
    }

    CloseHandle(token);
}

bool memory::is_foreground_window_current_process_id()
{
    HWND foreground_hwnd = GetForegroundWindow();

    DWORD foreground_process_id;
    GetWindowThreadProcessId(foreground_hwnd, &foreground_process_id);

    if (foreground_process_id != GetCurrentProcessId())
    {
        return false;
    }

    return true;
}

void memory::set_process_by_hwnd(HWND hwnd)
{
    m_process_hwnd = hwnd;

    GetWindowThreadProcessId(m_process_hwnd, &m_process_id);

    m_process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, m_process_id);
}

void memory::set_process_by_id(DWORD process_id)
{
    m_process_id = process_id;

    m_process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, m_process_id);
}

DWORD memory::set_protection(DWORD address, DWORD type, int size)
{
    DWORD old_protection;
    VirtualProtectEx(m_process_handle, reinterpret_cast<void*>(address), size, type, &old_protection);
    return old_protection;
}

template <class T>
void memory::write_any(DWORD address, T value)
{
    WriteProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &value, sizeof(value), 0);
}

template <class T>
T memory::read_any(DWORD address)
{
    T buffer;
    ReadProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &buffer, sizeof(buffer), 0);
    return buffer;
}

void memory::write_char(DWORD address, unsigned char* value, int size)
{
    WriteProcessMemory(m_process_handle, reinterpret_cast<void*>(address), value, size, 0);
}

void memory::write_string(DWORD address, std::string value)
{
    int j = 0;
    for(unsigned int i = 0; i < value.size(); i++)
    {
        WriteProcessMemory(m_process_handle, reinterpret_cast<void*>(address + j), &value[i], 1, 0);
        j++;
    }

    unsigned char null_terminator = 0x00;
    WriteProcessMemory(m_process_handle, reinterpret_cast<void*>(address + j), &null_terminator, sizeof(null_terminator), 0);
}

std::string memory::read_string(DWORD address, int size)
{
    char *buffer = new char[size + 1];

    ReadProcessMemory(m_process_handle, reinterpret_cast<void*>(address), buffer, size, 0);

    std::string result = buffer;

    delete[] buffer;

    return result;
}

void memory::write_nops(DWORD address, int size)
{
    char *nops = new char[size];

    unsigned char nop = 0x90;

    for (int i = 0; i < size; i++)
    {
        memcpy(&nops, &nop, sizeof(nop));
    }

    WriteProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &nops, sizeof(nops), 0);

    delete[] nops;
}

#endif // MEMORY_HPP
