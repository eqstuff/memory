#ifndef MEMORY_HPP
#define MEMORY_HPP

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
        memory(DWORD process_id);

        void close();

        HWND get_process_hwnd();
        DWORD get_process_id();
        HANDLE get_process_handle();

        void set_process_hwnd(HWND hwnd);
        void set_process_id(DWORD process_id);
        void set_process_handle(HANDLE process_handle);

        void enable_debug_privileges();

        void set_process_by_hwnd(HWND hwnd);
        void set_process_by_id(DWORD process_id);

        DWORD set_protection(DWORD address, DWORD type, int size);

        template <class T>
        T read_any(DWORD address);

        void write_bytes(DWORD address, int value, int size);
        int read_bytes(DWORD address, int size);

        void write_float(DWORD address, float value);
        float read_float(DWORD address);

        void write_double(DWORD address, double value);
        double read_double(DWORD address);

        void write_char(DWORD address, unsigned char* value, int size);

        void write_string(DWORD address, std::string value);
        std::string read_string(DWORD address, int size);

        void write_nops(DWORD address, int size);
};

memory::memory()
{
    //
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
    HANDLE hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        TOKEN_PRIVILEGES tpPrevious;
        DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        {
            tp.PrivilegeCount           = 1;
            tp.Privileges[0].Luid       = luid;
            tp.Privileges[0].Attributes = 0;

            AdjustTokenPrivileges
            (
                hToken,
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
                hToken,
                FALSE,
                &tpPrevious,
                cbPrevious,
                NULL,
                NULL
            );
        }
    }

    CloseHandle(hToken);
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
T memory::read_any(DWORD address)
{
        T buffer;
        ReadProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &buffer, sizeof(buffer), 0);
        return buffer;
}

void memory::write_bytes(DWORD address, int value, int size)
{
    WriteProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &value, size, 0);
}

int memory::read_bytes(DWORD address, int size)
{
        int buffer;
        ReadProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &buffer, size, 0);
        return buffer;
}

void memory::write_float(DWORD address, float value)
{
    WriteProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &value, sizeof(value), 0);
}

float memory::read_float(DWORD address)
{
        float buffer;
        ReadProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &buffer, sizeof(buffer), 0);
        return buffer;
}

void memory::write_double(DWORD address, double value)
{
    WriteProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &value, sizeof(value), 0);
}

double memory::read_double(DWORD address)
{
        double buffer;
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
        //char * buffer;
        //buffer = (char*)malloc((sizeof(char) * size) + 1);

        char buffer[size];
        ReadProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &buffer, sizeof(buffer), 0);
        return buffer;
}

void memory::write_nops(DWORD address, int size)
{
        char nops[size];

        unsigned char nop = 0x90;

        for (int i = 0; i < size; i++)
        {
            memcpy(&nops, &nop, sizeof(nop));
        }

        WriteProcessMemory(m_process_handle, reinterpret_cast<void*>(address), &nops, sizeof(nops), 0);
}

#endif // MEMORY_HPP
