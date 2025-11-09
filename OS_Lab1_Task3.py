import platform
import os
import sys
import ctypes


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("dwOemId", ctypes.c_ulong),
        ("dwPageSize", ctypes.c_ulong),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_void_p),
        ("dwNumberOfProcessors", ctypes.c_ulong),
        ("dwProcessorType", ctypes.c_ulong),
        ("dwAllocationGranularity", ctypes.c_ulong),
        ("wProcessorLevel", ctypes.c_ushort),
        ("wProcessorRevision", ctypes.c_ushort),
    ]

class SysInfo:
    def __init__(self):
        """Инициализация класса с определением платформы"""
        self._platform = self._detect_platform()

    def _detect_platform(self):
        """Внутренняя функция определения платформы"""
        try:
            system_name = platform.system()
            if system_name == "Windows":
                return "windows"
            elif system_name == "Linux":
                return "linux"
            else:
                return "unknown"
        except Exception:
            return "error"

    def get_os_name(self):
        """Получение названия операционной системы"""
        try:
            os_name = platform.system()
            if os_name:
                return os_name
            else:
                # через sys.platform
                if sys.platform.startswith('win'):
                    return "Windows"
                elif sys.platform.startswith('linux'):
                    return "Linux"
                else:
                    return "Unknown"
        except Exception:
            return "Unknown"

    def get_os_version(self):
        """Получение версии операционной системы"""
        try:
            base_version = platform.version()

            if self._platform == "linux":
                # для Linux дистрибутивов
                try:
                    with open('/etc/os-release', 'r') as f:
                        for line in f:
                            if line.startswith('PRETTY_NAME='):
                                distro_info = line.split('=')[1].strip().strip('"')
                                return f"{base_version} ({distro_info})"
                except:
                    pass

            return base_version if base_version else "Unknown"

        except Exception:
            return "Unknown"

    def get_processor_count(self):
        """Получение количества логических процессоров"""
        try:
            cpu_count = os.cpu_count()
            if cpu_count is not None:
                return cpu_count

            if self._platform == "linux":
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        content = f.read()
                        return content.count('processor\t:')
                except:
                    return None
            elif self._platform == "windows":
                try:
                    system_info = SYSTEM_INFO()
                    ctypes.windll.kernel32.GetSystemInfo(ctypes.byref(system_info))
                    return system_info.dwNumberOfProcessors
                except:
                    return None
            else:
                return None

        except Exception:
            return None

    def get_free_memory(self):
        """Получение количества свободной оперативной памяти"""
        try:
            if self._platform == "windows":
                memory_status = MEMORYSTATUSEX()
                memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)

                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
                    return memory_status.ullAvailPhys
                return None

            elif self._platform == "linux":
                try:
                    with open('/proc/meminfo', 'r') as mem:
                        for line in mem:
                            if 'MemAvailable' in line:
                                return int(line.split()[1]) * 1024
                    return None
                except:
                    return None
            else:
                return None

        except Exception:
            return None

    def get_total_memory(self):
        """Получение общего количества оперативной памяти"""
        try:
            if self._platform == "windows":
                memory_status = MEMORYSTATUSEX()
                memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)

                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
                    return memory_status.ullTotalPhys
                return None

            elif self._platform == "linux":
                try:
                    with open('/proc/meminfo', 'r') as mem:
                        for line in mem:
                            if 'MemTotal' in line:
                                return int(line.split()[1]) * 1024
                    return None
                except:
                    return None
            else:
                return None

        except Exception:
            return None


def format_bytes(bytes_count):
    """Форматирует байты в читаемый вид"""
    if bytes_count is None:
        return "Error"

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0


def format_value(value):
    """Форматирует любое значение для вывода"""
    if value is None:
        return "Error"
    return str(value)


def main():
    info = SysInfo()

    # операционная система
    os_name = info.get_os_name()

    # версия операционной системы
    os_version = info.get_os_version()

    # количество логических процессоров
    processor_count = info.get_processor_count()

    # общий объем оперативной памяти
    total_memory = info.get_total_memory()

    # объем свободной оперативной памяти
    free_memory = info.get_free_memory()

    print(f"Operating System: {format_value(os_name)}")
    print(f"OS Version: {format_value(os_version)}")
    print(f"Processors: {format_value(processor_count)}")
    print(f"Total Memory: {format_bytes(total_memory)}")
    print(f"Free Memory: {format_bytes(free_memory)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)