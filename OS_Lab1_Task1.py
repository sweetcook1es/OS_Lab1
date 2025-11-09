import ctypes
from ctypes import wintypes
import sys
import os
import getpass


# основные функции ядра Windows (память, процессор, диски)
kernel32 = ctypes.windll.kernel32
# функции безопасности и реестра (имена пользователей)
advapi32 = ctypes.windll.advapi32
# функции для работы с системой производительности (файл подкачки)
psapi = ctypes.windll.psapi
# функция RtlGetVersion, информация о версии Windows
ntdll = ctypes.windll.ntdll


class MEMORYSTATUSEX(ctypes.Structure):
    """
    Структура MEMORYSTATUSEX для функции GlobalMemoryStatusEx()
    Содержит подробную информацию о физической и виртуальной памяти
    """
    _fields_ = [
        ("dwLength", wintypes.DWORD),  # Размер структуры в байтах
        ("dwMemoryLoad", wintypes.DWORD),  # Процент использования памяти (0-100)
        ("ullTotalPhys", ctypes.c_ulonglong),  # Общий объем физической памяти в байтах
        ("ullAvailPhys", ctypes.c_ulonglong),  # Доступная физическая память в байтах
        ("ullTotalPageFile", ctypes.c_ulonglong),  # Максимальный размер файла подкачки
        ("ullAvailPageFile", ctypes.c_ulonglong),  # Доступный размер файла подкачки
        ("ullTotalVirtual", ctypes.c_ulonglong),  # Общий объем виртуальной памяти
        ("ullAvailVirtual", ctypes.c_ulonglong),  # Доступная виртуальная память
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),  # Расширенная виртуальная память
    ]

    def __init__(self):
        """Автоматически устанавливает правильный размер структуры"""
        self.dwLength = ctypes.sizeof(self)
        super().__init__()


class PERFORMANCE_INFORMATION(ctypes.Structure):
    """
    Структура PERFORMANCE_INFORMATION для функции GetPerformanceInfo()
    Содержит информацию о производительности системы
    """
    _fields_ = [
        ("cb", wintypes.DWORD),  # Размер структуры в байтах
        ("CommitTotal", ctypes.c_size_t),  # Текущий объем выделенной памяти
        ("CommitLimit", ctypes.c_size_t),  # Максимальный объем памяти, который может быть выделен
        ("CommitPeak", ctypes.c_size_t),  # Пиковый объем выделенной памяти
        ("PhysicalTotal", ctypes.c_size_t),  # Общий объем физической памяти
        ("PhysicalAvailable", ctypes.c_size_t),  # Доступная физическая память
        ("SystemCache", ctypes.c_size_t),  # Размер системного кэша
        ("KernelTotal", ctypes.c_size_t),  # Общая память ядра
        ("KernelPaged", ctypes.c_size_t),  # Выгружаемая память ядра
        ("KernelNonpaged", ctypes.c_size_t),  # Невыгружаемая память ядра
        ("PageSize", ctypes.c_size_t),  # Размер страницы памяти в байтах
        ("HandleCount", wintypes.DWORD),  # Количество открытых handles
        ("ProcessCount", wintypes.DWORD),  # Количество процессов
        ("ThreadCount", wintypes.DWORD),  # Количество потоков
    ]

    def __init__(self):
        """Устанавливает размер структуры"""
        self.cb = ctypes.sizeof(self)
        super().__init__()


class OSVERSIONINFOEXW(ctypes.Structure):
    """
    Структура OSVERSIONINFOEXW для функции RtlGetVersion()
    Содержит подробную информацию о версии операционной системы
    """
    _fields_ = [
        ("dwOSVersionInfoSize", wintypes.DWORD),  # Размер структуры
        ("dwMajorVersion", wintypes.DWORD),  # Основной номер версии (10 для Windows 10/11)
        ("dwMinorVersion", wintypes.DWORD),  # Дополнительный номер версии
        ("dwBuildNumber", wintypes.DWORD),  # Номер сборки (важен для отличия Win10 и Win11)
        ("dwPlatformId", wintypes.DWORD),  # Идентификатор платформы
        ("szCSDVersion", wintypes.WCHAR * 128),  # Строка сервис-пака
        ("wServicePackMajor", wintypes.WORD),  # Основной номер сервис-пака
        ("wServicePackMinor", wintypes.WORD),  # Дополнительный номер сервис-пака
        ("wSuiteMask", wintypes.WORD),  # Маска набора продуктов
        ("wProductType", wintypes.BYTE),  # Тип продукта
        ("wReserved", wintypes.BYTE),  # Зарезервировано
    ]

    def __init__(self):
        """Устанавливает размер структуры"""
        self.dwOSVersionInfoSize = ctypes.sizeof(self)
        super().__init__()


class SYSTEM_INFO(ctypes.Structure):
    """
    Структура SYSTEM_INFO для функций GetSystemInfo() и GetNativeSystemInfo()
    Содержит информацию о системе и процессоре
    """
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),  # Архитектура процессора
        ("wReserved", wintypes.WORD),               # Зарезервировано
        ("dwPageSize", wintypes.DWORD),             # Размер страницы памяти
        ("lpMinimumApplicationAddress", ctypes.c_void_p),  # Минимальный адрес приложения
        ("lpMaximumApplicationAddress", ctypes.c_void_p),  # Максимальный адрес приложения
        ("dwActiveProcessorMask", ctypes.c_void_p),        # Маска активных процессоров
        ("dwNumberOfProcessors", wintypes.DWORD),   # Количество процессоров (ядер)
        ("dwProcessorType", wintypes.DWORD),        # Тип процессора (устарело)
        ("dwAllocationGranularity", wintypes.DWORD), # Гранулярность выделения памяти
        ("wProcessorLevel", wintypes.WORD),         # Уровень процессора
        ("wProcessorRevision", wintypes.WORD),      # Ревизия процессора
    ]


def get_os_version():
    """
    Получение версии операционной системы
    """
    try:
        version_info = OSVERSIONINFOEXW()

        # функция всегда возвращает реальную версию ОС
        if ntdll.RtlGetVersion(ctypes.byref(version_info)) != 0:
            return "Unknown Windows Version"

        major = version_info.dwMajorVersion # основная версия
        minor = version_info.dwMinorVersion # дополнительная версия
        build = version_info.dwBuildNumber # номер сборки

        if major == 10 and build >= 22000:
            return "Windows 11 or Greater"
        elif major >= 10:
            return "Windows 10 or Greater"
        elif major == 6 and minor >= 3:
            return "Windows 8.1 or Greater"
        elif major == 6 and minor >= 2:
            return "Windows 8 or Greater"
        elif major == 6 and minor >= 1:
            return "Windows 7 or Greater"
        elif major == 6:
            return "Windows Vista or Greater"
        elif major == 5 and minor >= 1:
            return "Windows XP or Greater"
        else:
            return f"Windows {major}.{minor}"

    except Exception:
        return "Unknown Windows Version"


def get_memory_info():
    """
    Получение подробной информации о физической и виртуальной памяти
    """
    try:
        memory_status = MEMORYSTATUSEX()

        # GlobalMemoryStatusEx для заполнения структуры данными
        if kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
            total_phys_mb = memory_status.ullTotalPhys // (1024 * 1024)
            avail_phys_mb = memory_status.ullAvailPhys // (1024 * 1024)
            used_phys_mb = total_phys_mb - avail_phys_mb
            memory_load = memory_status.dwMemoryLoad
            total_virtual_mb = memory_status.ullTotalVirtual // (1024 * 1024)

            return {
                'total_physical_mb': total_phys_mb, # всего памяти
                'available_physical_mb': avail_phys_mb, # свободно памяти
                'used_physical_mb': used_phys_mb, # занято памяти
                'memory_load': memory_load,  # уровень загрузки памяти
                'total_virtual_mb': total_virtual_mb # всего памяти (RAM + файлы подкачки)
            }
        else:
            return None
    except Exception:
        return None


def get_processor_info():
    """
    Получение информации о процессоре: количество ядер и архитектура
    """
    try:
        system_info = SYSTEM_INFO()

        try:
            kernel32.GetNativeSystemInfo(ctypes.byref(system_info))
        except:
            kernel32.GetSystemInfo(ctypes.byref(system_info))

        # сопоставляем числовые коды архитектуры с читаемыми названиями
        arch_map = {
            0: "x86",  # Intel x86 (32-битная)
            9: "x64 (AMD64)",  # AMD64 (64-битная)
            5: "ARM",  # ARM (32-битная)
            12: "ARM64",  # ARM64 (64-битная)
            6: "IA64"  # Intel Itanium
        }

        architecture = arch_map.get(system_info.wProcessorArchitecture, "Unknown")

        return {
            'cores': system_info.dwNumberOfProcessors, # количество ядер
            'architecture': architecture # название архитектуры
        }
    except Exception:
        return None


def get_computer_and_user_info():
    """
    Получение имени компьютера и текущего пользователя
    """
    try:
        # создаем переменную для хранения размера буфера
        computer_name = wintypes.DWORD()
        computer_name.value = 256

        # создаем буфер для хранения имени компьютера
        computer_name_buffer = ctypes.create_unicode_buffer(computer_name.value)

        if kernel32.GetComputerNameW(computer_name_buffer, ctypes.byref(computer_name)):
            computer_name_str = computer_name_buffer.value
        else:
            computer_name_str = "Unknown"


        # переменная окружения USERNAME
        username = os.environ.get('USERNAME')

        # модуль getpass
        if not username:
            try:
                username = getpass.getuser()
            except:
                username = "Unknown"

        # Win32 API
        if username == "Unknown":
            user_name = wintypes.DWORD(256)
            user_name_buffer = ctypes.create_unicode_buffer(user_name.value)

            # возвращает имя в формате DOMAIN\USERNAME
            if advapi32.GetUserNameW(user_name_buffer, ctypes.byref(user_name)):
                full_username = user_name_buffer.value
                if '\\' in full_username:
                    username = full_username.split('\\')[-1]
                else:
                    username = full_username

        return {
            'computer_name': computer_name_str, # имя компа
            'user_name': username # имя пользователя
        }
    except Exception:
        return None


def get_pagefile_info():
    """
    Получение информации о файле подкачки (pagefile)
    """
    try:
        perf_info = PERFORMANCE_INFORMATION()

        if psapi.GetPerformanceInfo(ctypes.byref(perf_info), ctypes.sizeof(perf_info)):
            # получаем размер страницы памяти
            page_size = perf_info.PageSize

            commit_total = perf_info.CommitTotal * page_size // (1024 * 1024)
            commit_limit = perf_info.CommitLimit * page_size // (1024 * 1024)

            return {
                'commit_total': commit_total,  # текущий размер файла подкачки + физ. память
                'commit_limit': commit_limit  # максимально возможный
            }
        else:
            return None
    except Exception:
        return None


def get_drive_info():
    """
    Получение информации о всех логических дисках в системе
    """
    try:
        drives = []

        # устанавливаем размер буфера
        buffer_size = 1024
        drive_buffer = ctypes.create_unicode_buffer(buffer_size)

        # для получения строки с путями дисков
        result = kernel32.GetLogicalDriveStringsW(
            buffer_size - 1,
            drive_buffer
        )

        if result == 0:
            return []

        # получаем строку с дисками и разбиваем по нулевым символам
        drive_string = drive_buffer.value
        drive_list = [drive for drive in drive_string.split('\x00') if drive.strip()]

        for drive in drive_list:
            try:
                free_bytes = ctypes.c_ulonglong(0)  # доступное место для текущего пользователя
                total_bytes = ctypes.c_ulonglong(0)  # общий размер диска
                total_free_bytes = ctypes.c_ulonglong(0)  # общее свободное место

                # получает информацию о свободном месте
                if kernel32.GetDiskFreeSpaceExW(
                        drive,  # путь к диску
                        ctypes.byref(free_bytes),
                        ctypes.byref(total_bytes),
                        ctypes.byref(total_free_bytes)
                ):

                    # создаем буферы для типа файловой системы и "имя" диска
                    fs_buffer = ctypes.create_unicode_buffer(32)  # типа ФС
                    volume_buffer = ctypes.create_unicode_buffer(256)  # "имя" диска

                    # получает подробную информацию о "имя" диска
                    fs_success = kernel32.GetVolumeInformationW(
                        drive,
                        volume_buffer,
                        ctypes.sizeof(volume_buffer),
                        None,  # серийный номер "имя" диска (не нужен)
                        None,  # Макс. длина компонента пути (не нужен)
                        None,  # Флаги файловой системы (не нужен)
                        fs_buffer,
                        ctypes.sizeof(fs_buffer)
                    )

                    fs_type = fs_buffer.value if fs_success and fs_buffer.value else "Unknown"

                    drives.append({
                        'drive': drive,
                        'total_gb': total_bytes.value // (1024 ** 3),
                        'free_gb': free_bytes.value // (1024 ** 3),
                        'fs_type': fs_type # тип файловой системы
                    })

            except Exception:
                continue

        return drives

    except Exception:
        return []



def main():
    # версия операционной системы
    os_version = get_os_version()
    print(f"OS: {os_version}")

    # имя компьютера и пользователя
    computer_user_info = get_computer_and_user_info()
    if computer_user_info:
        print(f"Computer Name: {computer_user_info['computer_name']}")
        print(f"User: {computer_user_info['user_name']}")

    # архитектура процессора
    processor_info = get_processor_info()
    if processor_info:
        print(f"Architecture: {processor_info['architecture']}")

    # информация о памяти
    memory_info = get_memory_info()
    if memory_info:
        print(f"RAM: {memory_info['used_physical_mb']}MB / {memory_info['total_physical_mb']}MB")
        print(f"Virtual Memory: {memory_info['total_virtual_mb']}MB")
        print(f"Memory Load: {memory_info['memory_load']}%")

    # информация о файле подкачки
    pagefile_info = get_pagefile_info()
    if pagefile_info:
        print(f"Pagefile: {pagefile_info['commit_total']}MB / {pagefile_info['commit_limit']}MB")

    # количество ядер
    if processor_info:
        print(f"Processors: {processor_info['cores']}")

    # информация о дисках
    drives = get_drive_info()
    if drives:
        print("Drives:")
        for drive in drives:
            print(
                f"  - {drive['drive']} ({drive['fs_type']}): {drive['free_gb']} GB free / {drive['total_gb']} GB total")



if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)