import os
import platform
import socket
import ctypes
import subprocess
import pwd
import sys


def get_os_info():
    """Информация о дистрибутиве"""
    try:
        with open('/etc/os-release', 'r') as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith('PRETTY_NAME'):
                    return line.split('=')[1].strip().strip('"')
    except:
        pass

    try:
        # через утилиту lsb_release
        result = subprocess.run(['lsb_release', '-d'], capture_output=True, text=True, check=True)
        if result.returncode == 0:
            return result.stdout.split(':')[1].strip()
    except:
        pass

    # через platform
    return f"{platform.system()} {platform.release()}"


def get_kernel_info():
    """Информация о ядре"""
    return platform.release()


def get_architecture():
    """Архитектура процессора"""
    return platform.machine()


def get_hostname():
    """Имя хоста"""
    return socket.gethostname()


def get_current_user():
    """Текущий пользователь"""
    try:
        return os.getlogin()
    except OSError:
        try:
            # получает информацию о пользователе по User ID
            return pwd.getpwuid(os.getuid())[0]
        except:
            # переменная окружения USER
            return os.environ.get('USER', 'unknown')


def get_memory_info():
    """Информация о памяти"""
    mem_info = {}
    try:
        # содержит подробную информацию о памяти
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    # общая оперативная память
                    mem_info['ram_total'] = int(line.split()[1]) // 1024
                elif line.startswith('MemAvailable:'):
                    # доступная оперативная память
                    mem_info['ram_free'] = int(line.split()[1]) // 1024
                elif line.startswith('SwapTotal:'):
                    # общий размер swap-раздела
                    mem_info['swap_total'] = int(line.split()[1]) // 1024
                elif line.startswith('SwapFree:'):
                    # свободное место в swap
                    mem_info['swap_free'] = int(line.split()[1]) // 1024

                if all(key in mem_info for key in ['ram_total', 'ram_free', 'swap_total', 'swap_free']):
                    break
    except:
        mem_info = get_memory_info_syscall()

    return mem_info


def get_memory_info_syscall():
    """через sysinfo syscall"""

    class SysInfo(ctypes.Structure):
        _fields_ = [
            ('uptime', ctypes.c_long),  # Время работы системы в секундах
            ('loads', ctypes.c_ulong * 3),  # Загрузка системы за 1, 5 и 15 минут
            ('totalram', ctypes.c_ulong),  # Общая оперативная память
            ('freeram', ctypes.c_ulong),  # Свободная оперативная память
            ('sharedram', ctypes.c_ulong),  # Разделяемая память
            ('bufferram', ctypes.c_ulong),  # Память в буферах
            ('totalswap', ctypes.c_ulong),  # Общий swap
            ('freeswap', ctypes.c_ulong),  # Свободный swap
            ('procs', ctypes.c_ushort),  # Количество процессов
            ('pad', ctypes.c_ushort),  # Выравнивание
            ('totalhigh', ctypes.c_ulong),  # Общая high memory
            ('freehigh', ctypes.c_ulong),  # Свободная high memory
            ('mem_unit', ctypes.c_uint)  # Размер единицы памяти в байтах
        ]

    try:
        libc = ctypes.CDLL('libc.so.6')
        info = SysInfo()
        if libc.sysinfo(ctypes.byref(info)) == 0:
            mem_unit = info.mem_unit if info.mem_unit > 0 else 1
            return {
                'ram_total': (info.totalram * mem_unit) // (1024 * 1024),
                'ram_free': (info.freeram * mem_unit) // (1024 * 1024),
                'swap_total': (info.totalswap * mem_unit) // (1024 * 1024),
                'swap_free': (info.freeswap * mem_unit) // (1024 * 1024)
            }
    except:
        pass

    return {'ram_total': 0, 'ram_free': 0, 'swap_total': 0, 'swap_free': 0}


def get_cpu_info():
    """Информация о процессоре"""
    logical_cores = 0

    try:
        # содержит информацию о каждом процессорном ядре
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('processor'):
                    logical_cores += 1
    except:
        logical_cores = os.cpu_count() or 0

    try:
        # содержит среднюю загрузку системы за 1, 5 и 15 минут
        with open('/proc/loadavg', 'r') as f:
            load_data = f.read().split()
            load_avg = tuple(float(x) for x in load_data[:3])
    except:
        # через syscall getloadavg
        try:
            libc = ctypes.CDLL('libc.so.6')
            info = ctypes.c_double * 3
            loads = info()
            if hasattr(libc, 'getloadavg'):
                libc.getloadavg(loads, 3)
                load_avg = (loads[0], loads[1], loads[2])
            else:
                load_avg = (0.0, 0.0, 0.0)
        except:
            load_avg = (0.0, 0.0, 0.0)

    return {
        'logical_cores': logical_cores,  # количество логических процессоров
        'load_avg': load_avg  # средняя загрузка системы
    }


def get_drives_info():
    """Информация о дисках"""
    drives = []

    # список файловых систем, которые нужно игнорировать (служебные ФС)
    skip_fs_types = {
        'proc', 'sysfs', 'devtmpfs', 'devpts', 'tmpfs', 'cgroup',
        'cgroup2', 'securityfs', 'pstore', 'efivarfs', 'mqueue',
        'debugfs', 'hugetlbfs', 'fusectl', 'binfmt_misc', 'rpc_pipefs',
        'nfsd', 'autofs', 'configfs', 'fuse.gvfsd-fuse', 'fuse.lxcfs',
        'tracefs', 'overlay', 'squashfs', 'nsfs', 'ramfs', 'rootfs'
    }

    # список точек монтирования, которые нужно игнорировать
    skip_mountpoints = {
        '/proc', '/sys', '/dev', '/run', '/snap', '/sys/kernel',
        '/dev/shm', '/run/lock', '/run/user', '/sys/fs', '/sys/fs/cgroup',
        '/sys/fs/fuse', '/sys/fs/pstore', '/sys/kernel/debug',
        '/sys/kernel/config', '/proc/sys/fs/binfmt_misc'
    }

    try:
        # содержит список всех смонтированных файловых систем
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    device, mountpoint, fstype = parts[0], parts[1], parts[2]

                    if fstype in skip_fs_types:
                        continue

                    if mountpoint in skip_mountpoints:
                        continue

                    skip_prefixes = ['/proc', '/sys', '/dev', '/run', '/snap']
                    if any(mountpoint.startswith(prefix) for prefix in skip_prefixes):
                        continue

                    try:
                        # для получения статистики файловой системы
                        stat = os.statvfs(mountpoint)
                        total_gb = (stat.f_blocks * stat.f_frsize) // (1024 * 1024 * 1024)
                        free_gb = (stat.f_bfree * stat.f_frsize) // (1024 * 1024 * 1024)

                        if total_gb > 0 and free_gb >= 0:
                            drives.append({
                                'device': device,  # устройство (например, /dev/sda1)
                                'mountpoint': mountpoint,  # точка монтирования
                                'fstype': fstype,  # тип ФС (ext4, ntfs, etc.)
                                'total': total_gb,  # общий размер в GB
                                'free': free_gb  # свободное место в GB
                            })
                    except (OSError, PermissionError):
                        continue
    except Exception as e:
        print(f"Error reading mounts: {e}")

    drives.sort(key=lambda x: x['mountpoint'])

    return drives


def get_virtual_memory_info():
    """Информация о виртуальной памяти"""
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('VmallocTotal'):
                    vmalloc_kb = int(line.split()[1])
                    vmalloc_mb = vmalloc_kb // 1024
                    return f"{vmalloc_mb} MB"
    except:
        pass
    return "Error"


def main():
    # операционная система
    os_info = get_os_info()
    print(f"OS: {os_info if os_info else 'Unknown'}")

    # версия ядра Linux
    kernel_info = get_kernel_info()
    print(f"Kernel: {kernel_info if kernel_info else 'Unknown'}")

    # архитектура процессора
    arch_info = get_architecture()
    print(f"Architecture: {arch_info if arch_info else 'Unknown'}")

    # сетевое имя компьютера
    hostname_info = get_hostname()
    print(f"Hostname: {hostname_info if hostname_info else 'Unknown'}")

    # текущий пользователь
    user_info = get_current_user()
    print(f"User: {user_info if user_info else 'Unknown'}")

    mem_info = get_memory_info()
    if isinstance(mem_info, dict):
        # оперативная память
        print(f"RAM: {mem_info.get('ram_free', 0)}MB free / {mem_info.get('ram_total', 0)}MB total")
        # swap-память
        print(f"Swap: {mem_info.get('swap_total', 0)}MB total / {mem_info.get('swap_free', 0)}MB free")
    else:
        print("RAM: Information unavailable")
        print("Swap: Information unavailable")

    # виртуальная память ядра
    virtual_mem = get_virtual_memory_info()
    print(f"Virtual memory: {virtual_mem}")

    cpu_info = get_cpu_info()
    if isinstance(cpu_info, dict):
        # количество логических процессоров (ядер)
        print(f"Processors: {cpu_info.get('logical_cores', 0)}")
        # средняя загрузка системы
        load_avg = cpu_info.get('load_avg', (0.0, 0.0, 0.0))
        # средняя загрузка за 1, 5 и 15 минут
        print(f"Load average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}")
    else:
        print("Processors: Information unavailable")
        print("Load average: Information unavailable")

    # информация о дисках
    print("Drives:")
    drives = get_drives_info()
    if drives:
        for drive in drives:
            print(f"  {drive['mountpoint']:12} {drive['fstype']:8} "
                  f"{drive['free']:3}GB free / {drive['total']:3}GB total")
    else:
        print("No drives information available")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:

        print(f"Error: {e}")
        sys.exit(1)