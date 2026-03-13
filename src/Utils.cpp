#include "Utils.h"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <windows.h>

std::string ToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int required_size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required_size <= 0) {
        return {};
    }

    std::string utf8(required_size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), utf8.data(), required_size, nullptr, nullptr);
    return utf8;
}

std::wstring ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }

    const int required_size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (required_size <= 0) {
        return {};
    }

    std::wstring wide(required_size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), wide.data(), required_size);
    return wide;
}

std::string FormatHex(std::uint64_t value, std::size_t width) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << std::setfill('0');
    if (width > 0) {
        stream << std::setw(static_cast<int>(width));
    }
    stream << value;
    return stream.str();
}

std::string FormatTimestamp(std::uint32_t timestamp) {
    const std::time_t seconds = static_cast<std::time_t>(timestamp);
    std::tm utc_time{};
    if (gmtime_s(&utc_time, &seconds) != 0) {
        return "Invalid timestamp";
    }

    std::ostringstream stream;
    stream << std::put_time(&utc_time, "%Y-%m-%d %H:%M:%S UTC");
    return stream.str();
}

std::string MachineTypeToString(std::uint16_t machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:
            return "Intel 386";
        case IMAGE_FILE_MACHINE_AMD64:
            return "AMD64";
        case IMAGE_FILE_MACHINE_ARM:
            return "ARM";
        case IMAGE_FILE_MACHINE_ARM64:
            return "ARM64";
        case IMAGE_FILE_MACHINE_IA64:
            return "Intel Itanium";
        default:
            return "Unknown";
    }
}

std::string SubsystemToString(std::uint16_t subsystem) {
    switch (subsystem) {
        case IMAGE_SUBSYSTEM_NATIVE:
            return "Native";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            return "Windows GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            return "Windows CUI";
        case IMAGE_SUBSYSTEM_OS2_CUI:
            return "OS/2 CUI";
        case IMAGE_SUBSYSTEM_POSIX_CUI:
            return "POSIX CUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
            return "Windows CE GUI";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:
            return "EFI Application";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
            return "EFI Boot Service Driver";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
            return "EFI Runtime Driver";
        case IMAGE_SUBSYSTEM_EFI_ROM:
            return "EFI ROM";
        case IMAGE_SUBSYSTEM_XBOX:
            return "Xbox";
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
            return "Windows Boot Application";
        default:
            return "Unknown";
    }
}
