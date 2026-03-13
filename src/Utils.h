#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

std::string ToUtf8(const std::wstring& value);
std::wstring ToWide(const std::string& value);
std::string FormatHex(std::uint64_t value, std::size_t width = 0);
std::string FormatTimestamp(std::uint32_t timestamp);
std::string MachineTypeToString(std::uint16_t machine);
std::string SubsystemToString(std::uint16_t subsystem);
