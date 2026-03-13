#include "PEParser.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <utility>
#include <windows.h>

#include "Utils.h"

namespace {
template <typename T>
bool ReadObject(const std::vector<std::uint8_t>& data, std::size_t offset, T& value) {
    if (offset > data.size() || sizeof(T) > data.size() - offset) {
        return false;
    }
    std::memcpy(&value, data.data() + offset, sizeof(T));
    return true;
}
}

std::optional<PEFile> PEParser::ParseFile(const std::wstring& path, std::string& error) const {
    error.clear();

    std::vector<std::uint8_t> data;
    if (!ReadFileBytes(path, data, error)) {
        return std::nullopt;
    }

    PEFile result;
    ParseContext context;
    if (!ParseHeaders(data, result, context, error)) {
        return std::nullopt;
    }

    if (!ParseImports(result, context, error)) {
        return std::nullopt;
    }

    if (!ParseExports(result, context, error)) {
        return std::nullopt;
    }

    result.file_path = ToUtf8(path);
    return result;
}

bool PEParser::ReadFileBytes(const std::wstring& path, std::vector<std::uint8_t>& data, std::string& error) const {
    std::ifstream stream(std::filesystem::path(path), std::ios::binary | std::ios::ate);
    if (!stream.is_open()) {
        error = "Unable to open file.";
        return false;
    }

    const std::streampos file_size = stream.tellg();
    if (file_size <= 0) {
        error = "File is empty.";
        return false;
    }

    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(file_size));
    const auto size = static_cast<std::streamsize>(file_size);
    stream.seekg(0, std::ios::beg);
    if (!stream.read(reinterpret_cast<char*>(buffer.data()), size)) {
        error = "Unable to read file bytes.";
        return false;
    }

    data = std::move(buffer);
    return true;
}

bool PEParser::ParseHeaders(const std::vector<std::uint8_t>& data, PEFile& result, ParseContext& context, std::string& error) const {
    IMAGE_DOS_HEADER dos_header{};
    if (!ReadObject(data, 0, dos_header)) {
        error = "File is smaller than DOS header.";
        return false;
    }

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        error = "Invalid DOS signature.";
        return false;
    }

    if (dos_header.e_lfanew < 0) {
        error = "Invalid NT header offset.";
        return false;
    }

    const std::size_t nt_offset = static_cast<std::size_t>(dos_header.e_lfanew);
    DWORD nt_signature{};
    if (!ReadObject(data, nt_offset, nt_signature)) {
        error = "NT signature is out of file bounds.";
        return false;
    }

    if (nt_signature != IMAGE_NT_SIGNATURE) {
        error = "Invalid NT signature.";
        return false;
    }

    IMAGE_FILE_HEADER file_header{};
    if (!ReadObject(data, nt_offset + sizeof(DWORD), file_header)) {
        error = "File header is out of file bounds.";
        return false;
    }

    const std::size_t optional_header_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (file_header.SizeOfOptionalHeader < sizeof(WORD)) {
        error = "Optional header is too small.";
        return false;
    }

    if (!IsRangeValid(optional_header_offset, file_header.SizeOfOptionalHeader, data.size())) {
        error = "Optional header exceeds file bounds.";
        return false;
    }

    WORD optional_magic{};
    if (!ReadObject(data, optional_header_offset, optional_magic)) {
        error = "Unable to read optional header magic.";
        return false;
    }

    result.header.machine = file_header.Machine;
    result.header.compile_timestamp = file_header.TimeDateStamp;
    result.header.number_of_sections = file_header.NumberOfSections;

    if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            error = "PE32 optional header size is invalid.";
            return false;
        }

        IMAGE_OPTIONAL_HEADER32 optional_header{};
        if (!ReadObject(data, optional_header_offset, optional_header)) {
            error = "Unable to read PE32 optional header.";
            return false;
        }

        result.header.entry_point_rva = optional_header.AddressOfEntryPoint;
        result.header.image_base = optional_header.ImageBase;
        result.header.subsystem = optional_header.Subsystem;
        result.header.size_of_image = optional_header.SizeOfImage;
        result.header.size_of_headers = optional_header.SizeOfHeaders;
        result.header.is_pe32_plus = false;

        context.is_pe32_plus = false;
        context.size_of_headers = optional_header.SizeOfHeaders;

        const std::uint32_t directory_count = std::min<std::uint32_t>(optional_header.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        if (directory_count > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            context.import_directory_rva = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            context.import_directory_size = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (directory_count > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            context.export_directory_rva = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            context.export_directory_size = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
    } else if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            error = "PE32+ optional header size is invalid.";
            return false;
        }

        IMAGE_OPTIONAL_HEADER64 optional_header{};
        if (!ReadObject(data, optional_header_offset, optional_header)) {
            error = "Unable to read PE32+ optional header.";
            return false;
        }

        result.header.entry_point_rva = optional_header.AddressOfEntryPoint;
        result.header.image_base = optional_header.ImageBase;
        result.header.subsystem = optional_header.Subsystem;
        result.header.size_of_image = optional_header.SizeOfImage;
        result.header.size_of_headers = optional_header.SizeOfHeaders;
        result.header.is_pe32_plus = true;

        context.is_pe32_plus = true;
        context.size_of_headers = optional_header.SizeOfHeaders;

        const std::uint32_t directory_count = std::min<std::uint32_t>(optional_header.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        if (directory_count > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            context.import_directory_rva = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            context.import_directory_size = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        if (directory_count > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            context.export_directory_rva = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            context.export_directory_size = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
    } else {
        error = "Unsupported optional header magic.";
        return false;
    }

    const std::size_t section_headers_offset = optional_header_offset + file_header.SizeOfOptionalHeader;
    const std::size_t section_headers_size = static_cast<std::size_t>(file_header.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (!IsRangeValid(section_headers_offset, section_headers_size, data.size())) {
        error = "Section header table exceeds file bounds.";
        return false;
    }

    result.sections.reserve(file_header.NumberOfSections);
    context.sections.reserve(file_header.NumberOfSections);
    for (std::uint16_t index = 0; index < file_header.NumberOfSections; ++index) {
        IMAGE_SECTION_HEADER section_header{};
        const std::size_t section_offset = section_headers_offset + static_cast<std::size_t>(index) * sizeof(IMAGE_SECTION_HEADER);
        if (!ReadObject(data, section_offset, section_header)) {
            error = "Failed to read a section header.";
            return false;
        }

        if (section_header.SizeOfRawData > 0) {
            if (!IsRangeValid(section_header.PointerToRawData, section_header.SizeOfRawData, data.size())) {
                error = "Section raw data exceeds file bounds.";
                return false;
            }
        }

        char name_buffer[9]{};
        std::memcpy(name_buffer, section_header.Name, 8);

        PESection section;
        section.name = std::string(name_buffer);
        section.virtual_address = section_header.VirtualAddress;
        section.virtual_size = section_header.Misc.VirtualSize;
        section.raw_size = section_header.SizeOfRawData;
        section.raw_pointer = section_header.PointerToRawData;
        section.characteristics = section_header.Characteristics;

        result.sections.push_back(section);
        context.sections.push_back(std::move(section));
    }

    context.data = &data;
    return true;
}

bool PEParser::ParseImports(PEFile& result, const ParseContext& context, std::string& error) const {
    if (context.import_directory_rva == 0 || context.import_directory_size == 0) {
        return true;
    }

    if (!IsRvaRangeValid(context.import_directory_rva, context.import_directory_size, context)) {
        error = "Import directory range is invalid.";
        return false;
    }

    const auto descriptor_offset = RvaToOffset(context.import_directory_rva, context);
    if (!descriptor_offset.has_value()) {
        error = "Import directory RVA is invalid.";
        return false;
    }

    const auto& data = *context.data;
    constexpr std::size_t max_descriptor_count = 4096;
    const std::size_t descriptor_limit_by_size = context.import_directory_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (descriptor_limit_by_size == 0) {
        error = "Import directory size is invalid.";
        return false;
    }
    const std::size_t descriptor_limit = std::min<std::size_t>(descriptor_limit_by_size, max_descriptor_count);

    for (std::size_t descriptor_index = 0; descriptor_index < descriptor_limit; ++descriptor_index) {
        const std::size_t current_offset = *descriptor_offset + descriptor_index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        if (!ReadObject(data, current_offset, descriptor)) {
            error = "Import descriptor is out of file bounds.";
            return false;
        }

        const bool is_terminal =
            descriptor.OriginalFirstThunk == 0 &&
            descriptor.TimeDateStamp == 0 &&
            descriptor.ForwarderChain == 0 &&
            descriptor.Name == 0 &&
            descriptor.FirstThunk == 0;
        if (is_terminal) {
            return true;
        }

        const auto module_name_offset = RvaToOffset(descriptor.Name, context);
        if (!module_name_offset.has_value()) {
            error = "Import module name RVA is invalid.";
            return false;
        }
        if (!IsRangeValid(*module_name_offset, 1, data.size())) {
            error = "Import module name is out of file bounds.";
            return false;
        }

        const auto module_name = ReadCString(data, *module_name_offset, 1024);
        if (!module_name.has_value()) {
            error = "Import module name is invalid.";
            return false;
        }

        ImportModule module;
        module.dll_name = *module_name;

        const std::uint32_t thunk_rva = descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
        if (thunk_rva != 0) {
            const auto thunk_offset = RvaToOffset(thunk_rva, context);
            if (!thunk_offset.has_value()) {
                error = "Import thunk RVA is invalid.";
                return false;
            }

            constexpr std::size_t max_thunk_count = 65536;
            if (context.is_pe32_plus) {
                bool terminated = false;
                for (std::size_t thunk_index = 0; thunk_index < max_thunk_count; ++thunk_index) {
                    const std::size_t current_thunk_offset = *thunk_offset + thunk_index * sizeof(ULONGLONG);
                    ULONGLONG thunk_value{};
                    if (!ReadObject(data, current_thunk_offset, thunk_value)) {
                        error = "Import thunk entry is out of file bounds.";
                        return false;
                    }

                    if (thunk_value == 0) {
                        terminated = true;
                        break;
                    }

                    ImportSymbol symbol;
                    symbol.thunk_rva = thunk_rva + static_cast<std::uint32_t>(thunk_index * sizeof(ULONGLONG));
                    if (IMAGE_SNAP_BY_ORDINAL64(thunk_value)) {
                        symbol.by_ordinal = true;
                        symbol.ordinal = static_cast<std::uint16_t>(IMAGE_ORDINAL64(thunk_value));
                    } else {
                        symbol.by_ordinal = false;
                        const auto import_name_offset = RvaToOffset(static_cast<std::uint32_t>(thunk_value), context);
                        if (!import_name_offset.has_value()) {
                            error = "Import name RVA is invalid.";
                            return false;
                        }
                        if (!IsRangeValid(*import_name_offset, sizeof(WORD) + 1, data.size())) {
                            error = "Import name entry is out of file bounds.";
                            return false;
                        }
                        const auto import_name = ReadCString(data, *import_name_offset + sizeof(WORD), 2048);
                        if (!import_name.has_value()) {
                            error = "Import name string is invalid.";
                            return false;
                        }
                        symbol.name = *import_name;
                    }
                    module.symbols.push_back(std::move(symbol));
                }
                if (!terminated) {
                    error = "Import thunk table is malformed.";
                    return false;
                }
            } else {
                bool terminated = false;
                for (std::size_t thunk_index = 0; thunk_index < max_thunk_count; ++thunk_index) {
                    const std::size_t current_thunk_offset = *thunk_offset + thunk_index * sizeof(DWORD);
                    DWORD thunk_value{};
                    if (!ReadObject(data, current_thunk_offset, thunk_value)) {
                        error = "Import thunk entry is out of file bounds.";
                        return false;
                    }

                    if (thunk_value == 0) {
                        terminated = true;
                        break;
                    }

                    ImportSymbol symbol;
                    symbol.thunk_rva = thunk_rva + static_cast<std::uint32_t>(thunk_index * sizeof(DWORD));
                    if (IMAGE_SNAP_BY_ORDINAL32(thunk_value)) {
                        symbol.by_ordinal = true;
                        symbol.ordinal = static_cast<std::uint16_t>(IMAGE_ORDINAL32(thunk_value));
                    } else {
                        symbol.by_ordinal = false;
                        const auto import_name_offset = RvaToOffset(thunk_value, context);
                        if (!import_name_offset.has_value()) {
                            error = "Import name RVA is invalid.";
                            return false;
                        }
                        if (!IsRangeValid(*import_name_offset, sizeof(WORD) + 1, data.size())) {
                            error = "Import name entry is out of file bounds.";
                            return false;
                        }
                        const auto import_name = ReadCString(data, *import_name_offset + sizeof(WORD), 2048);
                        if (!import_name.has_value()) {
                            error = "Import name string is invalid.";
                            return false;
                        }
                        symbol.name = *import_name;
                    }
                    module.symbols.push_back(std::move(symbol));
                }
                if (!terminated) {
                    error = "Import thunk table is malformed.";
                    return false;
                }
            }
        }

        result.imports.push_back(std::move(module));
    }

    error = "Import descriptor table is malformed.";
    return false;
}

bool PEParser::ParseExports(PEFile& result, const ParseContext& context, std::string& error) const {
    if (context.export_directory_rva == 0 || context.export_directory_size == 0) {
        return true;
    }

    if (context.export_directory_size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        error = "Export directory size is invalid.";
        return false;
    }
    if (!IsRvaRangeValid(context.export_directory_rva, context.export_directory_size, context)) {
        error = "Export directory range is invalid.";
        return false;
    }

    const auto export_directory_offset = RvaToOffset(context.export_directory_rva, context);
    if (!export_directory_offset.has_value()) {
        error = "Export directory RVA is invalid.";
        return false;
    }

    const auto& data = *context.data;
    IMAGE_EXPORT_DIRECTORY export_directory{};
    if (!ReadObject(data, *export_directory_offset, export_directory)) {
        error = "Export directory is out of file bounds.";
        return false;
    }

    if (export_directory.NumberOfFunctions == 0 || export_directory.AddressOfFunctions == 0) {
        return true;
    }

    const auto functions_offset = RvaToOffset(export_directory.AddressOfFunctions, context);
    if (!functions_offset.has_value()) {
        error = "Export function table RVA is invalid.";
        return false;
    }

    if (export_directory.NumberOfFunctions > (std::numeric_limits<std::size_t>::max() / sizeof(DWORD))) {
        error = "Export function table size is invalid.";
        return false;
    }
    const std::size_t function_table_size = static_cast<std::size_t>(export_directory.NumberOfFunctions) * sizeof(DWORD);
    if (function_table_size > std::numeric_limits<std::uint32_t>::max()) {
        error = "Export function table size is invalid.";
        return false;
    }
    if (!IsRvaRangeValid(export_directory.AddressOfFunctions, static_cast<std::uint32_t>(function_table_size), context)) {
        error = "Export function table range is invalid.";
        return false;
    }
    if (!IsRangeValid(*functions_offset, function_table_size, data.size())) {
        error = "Export function table exceeds file bounds.";
        return false;
    }

    std::vector<bool> has_name(export_directory.NumberOfFunctions, false);

    if (export_directory.NumberOfNames > 0 && export_directory.AddressOfNames != 0 && export_directory.AddressOfNameOrdinals != 0) {
        const auto names_offset = RvaToOffset(export_directory.AddressOfNames, context);
        const auto ordinals_offset = RvaToOffset(export_directory.AddressOfNameOrdinals, context);
        if (!names_offset.has_value() || !ordinals_offset.has_value()) {
            error = "Export name table RVA is invalid.";
            return false;
        }

        if (export_directory.NumberOfNames > (std::numeric_limits<std::size_t>::max() / sizeof(DWORD))) {
            error = "Export name table size is invalid.";
            return false;
        }
        const std::size_t names_table_size = static_cast<std::size_t>(export_directory.NumberOfNames) * sizeof(DWORD);
        if (names_table_size > std::numeric_limits<std::uint32_t>::max()) {
            error = "Export name table size is invalid.";
            return false;
        }
        if (!IsRvaRangeValid(export_directory.AddressOfNames, static_cast<std::uint32_t>(names_table_size), context)) {
            error = "Export name pointer table range is invalid.";
            return false;
        }
        if (!IsRangeValid(*names_offset, names_table_size, data.size())) {
            error = "Export name pointer table exceeds file bounds.";
            return false;
        }
        if (export_directory.NumberOfNames > (std::numeric_limits<std::size_t>::max() / sizeof(WORD))) {
            error = "Export ordinal table size is invalid.";
            return false;
        }
        const std::size_t ordinals_table_size = static_cast<std::size_t>(export_directory.NumberOfNames) * sizeof(WORD);
        if (ordinals_table_size > std::numeric_limits<std::uint32_t>::max()) {
            error = "Export ordinal table size is invalid.";
            return false;
        }
        if (!IsRvaRangeValid(export_directory.AddressOfNameOrdinals, static_cast<std::uint32_t>(ordinals_table_size), context)) {
            error = "Export ordinal table range is invalid.";
            return false;
        }
        if (!IsRangeValid(*ordinals_offset, ordinals_table_size, data.size())) {
            error = "Export ordinal table exceeds file bounds.";
            return false;
        }

        for (std::uint32_t name_index = 0; name_index < export_directory.NumberOfNames; ++name_index) {
            DWORD name_rva{};
            WORD ordinal_index{};
            if (!ReadObject(data, *names_offset + static_cast<std::size_t>(name_index) * sizeof(DWORD), name_rva)) {
                error = "Failed to read export name RVA.";
                return false;
            }
            if (!ReadObject(data, *ordinals_offset + static_cast<std::size_t>(name_index) * sizeof(WORD), ordinal_index)) {
                error = "Failed to read export ordinal index.";
                return false;
            }

            if (ordinal_index >= export_directory.NumberOfFunctions) {
                continue;
            }

            const auto name_offset = RvaToOffset(name_rva, context);
            if (!name_offset.has_value()) {
                continue;
            }

            const auto export_name = ReadCString(data, *name_offset, 2048);
            if (!export_name.has_value()) {
                continue;
            }

            DWORD function_rva{};
            if (!ReadObject(data, *functions_offset + static_cast<std::size_t>(ordinal_index) * sizeof(DWORD), function_rva)) {
                error = "Failed to read export function RVA.";
                return false;
            }

            ExportSymbol symbol;
            symbol.name = *export_name;
            symbol.ordinal = export_directory.Base + ordinal_index;
            symbol.rva = function_rva;
            result.exports.push_back(std::move(symbol));
            has_name[ordinal_index] = true;
        }
    }

    for (std::uint32_t function_index = 0; function_index < export_directory.NumberOfFunctions; ++function_index) {
        if (has_name[function_index]) {
            continue;
        }

        DWORD function_rva{};
        if (!ReadObject(data, *functions_offset + static_cast<std::size_t>(function_index) * sizeof(DWORD), function_rva)) {
            error = "Failed to read export function RVA.";
            return false;
        }

        if (function_rva == 0) {
            continue;
        }

        ExportSymbol symbol;
        symbol.ordinal = export_directory.Base + function_index;
        symbol.rva = function_rva;
        result.exports.push_back(std::move(symbol));
    }

    std::sort(result.exports.begin(), result.exports.end(), [](const ExportSymbol& lhs, const ExportSymbol& rhs) {
        return lhs.ordinal < rhs.ordinal;
    });

    return true;
}

std::optional<std::size_t> PEParser::RvaToOffset(std::uint32_t rva, const ParseContext& context) const {
    if (context.data == nullptr) {
        return std::nullopt;
    }

    const std::size_t file_size = context.data->size();
    if (rva < context.size_of_headers && rva < file_size) {
        return static_cast<std::size_t>(rva);
    }

    for (const auto& section : context.sections) {
        const std::uint64_t section_start = section.virtual_address;
        const std::uint64_t mapped_size = std::max<std::uint32_t>(section.virtual_size, section.raw_size);
        if (mapped_size == 0) {
            continue;
        }

        const std::uint64_t section_end = section_start + mapped_size;
        if (rva < section_start || rva >= section_end) {
            continue;
        }

        const std::uint64_t delta = static_cast<std::uint64_t>(rva) - section_start;
        if (delta >= section.raw_size) {
            return std::nullopt;
        }

        const std::uint64_t file_offset = static_cast<std::uint64_t>(section.raw_pointer) + delta;
        if (file_offset >= file_size) {
            return std::nullopt;
        }

        return static_cast<std::size_t>(file_offset);
    }

    return std::nullopt;
}

bool PEParser::IsRvaRangeValid(std::uint32_t rva, std::uint32_t size, const ParseContext& context) const {
    if (size == 0) {
        return false;
    }

    const auto start_offset = RvaToOffset(rva, context);
    if (!start_offset.has_value()) {
        return false;
    }

    const std::uint64_t end_rva = static_cast<std::uint64_t>(rva) + static_cast<std::uint64_t>(size) - 1;
    if (end_rva > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    const auto end_offset = RvaToOffset(static_cast<std::uint32_t>(end_rva), context);
    if (!end_offset.has_value()) {
        return false;
    }

    return *end_offset >= *start_offset;
}

std::optional<std::string> PEParser::ReadCString(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t max_length) const {
    if (offset >= data.size()) {
        return std::nullopt;
    }

    const std::size_t available = data.size() - offset;
    const std::size_t span = std::min(available, max_length);
    const std::size_t end_limit = offset + span;
    std::size_t end = offset;
    while (end < end_limit && data[end] != 0) {
        ++end;
    }

    if (end == end_limit) {
        return std::nullopt;
    }

    return std::string(reinterpret_cast<const char*>(data.data() + offset), end - offset);
}

bool PEParser::IsRangeValid(std::size_t offset, std::size_t size, std::size_t total_size) const {
    if (offset > total_size) {
        return false;
    }
    if (size > total_size - offset) {
        return false;
    }
    return true;
}
