#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "PETypes.h"

class PEParser {
public:
    std::optional<PEFile> ParseFile(const std::wstring& path, std::string& error) const;

private:
    struct ParseContext {
        const std::vector<std::uint8_t>* data{};
        std::vector<PESection> sections;
        std::uint32_t import_directory_rva{};
        std::uint32_t import_directory_size{};
        std::uint32_t export_directory_rva{};
        std::uint32_t export_directory_size{};
        std::uint32_t size_of_headers{};
        bool is_pe32_plus{};
    };

    bool ReadFileBytes(const std::wstring& path, std::vector<std::uint8_t>& data, std::string& error) const;
    bool ParseHeaders(const std::vector<std::uint8_t>& data, PEFile& result, ParseContext& context, std::string& error) const;
    bool ParseImports(PEFile& result, const ParseContext& context, std::string& error) const;
    bool ParseExports(PEFile& result, const ParseContext& context, std::string& error) const;

    std::optional<std::size_t> RvaToOffset(std::uint32_t rva, const ParseContext& context) const;
    bool IsRvaRangeValid(std::uint32_t rva, std::uint32_t size, const ParseContext& context) const;
    std::optional<std::string> ReadCString(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t max_length) const;
    bool IsRangeValid(std::size_t offset, std::size_t size, std::size_t total_size) const;
};
