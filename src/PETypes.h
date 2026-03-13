#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct PEHeaderInfo {
    std::uint16_t machine{};
    std::uint32_t compile_timestamp{};
    std::uint32_t entry_point_rva{};
    std::uint64_t image_base{};
    std::uint16_t subsystem{};
    std::uint16_t number_of_sections{};
    std::uint32_t size_of_image{};
    std::uint32_t size_of_headers{};
    bool is_pe32_plus{};
};

struct PESection {
    std::string name;
    std::uint32_t virtual_address{};
    std::uint32_t virtual_size{};
    std::uint32_t raw_size{};
    std::uint32_t raw_pointer{};
    std::uint32_t characteristics{};
};

struct ImportSymbol {
    std::string name;
    std::uint32_t ordinal{};
    bool by_ordinal{};
    std::uint32_t thunk_rva{};
};

struct ImportModule {
    std::string dll_name;
    std::vector<ImportSymbol> symbols;
};

struct ExportSymbol {
    std::string name;
    std::uint32_t ordinal{};
    std::uint32_t rva{};
};

struct PEFile {
    std::string file_path;
    PEHeaderInfo header;
    std::vector<PESection> sections;
    std::vector<ImportModule> imports;
    std::vector<ExportSymbol> exports;
};
