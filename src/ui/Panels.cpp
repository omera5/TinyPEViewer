#include "Panels.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <numeric>
#include <vector>

#include <imgui.h>

#include "../Utils.h"

namespace {
std::string ToLowerCopy(const std::string& value) {
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lowered;
}

bool ContainsInsensitive(const std::string& text, const std::string& query) {
    if (query.empty()) {
        return true;
    }
    const std::string text_lower = ToLowerCopy(text);
    const std::string query_lower = ToLowerCopy(query);
    return text_lower.find(query_lower) != std::string::npos;
}

bool IsAscending(const ImGuiTableColumnSortSpecs& sort_spec) {
    return sort_spec.SortDirection == ImGuiSortDirection_Ascending;
}

template <typename T>
void BuildIdentityOrder(std::vector<std::size_t>& order, const std::vector<T>& source) {
    order.resize(source.size());
    std::iota(order.begin(), order.end(), 0);
}

void PropertyRow(const char* label, const std::string& value) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextUnformatted(label);
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(value.c_str());
}
}

namespace ui {
void RenderFileSummary(const std::optional<PEFile>& file, const std::wstring& path, const std::string& error) {
    ImGui::TextUnformatted("File");
    ImGui::Separator();

    if (path.empty()) {
        ImGui::TextUnformatted("No file selected.");
    } else {
        const std::string utf8_path = ToUtf8(path);
        ImGui::TextWrapped("%s", utf8_path.c_str());
    }

    if (!error.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "%s", error.c_str());
    }

    if (!file.has_value()) {
        return;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Format: %s", file->header.is_pe32_plus ? "PE32+" : "PE32");
    ImGui::Text("Sections: %u", static_cast<unsigned>(file->sections.size()));
    ImGui::Text("Import DLLs: %u", static_cast<unsigned>(file->imports.size()));
    ImGui::Text("Exports: %u", static_cast<unsigned>(file->exports.size()));
}

void RenderHeadersPanel(const PEFile& file) {
    const std::string machine = MachineTypeToString(file.header.machine) + " (" + FormatHex(file.header.machine, 4) + ")";
    const std::string timestamp = FormatTimestamp(file.header.compile_timestamp) + " (" + FormatHex(file.header.compile_timestamp, 8) + ")";
    const std::string entry = FormatHex(file.header.entry_point_rva, 8);
    const std::string image_base = FormatHex(file.header.image_base, file.header.is_pe32_plus ? 16 : 8);
    const std::string subsystem = SubsystemToString(file.header.subsystem) + " (" + FormatHex(file.header.subsystem, 4) + ")";
    const std::string size_of_image = FormatHex(file.header.size_of_image, 8) + " (" + std::to_string(file.header.size_of_image) + ")";
    const std::string size_of_headers = FormatHex(file.header.size_of_headers, 8) + " (" + std::to_string(file.header.size_of_headers) + ")";

    if (ImGui::BeginTable("HeadersTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 220.0f);
        ImGui::TableSetupColumn("Value");
        ImGui::TableHeadersRow();

        PropertyRow("Machine", machine);
        PropertyRow("Compile Timestamp", timestamp);
        PropertyRow("Entry Point RVA", entry);
        PropertyRow("Image Base", image_base);
        PropertyRow("Subsystem", subsystem);
        PropertyRow("Sections", std::to_string(file.header.number_of_sections));
        PropertyRow("Size Of Image", size_of_image);
        PropertyRow("Size Of Headers", size_of_headers);
        PropertyRow("PE Type", file.header.is_pe32_plus ? "PE32+" : "PE32");

        ImGui::EndTable();
    }
}

void RenderSectionsPanel(const PEFile& file) {
    if (file.sections.empty()) {
        ImGui::TextUnformatted("No section data.");
        return;
    }

    const ImGuiTableFlags table_flags =
        ImGuiTableFlags_Borders |
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_Resizable |
        ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Sortable |
        ImGuiTableFlags_SortMulti;

    if (ImGui::BeginTable("SectionsTable", 6, table_flags, ImVec2(0.0f, 0.0f))) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Virtual Address", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Virtual Size", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Raw Size", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Raw Pointer", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Characteristics", ImGuiTableColumnFlags_WidthFixed, 160.0f);
        ImGui::TableHeadersRow();

        std::vector<std::size_t> order;
        BuildIdentityOrder(order, file.sections);
        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs(); sort_specs != nullptr && sort_specs->SpecsCount > 0) {
            const ImGuiTableColumnSortSpecs& sort_spec = sort_specs->Specs[0];
            std::stable_sort(order.begin(), order.end(), [&](std::size_t lhs_index, std::size_t rhs_index) {
                const PESection& lhs = file.sections[lhs_index];
                const PESection& rhs = file.sections[rhs_index];

                int comparison = 0;
                switch (sort_spec.ColumnIndex) {
                    case 0:
                        comparison = lhs.name.compare(rhs.name);
                        break;
                    case 1:
                        comparison = lhs.virtual_address < rhs.virtual_address ? -1 : (lhs.virtual_address > rhs.virtual_address ? 1 : 0);
                        break;
                    case 2:
                        comparison = lhs.virtual_size < rhs.virtual_size ? -1 : (lhs.virtual_size > rhs.virtual_size ? 1 : 0);
                        break;
                    case 3:
                        comparison = lhs.raw_size < rhs.raw_size ? -1 : (lhs.raw_size > rhs.raw_size ? 1 : 0);
                        break;
                    case 4:
                        comparison = lhs.raw_pointer < rhs.raw_pointer ? -1 : (lhs.raw_pointer > rhs.raw_pointer ? 1 : 0);
                        break;
                    case 5:
                        comparison = lhs.characteristics < rhs.characteristics ? -1 : (lhs.characteristics > rhs.characteristics ? 1 : 0);
                        break;
                    default:
                        break;
                }

                if (comparison == 0) {
                    comparison = lhs_index < rhs_index ? -1 : (lhs_index > rhs_index ? 1 : 0);
                }

                return IsAscending(sort_spec) ? comparison < 0 : comparison > 0;
            });
            sort_specs->SpecsDirty = false;
        }

        for (const std::size_t row_index : order) {
            const PESection& section = file.sections[row_index];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(section.name.c_str());
            ImGui::TableSetColumnIndex(1);
            const std::string virtual_address = FormatHex(section.virtual_address, 8);
            ImGui::TextUnformatted(virtual_address.c_str());
            ImGui::TableSetColumnIndex(2);
            const std::string virtual_size = FormatHex(section.virtual_size, 8);
            ImGui::TextUnformatted(virtual_size.c_str());
            ImGui::TableSetColumnIndex(3);
            const std::string raw_size = FormatHex(section.raw_size, 8);
            ImGui::TextUnformatted(raw_size.c_str());
            ImGui::TableSetColumnIndex(4);
            const std::string raw_pointer = FormatHex(section.raw_pointer, 8);
            ImGui::TextUnformatted(raw_pointer.c_str());
            ImGui::TableSetColumnIndex(5);
            const std::string characteristics = FormatHex(section.characteristics, 8);
            ImGui::TextUnformatted(characteristics.c_str());
        }

        ImGui::EndTable();
    }
}

void RenderImportsPanel(const PEFile& file) {
    if (file.imports.empty()) {
        ImGui::TextUnformatted("No imports.");
        return;
    }

    ImGui::BeginChild("ImportsScrollRegion", ImVec2(0.0f, 0.0f), false, ImGuiWindowFlags_HorizontalScrollbar);
    for (std::size_t module_index = 0; module_index < file.imports.size(); ++module_index) {
        const ImportModule& module = file.imports[module_index];
        const std::string header_label = module.dll_name + "##module_" + std::to_string(module_index);
        if (!ImGui::CollapsingHeader(header_label.c_str(), ImGuiTreeNodeFlags_DefaultOpen)) {
            continue;
        }

        std::vector<std::size_t> order;
        BuildIdentityOrder(order, module.symbols);

        const std::string table_id = "ImportsTable_" + std::to_string(module_index);
        const ImGuiTableFlags table_flags =
            ImGuiTableFlags_Borders |
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_Sortable;

        if (!ImGui::BeginTable(table_id.c_str(), 3, table_flags)) {
            continue;
        }
        ImGui::TableSetupColumn("DLL", ImGuiTableColumnFlags_WidthFixed, 220.0f);
        ImGui::TableSetupColumn("Function / Ordinal");
        ImGui::TableSetupColumn("Thunk RVA", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableHeadersRow();

        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs(); sort_specs != nullptr && sort_specs->SpecsCount > 0) {
            const ImGuiTableColumnSortSpecs& sort_spec = sort_specs->Specs[0];
            std::stable_sort(order.begin(), order.end(), [&](std::size_t lhs_index, std::size_t rhs_index) {
                const ImportSymbol& lhs = module.symbols[lhs_index];
                const ImportSymbol& rhs = module.symbols[rhs_index];

                const std::string lhs_name = lhs.by_ordinal ? "Ordinal " + std::to_string(lhs.ordinal) : lhs.name;
                const std::string rhs_name = rhs.by_ordinal ? "Ordinal " + std::to_string(rhs.ordinal) : rhs.name;

                int comparison = 0;
                switch (sort_spec.ColumnIndex) {
                    case 0:
                        comparison = 0;
                        break;
                    case 1:
                        comparison = lhs_name.compare(rhs_name);
                        break;
                    case 2:
                        comparison = lhs.thunk_rva < rhs.thunk_rva ? -1 : (lhs.thunk_rva > rhs.thunk_rva ? 1 : 0);
                        break;
                    default:
                        break;
                }

                if (comparison == 0) {
                    comparison = lhs_index < rhs_index ? -1 : (lhs_index > rhs_index ? 1 : 0);
                }

                return IsAscending(sort_spec) ? comparison < 0 : comparison > 0;
            });
            sort_specs->SpecsDirty = false;
        }

        if (module.symbols.empty()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(module.dll_name.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted("<none>");
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted("-");
            ImGui::EndTable();
            continue;
        }

        for (const std::size_t symbol_index : order) {
            const ImportSymbol& symbol = module.symbols[symbol_index];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(module.dll_name.c_str());
            ImGui::TableSetColumnIndex(1);
            const std::string name = symbol.by_ordinal ? "Ordinal " + std::to_string(symbol.ordinal) : symbol.name;
            ImGui::TextUnformatted(name.c_str());
            ImGui::TableSetColumnIndex(2);
            const std::string thunk_rva = FormatHex(symbol.thunk_rva, 8);
            ImGui::TextUnformatted(thunk_rva.c_str());
        }

        ImGui::EndTable();
    }
    ImGui::EndChild();
}

void RenderExportsPanel(const PEFile& file, char* filter_buffer, std::size_t filter_buffer_size) {
    if (filter_buffer != nullptr && filter_buffer_size > 0) {
        filter_buffer[filter_buffer_size - 1] = '\0';
        ImGui::SetNextItemWidth(320.0f);
        ImGui::InputTextWithHint("##ExportSearch", "Filter exports by name", filter_buffer, filter_buffer_size);
    }

    const std::string filter = filter_buffer != nullptr ? std::string(filter_buffer) : std::string();
    ImGui::Spacing();

    if (file.exports.empty()) {
        ImGui::TextUnformatted("No exports.");
        return;
    }

    const ImGuiTableFlags table_flags =
        ImGuiTableFlags_Borders |
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_Resizable |
        ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Sortable |
        ImGuiTableFlags_SortMulti;

    if (ImGui::BeginTable("ExportsTable", 3, table_flags, ImVec2(0.0f, 0.0f))) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableHeadersRow();

        std::vector<std::size_t> order;
        BuildIdentityOrder(order, file.exports);
        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs(); sort_specs != nullptr && sort_specs->SpecsCount > 0) {
            const ImGuiTableColumnSortSpecs& sort_spec = sort_specs->Specs[0];
            std::stable_sort(order.begin(), order.end(), [&](std::size_t lhs_index, std::size_t rhs_index) {
                const ExportSymbol& lhs = file.exports[lhs_index];
                const ExportSymbol& rhs = file.exports[rhs_index];

                int comparison = 0;
                switch (sort_spec.ColumnIndex) {
                    case 0:
                        comparison = lhs.name.compare(rhs.name);
                        break;
                    case 1:
                        comparison = lhs.ordinal < rhs.ordinal ? -1 : (lhs.ordinal > rhs.ordinal ? 1 : 0);
                        break;
                    case 2:
                        comparison = lhs.rva < rhs.rva ? -1 : (lhs.rva > rhs.rva ? 1 : 0);
                        break;
                    default:
                        break;
                }

                if (comparison == 0) {
                    comparison = lhs_index < rhs_index ? -1 : (lhs_index > rhs_index ? 1 : 0);
                }

                return IsAscending(sort_spec) ? comparison < 0 : comparison > 0;
            });
            sort_specs->SpecsDirty = false;
        }

        std::size_t visible_count = 0;
        for (const std::size_t row_index : order) {
            const ExportSymbol& symbol = file.exports[row_index];
            if (!ContainsInsensitive(symbol.name, filter)) {
                continue;
            }
            ++visible_count;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (symbol.name.empty()) {
                ImGui::TextUnformatted("<ordinal-only>");
            } else {
                ImGui::TextUnformatted(symbol.name.c_str());
            }
            ImGui::TableSetColumnIndex(1);
            const std::string ordinal = std::to_string(symbol.ordinal);
            ImGui::TextUnformatted(ordinal.c_str());
            ImGui::TableSetColumnIndex(2);
            const std::string rva = FormatHex(symbol.rva, 8);
            ImGui::TextUnformatted(rva.c_str());
        }

        ImGui::EndTable();

        if (visible_count == 0) {
            ImGui::TextUnformatted("No exports match the current filter.");
        }
    }
}
}
