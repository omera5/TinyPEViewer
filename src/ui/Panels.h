#pragma once

#include <cstddef>
#include <optional>
#include <string>

#include "../PETypes.h"

namespace ui {
void RenderFileSummary(const std::optional<PEFile>& file, const std::wstring& path, const std::string& error);
void RenderHeadersPanel(const PEFile& file);
void RenderSectionsPanel(const PEFile& file);
void RenderImportsPanel(const PEFile& file);
void RenderExportsPanel(const PEFile& file, char* filter_buffer, std::size_t filter_buffer_size);
}
