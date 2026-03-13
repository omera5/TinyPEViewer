#pragma once

#include <optional>
#include <string>
#include <windows.h>
#include <commdlg.h>

std::optional<std::wstring> OpenPEFileDialog(HWND owner_window);
