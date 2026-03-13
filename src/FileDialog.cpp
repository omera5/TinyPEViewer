#include "FileDialog.h"

#include <array>

std::optional<std::wstring> OpenPEFileDialog(HWND owner_window) {
    std::array<wchar_t, 32768> file_buffer{};

    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner_window;
    dialog.lpstrFile = file_buffer.data();
    dialog.nMaxFile = static_cast<DWORD>(file_buffer.size());
    dialog.lpstrFilter = L"Portable Executable (*.exe;*.dll)\0*.exe;*.dll\0All Files (*.*)\0*.*\0";
    dialog.nFilterIndex = 1;
    dialog.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    dialog.lpstrDefExt = L"exe";

    if (GetOpenFileNameW(&dialog) == TRUE) {
        return std::wstring(dialog.lpstrFile);
    }

    return std::nullopt;
}
