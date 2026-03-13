#pragma once

#include <array>
#include <d3d11.h>
#include <optional>
#include <string>
#include <windows.h>
#include <wrl/client.h>

#include "PEParser.h"
#include "PETypes.h"

class App {
public:
    int Run(HINSTANCE instance, int show_command);

private:
    bool Initialize(HINSTANCE instance, int show_command);
    bool InitializeWindow(HINSTANCE instance, int show_command);
    bool InitializeD3D();
    void Shutdown();
    void MainLoop();
    void RenderUI();
    void OpenFile();
    void CreateRenderTarget();
    void CleanupRenderTarget();

    LRESULT WndProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
    static LRESULT CALLBACK StaticWndProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);

    HWND window_{};
    std::wstring window_class_name_{L"TinyPEViewerWindowClass"};
    std::wstring window_title_{L"TinyPEViewer"};
    HINSTANCE instance_{};

    Microsoft::WRL::ComPtr<ID3D11Device> d3d_device_;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> d3d_device_context_;
    Microsoft::WRL::ComPtr<IDXGISwapChain> swap_chain_;
    Microsoft::WRL::ComPtr<ID3D11RenderTargetView> render_target_view_;

    PEParser parser_;
    std::optional<PEFile> parsed_file_;
    std::wstring current_file_path_;
    std::string error_message_;
    std::array<char, 256> export_filter_buffer_{};

    bool running_{false};
    bool swap_chain_occluded_{false};
};
