#include "App.h"

#include <algorithm>

#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>

#include "FileDialog.h"
#include "Utils.h"
#include "ui/Panels.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND window, UINT message, WPARAM wparam, LPARAM lparam);

int App::Run(HINSTANCE instance, int show_command) {
    if (!Initialize(instance, show_command)) {
        Shutdown();
        return 1;
    }

    MainLoop();
    Shutdown();
    return 0;
}

bool App::Initialize(HINSTANCE instance, int show_command) {
    if (!InitializeWindow(instance, show_command)) {
        return false;
    }

    if (!InitializeD3D()) {
        return false;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();

    if (!ImGui_ImplWin32_Init(window_)) {
        return false;
    }
    if (!ImGui_ImplDX11_Init(d3d_device_.Get(), d3d_device_context_.Get())) {
        return false;
    }

    ShowWindow(window_, show_command);
    UpdateWindow(window_);
    running_ = true;
    return true;
}

bool App::InitializeWindow(HINSTANCE instance, int show_command) {
    static_cast<void>(show_command);
    instance_ = instance;

    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_CLASSDC;
    window_class.lpfnWndProc = StaticWndProc;
    window_class.hInstance = instance_;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.lpszClassName = window_class_name_.c_str();

    if (RegisterClassExW(&window_class) == 0) {
        return false;
    }

    RECT window_rect{0, 0, 1280, 800};
    AdjustWindowRect(&window_rect, WS_OVERLAPPEDWINDOW, FALSE);

    window_ = CreateWindowExW(
        0,
        window_class_name_.c_str(),
        window_title_.c_str(),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        window_rect.right - window_rect.left,
        window_rect.bottom - window_rect.top,
        nullptr,
        nullptr,
        instance_,
        this
    );

    if (window_ == nullptr) {
        return false;
    }

    return true;
}

bool App::InitializeD3D() {
    DXGI_SWAP_CHAIN_DESC swap_chain_description{};
    swap_chain_description.BufferCount = 2;
    swap_chain_description.BufferDesc.Width = 0;
    swap_chain_description.BufferDesc.Height = 0;
    swap_chain_description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swap_chain_description.BufferDesc.RefreshRate.Numerator = 60;
    swap_chain_description.BufferDesc.RefreshRate.Denominator = 1;
    swap_chain_description.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    swap_chain_description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swap_chain_description.OutputWindow = window_;
    swap_chain_description.SampleDesc.Count = 1;
    swap_chain_description.SampleDesc.Quality = 0;
    swap_chain_description.Windowed = TRUE;
    swap_chain_description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT create_device_flags = 0;
    D3D_FEATURE_LEVEL feature_levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL feature_level_created{};
    HRESULT result = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        create_device_flags,
        feature_levels,
        static_cast<UINT>(_countof(feature_levels)),
        D3D11_SDK_VERSION,
        &swap_chain_description,
        swap_chain_.GetAddressOf(),
        d3d_device_.GetAddressOf(),
        &feature_level_created,
        d3d_device_context_.GetAddressOf()
    );

    if (FAILED(result)) {
        result = D3D11CreateDeviceAndSwapChain(
            nullptr,
            D3D_DRIVER_TYPE_WARP,
            nullptr,
            create_device_flags,
            feature_levels,
            static_cast<UINT>(_countof(feature_levels)),
            D3D11_SDK_VERSION,
            &swap_chain_description,
            swap_chain_.GetAddressOf(),
            d3d_device_.GetAddressOf(),
            &feature_level_created,
            d3d_device_context_.GetAddressOf()
        );
        if (FAILED(result)) {
            return false;
        }
    }

    CreateRenderTarget();
    return render_target_view_ != nullptr;
}

void App::CreateRenderTarget() {
    Microsoft::WRL::ComPtr<ID3D11Texture2D> back_buffer;
    if (swap_chain_ == nullptr) {
        return;
    }
    if (FAILED(swap_chain_->GetBuffer(0, IID_PPV_ARGS(back_buffer.GetAddressOf())))) {
        return;
    }
    d3d_device_->CreateRenderTargetView(back_buffer.Get(), nullptr, render_target_view_.GetAddressOf());
}

void App::CleanupRenderTarget() {
    render_target_view_.Reset();
}

void App::Shutdown() {
    if (ImGui::GetCurrentContext() != nullptr) {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
    }

    CleanupRenderTarget();
    swap_chain_.Reset();
    d3d_device_context_.Reset();
    d3d_device_.Reset();

    if (window_ != nullptr) {
        DestroyWindow(window_);
        window_ = nullptr;
    }
    if (instance_ != nullptr) {
        UnregisterClassW(window_class_name_.c_str(), instance_);
        instance_ = nullptr;
    }
}

void App::MainLoop() {
    MSG message{};
    while (running_) {
        while (PeekMessageW(&message, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
            if (message.message == WM_QUIT) {
                running_ = false;
            }
        }

        if (!running_) {
            break;
        }

        if (swap_chain_occluded_) {
            const HRESULT test_result = swap_chain_->Present(0, DXGI_PRESENT_TEST);
            if (test_result == DXGI_STATUS_OCCLUDED) {
                Sleep(10);
                continue;
            }
            swap_chain_occluded_ = false;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RenderUI();

        ImGui::Render();
        constexpr float clear_color[4] = {0.10f, 0.10f, 0.11f, 1.00f};
        if (render_target_view_ == nullptr) {
            Sleep(10);
            continue;
        }
        d3d_device_context_->OMSetRenderTargets(1, render_target_view_.GetAddressOf(), nullptr);
        d3d_device_context_->ClearRenderTargetView(render_target_view_.Get(), clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        const HRESULT present_result = swap_chain_->Present(1, 0);
        swap_chain_occluded_ = present_result == DXGI_STATUS_OCCLUDED;
    }
}

void App::RenderUI() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);

    constexpr ImGuiWindowFlags root_flags =
        ImGuiWindowFlags_NoDecoration |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_MenuBar;

    ImGui::Begin("TinyPEViewerRoot", nullptr, root_flags);

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open...", "Ctrl+O")) {
                OpenFile();
            }
            if (ImGui::MenuItem("Exit")) {
                PostMessageW(window_, WM_CLOSE, 0, 0);
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    const float status_bar_height = ImGui::GetFrameHeightWithSpacing() + 4.0f;
    ImGui::BeginChild("MainRegion", ImVec2(0.0f, -status_bar_height), false);
    {
        const float left_width = 340.0f;
        ImGui::BeginChild("LeftPanel", ImVec2(left_width, 0.0f), true);
        ui::RenderFileSummary(parsed_file_, current_file_path_, error_message_);
        ImGui::EndChild();

        ImGui::SameLine();

        ImGui::BeginChild("RightPanel", ImVec2(0.0f, 0.0f), true);
        if (parsed_file_.has_value()) {
            if (ImGui::BeginTabBar("MainTabs")) {
                if (ImGui::BeginTabItem("Headers")) {
                    ui::RenderHeadersPanel(*parsed_file_);
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Sections")) {
                    ui::RenderSectionsPanel(*parsed_file_);
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Imports")) {
                    ui::RenderImportsPanel(*parsed_file_);
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem("Exports")) {
                    ui::RenderExportsPanel(*parsed_file_, export_filter_buffer_.data(), export_filter_buffer_.size());
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
        } else {
            const char* empty_text = "Open a PE file to begin analysis";
            const ImVec2 text_size = ImGui::CalcTextSize(empty_text);
            const ImVec2 available = ImGui::GetContentRegionAvail();
            ImGui::SetCursorPosX(std::max(0.0f, (available.x - text_size.x) * 0.5f));
            ImGui::SetCursorPosY(std::max(0.0f, (available.y - text_size.y) * 0.5f));
            ImGui::TextUnformatted(empty_text);
        }
        ImGui::EndChild();
    }
    ImGui::EndChild();

    ImGui::Separator();

    ImGui::BeginChild("StatusBar", ImVec2(0.0f, 0.0f), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    const std::string status_text = !error_message_.empty() ? "Parse Failed" : (parsed_file_.has_value() ? "Loaded" : "No File Loaded");
    const std::string path_text = current_file_path_.empty() ? "No file selected" : ToUtf8(current_file_path_);
    ImGui::Text("Status: %s", status_text.c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    ImGui::TextUnformatted(path_text.c_str());
    ImGui::EndChild();

    ImGui::End();
}

void App::OpenFile() {
    const auto selected_file = OpenPEFileDialog(window_);
    if (!selected_file.has_value()) {
        return;
    }

    current_file_path_ = *selected_file;

    std::string parse_error;
    const auto parsed = parser_.ParseFile(*selected_file, parse_error);
    if (!parsed.has_value()) {
        parsed_file_.reset();
        export_filter_buffer_.fill('\0');
        error_message_ = parse_error.empty() ? "Failed to parse PE file." : parse_error;
        return;
    }

    parsed_file_ = *parsed;
    export_filter_buffer_.fill('\0');
    error_message_.clear();
}

LRESULT App::WndProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (ImGui_ImplWin32_WndProcHandler(window, message, wparam, lparam)) {
        return TRUE;
    }

    switch (message) {
        case WM_SIZE:
            if (wparam != SIZE_MINIMIZED && swap_chain_ != nullptr && LOWORD(lparam) > 0 && HIWORD(lparam) > 0) {
                CleanupRenderTarget();
                swap_chain_->ResizeBuffers(0, static_cast<UINT>(LOWORD(lparam)), static_cast<UINT>(HIWORD(lparam)), DXGI_FORMAT_UNKNOWN, 0);
                CreateRenderTarget();
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wparam & 0xFFF0U) == SC_KEYMENU) {
                return 0;
            }
            break;
        case WM_DESTROY:
            running_ = false;
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }

    return DefWindowProcW(window, message, wparam, lparam);
}

LRESULT CALLBACK App::StaticWndProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_NCCREATE) {
        const auto* create_struct = reinterpret_cast<const CREATESTRUCTW*>(lparam);
        auto* app = static_cast<App*>(create_struct->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
    }

    auto* app = reinterpret_cast<App*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (app != nullptr) {
        return app->WndProc(window, message, wparam, lparam);
    }

    return DefWindowProcW(window, message, wparam, lparam);
}
