cmake_minimum_required(VERSION 3.24)

project(TinyPEViewer LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "TinyPEViewer builds on Windows only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.90.8
    GIT_SHALLOW TRUE
    GIT_SUBMODULES ""
    GIT_SUBMODULES_RECURSE FALSE
)

FetchContent_MakeAvailable(imgui)

add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
)

target_include_directories(imgui PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

target_link_libraries(imgui PUBLIC
    d3d11
    dxgi
    d3dcompiler
    user32
    gdi32
    imm32
)

add_executable(TinyPEViewer WIN32
    src/main.cpp
    src/App.h
    src/App.cpp
    src/PEParser.h
    src/PEParser.cpp
    src/PETypes.h
    src/FileDialog.h
    src/FileDialog.cpp
    src/Utils.h
    src/Utils.cpp
    src/ui/Panels.h
    src/ui/Panels.cpp
)

target_compile_definitions(TinyPEViewer PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(TinyPEViewer PRIVATE
    imgui
    comdlg32
)

if(MSVC)
    target_link_options(TinyPEViewer PRIVATE
        $<$<CONFIG:Release>:/INCREMENTAL:NO>
        $<$<CONFIG:Release>:/DEBUG:NONE>
        $<$<CONFIG:Release>:/OPT:REF>
        $<$<CONFIG:Release>:/OPT:ICF>
        $<$<CONFIG:Release>:/BREPRO>
    )
endif()

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT TinyPEViewer)
