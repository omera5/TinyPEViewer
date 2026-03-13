# TinyPEViewer

TinyPEViewer is a Windows desktop utility for inspecting Portable Executable (PE) files (`.exe`, `.dll`).

The project is implemented in modern C++ and parses PE structures directly via Windows headers. Rendering is built with Dear ImGui on Win32 + DirectX 11.

## Features

### PE File Loading
- Open `.exe` and `.dll` files through the Windows file dialog
- Validate file format before analysis

### Header Inspection
- Machine type
- Image base
- Entry point RVA
- Subsystem
- Compile timestamp
- Number of sections
- Size of image
- Size of headers

### Section Analysis
- Section name
- Virtual address
- Virtual size
- Raw size
- Raw pointer
- Characteristics

### Import Analysis
- Imported DLLs
- Imported functions
- Ordinal imports
- Thunk RVAs

### Export Analysis
- Exported functions
- Ordinals
- RVAs
- Name filtering in UI

### User Interface
- Dear ImGui-based interface
- Tab-based analysis panels
- Structured, sortable tables
- Default dark theme

## Project Structure

```text
TinyPEViewer/
  CMakeLists.txt
  README.md
  .gitignore
  external/
  docs/
  src/
    main.cpp
    App.cpp
    App.h
    PEParser.cpp
    PEParser.h
    ui/
```

- `src/`: Application source code, including UI rendering and PE parsing
- `src/ui/`: Panel rendering and table presentation logic
- `external/`: Optional space for third-party resources and local integration artifacts
- `docs/`: Project documentation assets such as screenshots and design notes

## Architecture Overview

TinyPEViewer is organized into three focused layers:

- Application layer: Owns process startup, Win32 windowing, DirectX 11 lifecycle, ImGui initialization, and the render loop
- Parsing layer: Handles file loading, PE header validation, RVA translation, and import/export/section extraction with bounds checks
- UI layer: Renders parsed results using tables and tabbed panels without embedding parsing logic

Parsing and rendering are intentionally separated so the parser remains reusable and testable, while UI logic remains presentation-focused.

## Build Instructions

### Requirements

- Windows 10 or newer
- CMake 3.24 or newer
- Visual Studio 2022 with C++ workload
- x64 toolchain

### Build Steps

1. Clone the repository:
   ```powershell
   git clone <repository-url>
   cd TinyPEViewer
   ```
2. Configure CMake:
   ```powershell
   cmake -S . -B build -G "Visual Studio 17 2022" -A x64
   ```
3. Build:
   ```powershell
   cmake --build build --config Release
   ```
4. Run:
   ```powershell
   .\build\Release\TinyPEViewer.exe
   ```

Dear ImGui is fetched automatically during CMake configure through `FetchContent`.

## Usage

1. Launch `TinyPEViewer.exe`
2. Open a target PE file (`.exe` or `.dll`) from `File -> Open...`
3. Inspect analysis data in the tab panels:
   - `Headers`
   - `Sections`
   - `Imports`
   - `Exports`

## Screenshot

Screenshot placeholder:

```text
docs/screenshot.png
```

Add an interface screenshot at this path for repository presentation.

## Contributing

Contributions are welcome. Pull requests that improve parser robustness, UI usability, diagnostics, or build quality are encouraged.

For substantial changes, open an issue first to align on scope and implementation direction.

## License

This project is released under the MIT License.
