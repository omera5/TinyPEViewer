# TinyPEViewer
Lightweight Windows PE inspection utility for `.exe` and `.dll` analysis with a native C++ desktop interface.

## Overview
TinyPEViewer is a focused Portable Executable analysis tool designed for Windows engineers, reverse engineers, and students working with binary internals. It parses PE structures directly using Windows definitions (`winnt.h`) and presents results in a structured Dear ImGui interface.

The project solves a common workflow problem: quickly inspecting PE metadata, sections, imports, and exports without loading a full disassembler. It is useful for rapid triage, debugging, malware analysis preparation, and PE format learning.

## Status Notice
> This project is in early development. Core analysis features are functional, and interfaces may continue to evolve.

## Features
| Feature | Description |
|---|---|
| PE File Loading | Opens `.exe` and `.dll` files via Windows file dialog and validates headers before parsing. |
| Header Inspection | Displays machine type, image base, entry point RVA, subsystem, section count, size metadata, and compile timestamp. |
| Section Analysis | Lists section names, addresses, sizes, raw offsets, and characteristics in sortable tables. |
| Import Analysis | Groups imported symbols by DLL and shows function names or ordinals with thunk RVAs. |
| Export Analysis | Displays exported symbols, ordinals, RVAs, and supports in-panel name filtering. |
| Defensive Parsing | Validates RVA conversions, directory bounds, and malformed tables to prevent out-of-bounds reads and crashes. |
| Native Desktop UI | Dear ImGui dark theme with tabbed panels, status bar, and consistent analysis layout. |

## Architecture
TinyPEViewer is organized into clear layers:

- Application layer: Win32 window lifecycle, DirectX 11 initialization, render loop, and file-open orchestration.
- Parsing layer: PE file loading and validation, section/import/export extraction, RVA-to-file-offset resolution.
- UI layer: Panel rendering and data presentation logic using Dear ImGui tables and tabs.

The parser and rendering paths are intentionally separated so the analysis logic remains reusable and testable outside the UI workflow.

## Quick Start
### Prerequisites
- Windows 10 or newer
- Visual Studio 2022 (Desktop development with C++)
- CMake 3.24+
- x64 toolchain

### Installation
```powershell
git clone https://github.com/omera5/TinyPEViewer.git
cd TinyPEViewer
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
```

### Run
```powershell
cmake --build build --config Release
.\build\Release\TinyPEViewer.exe
```

## Usage / Try It Out
1. Launch `TinyPEViewer.exe`.
2. Select `File -> Open...`.
3. Choose a target PE file, for example:
   - `C:\Windows\System32\notepad.exe`
   - `C:\Windows\System32\kernel32.dll`
4. Review each analysis tab:
   - `Headers`: core PE metadata and timestamp
   - `Sections`: memory and file layout
   - `Imports`: DLL dependencies and imported APIs
   - `Exports`: exported symbols with search filter
5. Validate parse state and active file path in the status bar.

## Project Structure
```text
TinyPEViewer/
├─ CMakeLists.txt
├─ README.md
├─ .gitignore
├─ external/
├─ src/
│  ├─ main.cpp
│  ├─ App.h
│  ├─ App.cpp
│  ├─ PEParser.h
│  ├─ PEParser.cpp
│  ├─ PETypes.h
│  ├─ FileDialog.h
│  ├─ FileDialog.cpp
│  ├─ Utils.h
│  ├─ Utils.cpp
│  └─ ui/
│     ├─ Panels.h
│     └─ Panels.cpp
└─ build/                     (generated)
```

- `src/App.*`: application shell, graphics initialization, main loop
- `src/PEParser.*`: PE parsing and validation logic
- `src/PETypes.h`: analysis data models
- `src/ui/Panels.*`: Dear ImGui panel rendering
- `external/`: reserved for third-party integration artifacts when needed

## API Reference
TinyPEViewer is a desktop application and does not expose HTTP endpoints. The primary integration surface is the in-process parsing API.

| API Surface | Description |
|---|---|
| `PEParser::ParseFile(const std::wstring& path, std::string& error)` | Parses a PE file and returns `std::optional<PEFile>`. |
| `PEFile::header` | Accesses parsed header metadata. |
| `PEFile::sections` | Accesses parsed section table data. |
| `PEFile::imports` | Accesses grouped import information by module. |
| `PEFile::exports` | Accesses export symbols, ordinals, and RVAs. |

### Example Request (C++)
```cpp
PEParser parser;
std::string error;
auto result = parser.ParseFile(L"C:\\Windows\\System32\\notepad.exe", error);
```

### Example Response (JSON-like Shape)
```json
{
  "file_path": "C:\\Windows\\System32\\notepad.exe",
  "header": {
    "machine": "0x8664",
    "entry_point_rva": "0x0001F6A0",
    "image_base": "0x0000000140000000",
    "subsystem": "Windows GUI",
    "number_of_sections": 7
  },
  "sections": [
    {
      "name": ".text",
      "virtual_address": "0x00001000",
      "virtual_size": "0x0001D000",
      "raw_size": "0x0001D200"
    }
  ]
}
```

## Technologies
### Backend Technologies
| Technology | Role |
|---|---|
| C++20 | Core language for parser and application logic |
| Win32 API | Native windowing and platform integration |
| DirectX 11 | Rendering backend for desktop UI |
| Windows SDK (`winnt.h`) | PE structure definitions and constants |
| CMake | Cross-toolchain build orchestration |

### Frontend Technologies
| Technology | Role |
|---|---|
| Dear ImGui | Immediate-mode user interface |
| ImGui Win32 Backend | Input and platform event integration |
| ImGui DX11 Backend | UI rendering pipeline on DirectX 11 |

## Configuration
TinyPEViewer currently requires no runtime environment variables for normal operation.

### Environment Variables
| Variable | Required | Default | Description |
|---|---|---|---|
| _None_ | No | N/A | No environment configuration is required. |

### Build Configuration Options
| Option | Default | Description |
|---|---|---|
| `-A x64` | `x64` | Builds target architecture for Windows 64-bit systems. |
| `CMAKE_BUILD_TYPE` | `Release` (multi-config generators use `--config`) | Selects optimization/debug profile. |
| `CMAKE_GENERATOR` | Visual Studio 2022 | Chooses build system generator. |

## Usage Example
```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\TinyPEViewer.exe
```

In the running UI:
1. Open `kernel32.dll`
2. Navigate to `Exports`
3. Enter `Create` in the filter box
4. Review matching exported symbols and RVAs

## Contributing
Contributions are welcome through issues and pull requests.

1. Fork the repository
2. Create a feature branch
3. Implement and test your change
4. Submit a pull request with a clear technical summary

For larger changes, open an issue first to discuss design and scope.

## License
This project is licensed under the MIT License.

## Acknowledgments
- Dear ImGui for the immediate-mode UI framework
- Microsoft Win32 and DirectX 11 platform APIs
- CMake maintainers and community tooling contributors
