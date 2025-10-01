# MFT Master (MFT Search)

MFT Master is a lightweight native GUI tool (built with Rust + eframe/egui) that indexes the NTFS Master File Table (MFT) and provides fast filename/path searching. It opens the raw volume device (e.g. \\.\C:) and parses MFT entries to build a searchable file index, showing name, path, size and extension in a simple table UI.

Important: this tool opens the raw volume device and reads low-level NTFS structures. Running it requires administrative privileges and can expose sensitive file metadata. Use responsibly.

## Features

- Directly reads the NTFS MFT from a specified drive (default: C:)
- Builds full paths by following parent references in the MFT
- Lightweight GUI with:
  - Search textbox (live filtering)
  - Columns: Name, Path, Size, Extension
  - Size formatting (bytes / KB / MB / GB)
  - Status bar showing number of results
- Multithreaded indexing so the UI remains responsive during build

## Quick snapshot of behavior

- On start the app spawns a background thread to read the MFT and index entries.
- While indexing the UI shows a spinner and status message.
- When indexing finishes, the table is populated and the search box filters results in real time.

## Requirements

- Windows (the code uses Windows-specific raw device access APIs)
- Rust toolchain (recommended: stable)
  - For MSVC target: `rustup default stable-x86_64-pc-windows-msvc`
  - Visual Studio Build Tools (C/C++ toolset) or other MSVC-compatible toolchain for linking native dependencies
- Administrator privileges to open `\\.\X:` for direct volume access

## Build

1. Install Rust: https://rustup.rs
2. Ensure you have the MSVC toolchain (on Windows):
   - Install Visual Studio Build Tools (C++ workload) or full Visual Studio with Desktop Development for C++.
   - Install the Rust MSVC target: `rustup target add x86_64-pc-windows-msvc` if needed.
3. Clone the repo and build:
   - Open an elevated (Run as administrator) PowerShell
   - cd to repo root (where Cargo.toml is)
   - Debug build: cargo build
   - Release build: cargo build --release

The compiled binary will be in `target\debug\` or release (e.g. `mft_master.exe`).

## Run

- Run the binary from an elevated terminal (Run as Administrator) because opening the raw volume requires elevated privileges.
- Example (PowerShell, as Administrator):
  - mft_master.exe

When launched the app will start indexing the MFT for drive C: by default. The UI will display a spinner while indexing completes.

## Usage

- Wait for indexing to finish (spinner + "Indexing MFT..." message).
- Type in the Search box: filtering is case-insensitive and matches against filenames.
- Browse results in the table:
  - Name — filename
  - Path — parent path (directory)
  - Size — file size (empty for directories)
  - Extension — file extension (uppercase, includes leading dot)
- The status bar shows the number of matching objects.

## Configuration / Source edits

- Default drive: the code currently constructs `MftReader::new('C')` in `SearchApp::new`. To index a different drive, change that parameter or add UI to choose the drive.
- Window size and title are set in `main()` via `eframe::NativeOptions::viewport`. Modify as desired.
- The MFT parsing implementation is intentionally minimal and focuses on filename (0x30) and data (0x80) attributes.

## Internals (brief)

- Opens the raw volume through `\\.\<DriveLetter>:` using Windows OpenOptions with share flags.
- Reads the boot sector to compute bytes/cluster and the MFT starting cluster.
- Reads MFT entries (assumes 1024 bytes per MFT record) and parses attributes:
  - FILE record signature
  - Filename attribute (0x30) to obtain name, parent reference and directory flag
  - Data attribute (0x80) to obtain size when present
- Builds full path strings by walking parent_ref entries and joining names.

## Limitations & Known issues

- The MFT parsing code is a simplified parser:
  - It may not handle all attribute layouts, compression, encrypted or complex attribute forms.
  - Parent reference parsing masks out high bits in a simplistic way — edge cases may not be fully handled.
  - Unicode filename handling uses from_utf16_lossy; some rare characters may be lost or replaced.
- Currently only indexes one drive (hard-coded in the initial thread spawn).

## Troubleshooting

- Access denied / permission errors:
  - Run the app from an elevated Administrator PowerShell.
  - Ensure no policy blocks raw device access (corporate restrictions, security products).
- Long or failing indexing:
  - The parsing code has basic checks — a malformed MFT or unexpected layout can stop the indexer. Relevant errors are printed to stderr.
- Building fails on Windows:
  - Ensure the MSVC C toolchain is installed (Visual Studio Build Tools).
  - Try `rustup default stable-x86_64-pc-windows-msvc`.
- Antivirus or Defender blocking:
  - Reading raw devices is often flagged — you may need to create an exclusion or run with explicit consent.

## Contributing

- Contributions via issues and pull requests are welcome.
- Please:
  - Open an issue to discuss larger changes first.
  - Add tests for new parsing behavior where possible.
  - Keep changes focused: improve parsing robustness, add drive selection UI, and fix known edge cases.
- Follow the repository license when contributing.

## References

- eframe / egui crates for Rust GUI: https://crates.io/crates/eframe and https://crates.io/crates/egui

## License

This repository includes a LICENSE file. See LICENSE for details.

## Todo

Add real-time updates (would need USN journal monitoring)
Add support for folders
Change edit button to be named "Size"
Add button that says "Date" up top next to size and make it filter by date
Make program not only save the db it builds, but on program re-open it can load the previous db and update it with new changes
Fix screwed up GUI sort by buttons
Under file button, save results and their details to a CSV