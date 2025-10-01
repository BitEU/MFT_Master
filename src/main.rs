use eframe::egui;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};
use std::thread;

const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;

#[derive(Debug, Clone)]
struct FileEntry {
    name: String,
    parent_ref: u64,
    is_directory: bool,
    full_path: Option<String>,
    extension: String,
    size: u64,
}

struct MftReader {
    entries: HashMap<u64, FileEntry>,
    drive_letter: char,
}

impl MftReader {
    fn new(drive_letter: char) -> Self {
        Self {
            entries: HashMap::new(),
            drive_letter,
        }
    }

    fn read_mft(&mut self) -> std::io::Result<()> {
        let mft_path = format!("\\\\.\\{}:", self.drive_letter);
        
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&mft_path)?;

        let mut boot_sector = vec![0u8; 512];
        file.read_exact(&mut boot_sector)?;

        let bytes_per_sector = u16::from_le_bytes([boot_sector[11], boot_sector[12]]) as u64;
        let sectors_per_cluster = boot_sector[13] as u64;
        let bytes_per_cluster = bytes_per_sector * sectors_per_cluster;
        
        let mft_cluster = u64::from_le_bytes([
            boot_sector[48], boot_sector[49], boot_sector[50], boot_sector[51],
            boot_sector[52], boot_sector[53], boot_sector[54], boot_sector[55],
        ]);

        let mft_offset = mft_cluster * bytes_per_cluster;
        
        file.seek(SeekFrom::Start(mft_offset))?;
        let mut mft_entry = vec![0u8; 1024];
        file.read_exact(&mut mft_entry)?;

        let mft_size = self.get_mft_size(&mft_entry)?;
        let entry_size = 1024u64;
        let total_entries = mft_size / entry_size;

        let mut buffer = vec![0u8; (entry_size * 100) as usize];

        for chunk_start in (0..total_entries).step_by(100) {
            let entries_in_chunk = std::cmp::min(100, total_entries - chunk_start);
            let bytes_to_read = (entries_in_chunk * entry_size) as usize;
            
            let offset = mft_offset + (chunk_start * entry_size);
            file.seek(SeekFrom::Start(offset))?;
            
            if file.read_exact(&mut buffer[..bytes_to_read]).is_err() {
                break;
            }

            for i in 0..entries_in_chunk {
                let entry_offset = (i * entry_size) as usize;
                let entry_data = &buffer[entry_offset..entry_offset + entry_size as usize];
                let entry_num = chunk_start + i;

                if let Some(file_entry) = self.parse_mft_entry(entry_data, entry_num) {
                    self.entries.insert(entry_num, file_entry);
                }
            }
        }

        self.build_paths();
        
        Ok(())
    }

    fn get_mft_size(&self, mft_entry: &[u8]) -> std::io::Result<u64> {
        if &mft_entry[0..4] != b"FILE" {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid MFT entry"));
        }

        let first_attr_offset = u16::from_le_bytes([mft_entry[20], mft_entry[21]]) as usize;
        let mut offset = first_attr_offset;

        while offset + 16 < mft_entry.len() {
            let attr_type = u32::from_le_bytes([
                mft_entry[offset], mft_entry[offset + 1], 
                mft_entry[offset + 2], mft_entry[offset + 3]
            ]);
            
            if attr_type == 0xFFFFFFFF {
                break;
            }

            let attr_length = u32::from_le_bytes([
                mft_entry[offset + 4], mft_entry[offset + 5], 
                mft_entry[offset + 6], mft_entry[offset + 7]
            ]) as usize;

            if attr_length == 0 || offset + attr_length > mft_entry.len() {
                break;
            }

            if attr_type == 0x80 {
                let non_resident_flag = mft_entry[offset + 8];
                
                if non_resident_flag != 0 {
                    if offset + 40 <= mft_entry.len() {
                        let allocated_size = u64::from_le_bytes([
                            mft_entry[offset + 40], mft_entry[offset + 41],
                            mft_entry[offset + 42], mft_entry[offset + 43],
                            mft_entry[offset + 44], mft_entry[offset + 45],
                            mft_entry[offset + 46], mft_entry[offset + 47],
                        ]);
                        return Ok(allocated_size);
                    }
                }
            }

            offset += attr_length;
        }

        Ok(1024 * 100000)
    }

    fn parse_mft_entry(&self, data: &[u8], _entry_num: u64) -> Option<FileEntry> {
        if data.len() < 4 || &data[0..4] != b"FILE" {
            return None;
        }

        if data.len() < 23 || (data[22] & 0x01) == 0 {
            return None;
        }

        let mut best_name = String::new();
        let mut parent_ref = 0u64;
        let mut is_directory = false;
        let mut size = 0u64;

        let first_attr_offset = u16::from_le_bytes([data[20], data[21]]) as usize;
        let mut offset = first_attr_offset;

        while offset + 16 < data.len() {
            let attr_type = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]);
            
            if attr_type == 0xFFFFFFFF {
                break;
            }

            let attr_length = u32::from_le_bytes([
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]) as usize;

            if attr_length == 0 || offset + attr_length > data.len() {
                break;
            }

            if attr_type == 0x30 {
                if let Some((name, parent, is_dir, namespace)) = 
                    self.parse_filename_attribute(&data[offset..offset + attr_length]) {
                    
                    if best_name.is_empty() || namespace == 1 || namespace == 3 {
                        best_name = name;
                        parent_ref = parent;
                        is_directory = is_dir;
                    }
                }
            } else if attr_type == 0x80 {
                let non_resident_flag = data[offset + 8];
                if non_resident_flag == 0 && offset + 24 <= data.len() {
                    let content_length = u32::from_le_bytes([
                        data[offset + 16], data[offset + 17],
                        data[offset + 18], data[offset + 19]
                    ]) as u64;
                    size = content_length;
                } else if non_resident_flag != 0 && offset + 48 <= data.len() {
                    size = u64::from_le_bytes([
                        data[offset + 48], data[offset + 49],
                        data[offset + 50], data[offset + 51],
                        data[offset + 52], data[offset + 53],
                        data[offset + 54], data[offset + 55],
                    ]);
                }
            }

            offset += attr_length;
        }

        if !best_name.is_empty() && !best_name.contains('\0') {
            let extension = if let Some(pos) = best_name.rfind('.') {
                best_name[pos..].to_uppercase()
            } else {
                String::new()
            };

            Some(FileEntry {
                name: best_name,
                parent_ref,
                is_directory,
                full_path: None,
                extension,
                size,
            })
        } else {
            None
        }
    }

    fn parse_filename_attribute(&self, attr_data: &[u8]) -> Option<(String, u64, bool, u8)> {
        if attr_data.len() < 66 {
            return None;
        }

        let non_resident = attr_data[8];
        if non_resident != 0 {
            return None;
        }

        let content_offset = u16::from_le_bytes([attr_data[20], attr_data[21]]) as usize;
        
        if content_offset + 66 > attr_data.len() {
            return None;
        }

        let content = &attr_data[content_offset..];

        let parent_ref = u64::from_le_bytes([
            content[0], content[1], content[2], content[3],
            content[4], content[5], 0, 0
        ]) & 0x0000FFFFFFFFFFFF;

        if content_offset + 60 > attr_data.len() {
            return None;
        }
        let flags = u32::from_le_bytes([
            content[56], content[57], content[58], content[59]
        ]);
        let is_directory = (flags & 0x10000000) != 0;

        if content_offset + 65 > attr_data.len() {
            return None;
        }
        let name_length = content[64] as usize;
        let namespace = content[65];

        let name_start = 66;
        let name_end = name_start + (name_length * 2);
        
        if content_offset + name_end > attr_data.len() {
            return None;
        }

        let mut name_u16 = Vec::with_capacity(name_length);
        for i in 0..name_length {
            let byte_offset = name_start + (i * 2);
            if byte_offset + 1 < content.len() {
                let char_val = u16::from_le_bytes([
                    content[byte_offset],
                    content[byte_offset + 1]
                ]);
                name_u16.push(char_val);
            }
        }

        let name = String::from_utf16_lossy(&name_u16);
        
        Some((name, parent_ref, is_directory, namespace))
    }

    fn build_paths(&mut self) {
        let entries_clone: Vec<(u64, FileEntry)> = 
            self.entries.iter().map(|(k, v)| (*k, v.clone())).collect();

        for (entry_ref, entry) in entries_clone {
            let path = self.build_full_path(entry_ref, &entry);
            if let Some(e) = self.entries.get_mut(&entry_ref) {
                e.full_path = Some(path);
            }
        }
    }

    fn build_full_path(&self, entry_ref: u64, entry: &FileEntry) -> String {
        if entry.parent_ref == 5 || entry.parent_ref == entry_ref {
            return format!("{}:\\{}", self.drive_letter, entry.name);
        }

        let mut path_parts = vec![entry.name.clone()];
        let mut current_ref = entry.parent_ref;
        let mut seen = std::collections::HashSet::new();
        seen.insert(entry_ref);

        for _ in 0..100 {
            if seen.contains(&current_ref) {
                break;
            }
            seen.insert(current_ref);

            if let Some(parent) = self.entries.get(&current_ref) {
                if current_ref == 5 || parent.parent_ref == current_ref {
                    break;
                }
                path_parts.push(parent.name.clone());
                current_ref = parent.parent_ref;
            } else {
                break;
            }
        }

        path_parts.reverse();
        format!("{}:\\{}", self.drive_letter, path_parts.join("\\"))
    }
}

struct SearchApp {
    mft_data: Arc<Mutex<Option<MftReader>>>,
    search_query: String,
    filtered_results: Vec<FileEntry>,
    loading: bool,
    status_message: String,
    scroll_offset: f32,
}

impl SearchApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let app = Self {
            mft_data: Arc::new(Mutex::new(None)),
            search_query: String::new(),
            filtered_results: Vec::new(),
            loading: true,
            status_message: "Indexing drive C:...".to_string(),
            scroll_offset: 0.0,
        };

        let mft_data = app.mft_data.clone();
        let ctx = cc.egui_ctx.clone();
        
        thread::spawn(move || {
            let mut reader = MftReader::new('C');
            match reader.read_mft() {
                Ok(_) => {
                    // don't create an unused variable
                    let _count = reader.entries.len();
                    *mft_data.lock().unwrap() = Some(reader);
                    ctx.request_repaint();
                }
                Err(e) => {
                    eprintln!("Error reading MFT: {}", e);
                }
            }
        });

        app
    }

    fn update_search(&mut self) {
        if let Some(reader) = self.mft_data.lock().unwrap().as_ref() {
            let query_lower = self.search_query.to_lowercase();
            
            self.filtered_results.clear();
            
            for entry in reader.entries.values() {
                if let Some(full_path) = &entry.full_path {
                    let name_lower = entry.name.to_lowercase();
                    
                    if query_lower.is_empty() || name_lower.contains(&query_lower) {
                        self.filtered_results.push(entry.clone());
                    }
                }
            }
            
            self.filtered_results.sort_by(|a, b| {
                a.full_path.as_ref().unwrap().to_lowercase()
                    .cmp(&b.full_path.as_ref().unwrap().to_lowercase())
            });

            self.status_message = format!("{} objects", self.filtered_results.len());
        }
    }

    fn format_size(size: u64) -> String {
        if size == 0 {
            return String::new();
        }
        
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        
        if size >= GB {
            format!("{:.1} GB", size as f64 / GB as f64)
        } else if size >= MB {
            format!("{:.1} MB", size as f64 / MB as f64)
        } else if size >= KB {
            format!("{} KB", size / KB)
        } else {
            format!("{} bytes", size)
        }
    }
}

impl eframe::App for SearchApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.loading {
            // Check for presence of data while ensuring the mutex guard is dropped
            let has_data = { self.mft_data.lock().unwrap().is_some() };
            if has_data {
                self.loading = false;
                self.update_search();
            }
        }

        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Edit", |_ui| {});
                ui.menu_button("View", |_ui| {});
                ui.menu_button("Search", |_ui| {});
                ui.menu_button("Bookmarks", |_ui| {});
                ui.menu_button("Tools", |_ui| {});
                ui.menu_button("Help", |_ui| {});
            });
        });

        egui::TopBottomPanel::top("search_bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.label("Search:");
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .desired_width(ui.available_width() - 8.0)
                );
                
                if response.changed() {
                    self.update_search();
                }
            });
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.label(&self.status_message);
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.loading {
                ui.vertical_centered(|ui| {
                    ui.add_space(100.0);
                    ui.spinner();
                    ui.label("Indexing MFT...");
                });
                return;
            }

            use egui_extras::{Column, TableBuilder};
            
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto().at_least(300.0))
                .column(Column::auto().at_least(400.0))
                .column(Column::auto().at_least(60.0))
                .column(Column::auto().at_least(60.0))
                .header(20.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("Name");
                    });
                    header.col(|ui| {
                        ui.strong("Path");
                    });
                    header.col(|ui| {
                        ui.strong("Size");
                    });
                    header.col(|ui| {
                        ui.strong("Extension");
                    });
                })
                .body(|body| {
                    body.rows(18.0, self.filtered_results.len(), |mut row| {
                        let index = row.index();
                        if let Some(entry) = self.filtered_results.get(index) {
                            row.col(|ui| {
                                ui.label(&entry.name);
                            });
                            row.col(|ui| {
                                if let Some(path) = &entry.full_path {
                                    let parent_path = if let Some(pos) = path.rfind('\\') {
                                        &path[..pos]
                                    } else {
                                        path
                                    };
                                    ui.label(parent_path);
                                }
                            });
                            row.col(|ui| {
                                if !entry.is_directory {
                                    ui.label(Self::format_size(entry.size));
                                }
                            });
                            row.col(|ui| {
                                if !entry.extension.is_empty() {
                                    ui.label(&entry.extension);
                                }
                            });
                        }
                    });
                });
        });

        ctx.request_repaint();
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 700.0])
            .with_title("MFT Search"),
        ..Default::default()
    };
    
    eframe::run_native(
        "MFT Search",
        options,
        Box::new(|cc| Ok(Box::new(SearchApp::new(cc)))),
    )
}