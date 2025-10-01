use eframe::egui;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};
use std::thread;
use std::path::PathBuf;
use regex::Regex;
use serde::{Deserialize, Serialize};

const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const VERSION: &str = "0.2.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileEntry {
    name: String,
    parent_ref: u64,
    is_directory: bool,
    full_path: Option<String>,
    extension: String,
    size: u64,
    modified_time: u64,
    drive_letter: char,
}

#[derive(Clone, Copy, PartialEq)]
enum SortColumn {
    Name,
    Path,
    Size,
    Extension,
}

#[derive(Clone, Copy, PartialEq)]
enum SortOrder {
    Ascending,
    Descending,
}

#[derive(Serialize, Deserialize)]
struct DatabaseCache {
    entries: HashMap<u64, FileEntry>,
    drive_letter: char,
    timestamp: u64,
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

    fn get_available_drives() -> Vec<char> {
        let mut drives = Vec::new();
        for letter in 'A'..='Z' {
            let path = format!("\\\\.\\{}:", letter);
            if std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(&path)
                .is_ok()
            {
                drives.push(letter);
            }
        }
        drives
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
        let mut modified_time = 0u64;

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
                if let Some((name, parent, is_dir, namespace, mtime)) = 
                    self.parse_filename_attribute(&data[offset..offset + attr_length]) {
                    
                    if best_name.is_empty() || namespace == 1 || namespace == 3 {
                        best_name = name;
                        parent_ref = parent;
                        is_directory = is_dir;
                        modified_time = mtime;
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
                modified_time,
                drive_letter: self.drive_letter,
            })
        } else {
            None
        }
    }

    fn parse_filename_attribute(&self, attr_data: &[u8]) -> Option<(String, u64, bool, u8, u64)> {
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

        // Parse modification time (8 bytes starting at offset 24)
        let modified_time = if content_offset + 32 <= attr_data.len() {
            u64::from_le_bytes([
                content[24], content[25], content[26], content[27],
                content[28], content[29], content[30], content[31],
            ])
        } else {
            0
        };

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
        
        Some((name, parent_ref, is_directory, namespace, modified_time))
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

    fn save_to_cache(&self, cache_path: &PathBuf) -> std::io::Result<()> {
        let cache = DatabaseCache {
            entries: self.entries.clone(),
            drive_letter: self.drive_letter,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let serialized = bincode::serialize(&cache)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        let mut file = std::fs::File::create(cache_path)?;
        file.write_all(&serialized)?;
        Ok(())
    }

    fn load_from_cache(cache_path: &PathBuf, drive_letter: char) -> std::io::Result<Self> {
        let data = std::fs::read(cache_path)?;
        let cache: DatabaseCache = bincode::deserialize(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        if cache.drive_letter != drive_letter {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Drive letter mismatch"
            ));
        }
        
        Ok(Self {
            entries: cache.entries,
            drive_letter: cache.drive_letter,
        })
    }
}

struct SearchApp {
    all_entries: Arc<Mutex<HashMap<char, HashMap<u64, FileEntry>>>>,
    search_query: String,
    use_regex: bool,
    filtered_results: Vec<FileEntry>,
    loading: bool,
    status_message: String,
    sort_column: SortColumn,
    sort_order: SortOrder,
    min_size_filter: String,
    max_size_filter: String,
    min_date_filter: String,
    max_date_filter: String,
    show_about: bool,
}

impl SearchApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let app = Self {
            all_entries: Arc::new(Mutex::new(HashMap::new())),
            search_query: String::new(),
            use_regex: false,
            filtered_results: Vec::new(),
            loading: true,
            status_message: "Indexing drives...".to_string(),
            sort_column: SortColumn::Name,
            sort_order: SortOrder::Ascending,
            min_size_filter: String::new(),
            max_size_filter: String::new(),
            min_date_filter: String::new(),
            max_date_filter: String::new(),
            show_about: false,
        };

        let all_entries = app.all_entries.clone();
        let ctx = cc.egui_ctx.clone();
        
        thread::spawn(move || {
            let drives = MftReader::get_available_drives();
            let cache_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .unwrap_or_else(|| PathBuf::from("."));

            for drive in drives {
                let cache_path = cache_dir.join(format!("mft_cache_{}.bin", drive));
                
                let mut reader = if cache_path.exists() {
                    match MftReader::load_from_cache(&cache_path, drive) {
                        Ok(r) => r,
                        Err(_) => MftReader::new(drive),
                    }
                } else {
                    MftReader::new(drive)
                };

                match reader.read_mft() {
                    Ok(_) => {
                        let _ = reader.save_to_cache(&cache_path);
                        all_entries.lock().unwrap().insert(drive, reader.entries);
                        ctx.request_repaint();
                    }
                    Err(e) => {
                        eprintln!("Error reading MFT for drive {}: {}", drive, e);
                    }
                }
            }
        });

        app
    }

    fn update_search(&mut self) {
        // Collect entries while holding the lock, then drop the lock immediately by
        // ending this inner scope so we can mutate self later.
        let all_entries: Vec<FileEntry> = {
            let entries = self.all_entries.lock().unwrap();
            entries
                .values()
                .flat_map(|drive_entries| drive_entries.values().cloned())
                .collect()
        };

        let query_lower = self.search_query.to_lowercase();
        let regex = if self.use_regex && !self.search_query.is_empty() {
            Regex::new(&self.search_query).ok()
        } else {
            None
        };

        let min_size = self.parse_size(&self.min_size_filter);
        let max_size = self.parse_size(&self.max_size_filter);

        self.filtered_results.clear();

        for mut entry in all_entries {
            // Only include entries that have a built full_path
            if entry.full_path.is_some() {
                let name_lower = entry.name.to_lowercase();

                let matches_search = if let Some(ref re) = regex {
                    re.is_match(&entry.name)
                } else {
                    query_lower.is_empty() || name_lower.contains(&query_lower)
                };

                let matches_size = (min_size.is_none() || entry.size >= min_size.unwrap())
                    && (max_size.is_none() || entry.size <= max_size.unwrap());

                if matches_search && matches_size {
                    self.filtered_results.push(entry);
                }
            }
        }

        self.apply_sort();
        self.status_message = format!("{} objects", self.filtered_results.len());
    }

    fn apply_sort(&mut self) {
        match self.sort_column {
            SortColumn::Name => {
                self.filtered_results.sort_by(|a, b| {
                    let cmp = a.name.to_lowercase().cmp(&b.name.to_lowercase());
                    if self.sort_order == SortOrder::Ascending { cmp } else { cmp.reverse() }
                });
            }
            SortColumn::Path => {
                self.filtered_results.sort_by(|a, b| {
                    let path_a = a.full_path.as_ref().unwrap().to_lowercase();
                    let path_b = b.full_path.as_ref().unwrap().to_lowercase();
                    let cmp = path_a.cmp(&path_b);
                    if self.sort_order == SortOrder::Ascending { cmp } else { cmp.reverse() }
                });
            }
            SortColumn::Size => {
                self.filtered_results.sort_by(|a, b| {
                    let cmp = a.size.cmp(&b.size);
                    if self.sort_order == SortOrder::Ascending { cmp } else { cmp.reverse() }
                });
            }
            SortColumn::Extension => {
                self.filtered_results.sort_by(|a, b| {
                    let cmp = a.extension.cmp(&b.extension);
                    if self.sort_order == SortOrder::Ascending { cmp } else { cmp.reverse() }
                });
            }
        }
    }

    fn parse_size(&self, input: &str) -> Option<u64> {
        if input.is_empty() {
            return None;
        }

        let input = input.trim().to_uppercase();
        let (num_str, multiplier) = if input.ends_with("GB") {
            (input.trim_end_matches("GB"), 1024u64 * 1024 * 1024)
        } else if input.ends_with("MB") {
            (input.trim_end_matches("MB"), 1024u64 * 1024)
        } else if input.ends_with("KB") {
            (input.trim_end_matches("KB"), 1024u64)
        } else {
            (input.as_str(), 1u64)
        };

        num_str.trim().parse::<u64>().ok().map(|n| n * multiplier)
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

    fn export_to_csv(&self) -> std::io::Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let filename = format!("mft_results_{}.csv", timestamp);
        
        let mut file = std::fs::File::create(&filename)?;
        writeln!(file, "Name,Path,Size,Extension,Drive")?;
        
        for entry in &self.filtered_results {
            let parent_path = if let Some(path) = &entry.full_path {
                if let Some(pos) = path.rfind('\\') {
                    &path[..pos]
                } else {
                    path.as_str()
                }
            } else {
                ""
            };
            
            writeln!(
                file,
                "\"{}\",\"{}\",{},\"{}\",{}",
                entry.name.replace("\"", "\"\""),
                parent_path.replace("\"", "\"\""),
                entry.size,
                entry.extension,
                entry.drive_letter
            )?;
        }
        
        Ok(())
    }

    fn show_about_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("About MFT Master")
            .open(&mut self.show_about)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("MFT Master");
                    ui.label(format!("Version {}", VERSION));
                    ui.add_space(10.0);
                    ui.label("A fast NTFS file search tool");
                    ui.add_space(10.0);
                    ui.label("Inspired by Everything by voidtools");
                    ui.hyperlink_to("voidtools.com", "https://www.voidtools.com/");
                    ui.add_space(10.0);
                    ui.label("Licensed under GNU GPL v3");
                });
            });
    }
}

impl eframe::App for SearchApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.loading {
            let has_data = { !self.all_entries.lock().unwrap().is_empty() };
            if has_data {
                self.loading = false;
                self.update_search();
            }
        }

        if self.show_about {
            self.show_about_dialog(ctx);
        }

        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Export Results to CSV").clicked() {
                        if let Err(e) = self.export_to_csv() {
                            eprintln!("Failed to export CSV: {}", e);
                        } else {
                            self.status_message = "Results exported to CSV".to_string();
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                
                ui.menu_button("Edit", |ui| {
                    ui.label("Size Filter:");
                    ui.horizontal(|ui| {
                        ui.label("Min:");
                        let response = ui.text_edit_singleline(&mut self.min_size_filter);
                        if response.changed() {
                            self.update_search();
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Max:");
                        let response = ui.text_edit_singleline(&mut self.max_size_filter);
                        if response.changed() {
                            self.update_search();
                        }
                    });
                    ui.label("(Use format: 100MB, 5GB, 1024KB)");
                });
                
                ui.menu_button("View", |ui| {
                    if ui.button("Refresh Index").clicked() {
                        self.loading = true;
                        self.status_message = "Re-indexing drives...".to_string();
                        ui.close_menu();
                    }
                });
                
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                        ui.close_menu();
                    }
                });
            });
        });

        egui::TopBottomPanel::top("search_bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.label("Search:");
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .desired_width(ui.available_width() - 100.0)
                );
                
                if response.changed() {
                    self.update_search();
                }

                if ui.checkbox(&mut self.use_regex, "Regex").changed() {
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
                        if ui.button("Path ↕").clicked() {
                            if self.sort_column == SortColumn::Path {
                                self.sort_order = match self.sort_order {
                                    SortOrder::Ascending => SortOrder::Descending,
                                    SortOrder::Descending => SortOrder::Ascending,
                                };
                            } else {
                                self.sort_column = SortColumn::Path;
                                self.sort_order = SortOrder::Ascending;
                            }
                            self.apply_sort();
                        }
                    });
                    header.col(|ui| {
                        if ui.button("Size ↕").clicked() {
                            if self.sort_column == SortColumn::Size {
                                self.sort_order = match self.sort_order {
                                    SortOrder::Ascending => SortOrder::Descending,
                                    SortOrder::Descending => SortOrder::Ascending,
                                };
                            } else {
                                self.sort_column = SortColumn::Size;
                                self.sort_order = SortOrder::Ascending;
                            }
                            self.apply_sort();
                        }
                    });
                    header.col(|ui| {
                        if ui.button("Extension ↕").clicked() {
                            if self.sort_column == SortColumn::Extension {
                                self.sort_order = match self.sort_order {
                                    SortOrder::Ascending => SortOrder::Descending,
                                    SortOrder::Descending => SortOrder::Ascending,
                                };
                            } else {
                                self.sort_column = SortColumn::Extension;
                                self.sort_order = SortOrder::Ascending;
                            }
                            self.apply_sort();
                        }
                    });
                    header.col(|ui| {
                       if ui.button("Name ↕").clicked() {
                            if self.sort_column == SortColumn::Name {
                                self.sort_order = match self.sort_order {
                                    SortOrder::Ascending => SortOrder::Descending,
                                    SortOrder::Descending => SortOrder::Ascending,
                                };
                            } else {
                                self.sort_column = SortColumn::Name;
                                self.sort_order = SortOrder::Ascending;
                            }
                            self.apply_sort();
                        }
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
            .with_title("MFT Master"),
        ..Default::default()
    };
    
    eframe::run_native(
        "MFT Master",
        options,
        Box::new(|cc| Ok(Box::new(SearchApp::new(cc)))),
    )
}