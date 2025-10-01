use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;

const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;

#[derive(Debug, Clone)]
struct FileEntry {
    name: String,
    parent_ref: u64,
    is_directory: bool,
    full_path: Option<String>,
}

struct MftReader {
    entries: HashMap<u64, FileEntry>,
    drive_letter: char,
}

impl MftReader {
    fn new(drive_letter: char) -> io::Result<Self> {
        Ok(Self {
            entries: HashMap::new(),
            drive_letter,
        })
    }

    fn read_mft(&mut self) -> io::Result<()> {
        let mft_path = format!("\\\\.\\{}:", self.drive_letter);
        
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&mft_path)?;

        // Read MFT location from boot sector
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
        
        // Read the MFT's own entry (entry 0) to get the full MFT size
        file.seek(SeekFrom::Start(mft_offset))?;
        let mut mft_entry = vec![0u8; 1024];
        file.read_exact(&mut mft_entry)?;

        // Parse entry 0 to get MFT size
        let mft_size = self.get_mft_size(&mft_entry)?;
        let entry_size = 1024u64;
        let total_entries = mft_size / entry_size;

        println!("MFT size: {} bytes", mft_size);
        println!("Total MFT entries: {}", total_entries);
        println!("Reading entries...");

        // Read all MFT entries
        let mut buffer = vec![0u8; (entry_size * 100) as usize]; // Read 100 entries at a time
        let mut entries_read = 0;

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

            entries_read += entries_in_chunk;
            if entries_read % 10000 == 0 {
                print!("\rRead {} entries...", entries_read);
                io::stdout().flush()?;
            }
        }

        println!("\rRead {} entries total", entries_read);
        println!("Building file paths...");

        // Build full paths
        self.build_paths();
        
        Ok(())
    }

    fn get_mft_size(&self, mft_entry: &[u8]) -> io::Result<u64> {
        // Check FILE signature
        if &mft_entry[0..4] != b"FILE" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid MFT entry"));
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

            // 0x80 = DATA attribute
            if attr_type == 0x80 {
                let non_resident_flag = mft_entry[offset + 8];
                
                if non_resident_flag != 0 {
                    // Non-resident - read allocated size
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

        // Default fallback
        Ok(1024 * 100000) // 100k entries as fallback
    }

    fn parse_mft_entry(&self, data: &[u8], entry_num: u64) -> Option<FileEntry> {
        // Check FILE signature
        if data.len() < 4 || &data[0..4] != b"FILE" {
            return None;
        }

        // Check if entry is in use (bit 0 of flags at offset 22)
        if data.len() < 23 || (data[22] & 0x01) == 0 {
            return None;
        }

        let mut best_name = String::new();
        let mut parent_ref = 0u64;
        let mut is_directory = false;

        // Parse attributes starting at offset 20 (first attribute offset)
        let first_attr_offset = u16::from_le_bytes([data[20], data[21]]) as usize;
        let mut offset = first_attr_offset;

        while offset + 16 < data.len() {
            let attr_type = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]);
            
            // 0xFFFFFFFF marks end of attributes
            if attr_type == 0xFFFFFFFF {
                break;
            }

            let attr_length = u32::from_le_bytes([
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]) as usize;

            if attr_length == 0 || offset + attr_length > data.len() {
                break;
            }

            // 0x30 = FILE_NAME attribute
            if attr_type == 0x30 {
                if let Some((name, parent, is_dir, namespace)) = 
                    self.parse_filename_attribute(&data[offset..offset + attr_length]) {
                    
                    // Prefer Win32 or Win32+DOS names over DOS-only or POSIX names
                    // Namespace: 0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS
                    if best_name.is_empty() || namespace == 1 || namespace == 3 {
                        best_name = name;
                        parent_ref = parent;
                        is_directory = is_dir;
                    }
                }
            }

            offset += attr_length;
        }

        if !best_name.is_empty() && !best_name.contains('\0') {
            Some(FileEntry {
                name: best_name,
                parent_ref,
                is_directory,
                full_path: None,
            })
        } else {
            None
        }
    }

    fn parse_filename_attribute(&self, attr_data: &[u8]) -> Option<(String, u64, bool, u8)> {
        if attr_data.len() < 66 {
            return None;
        }

        // Non-resident flag at offset 8
        let non_resident = attr_data[8];
        if non_resident != 0 {
            return None; // Filename attributes are always resident
        }

        // Content offset at offset 20 (for resident attributes)
        let content_offset = u16::from_le_bytes([attr_data[20], attr_data[21]]) as usize;
        
        if content_offset + 66 > attr_data.len() {
            return None;
        }

        let content = &attr_data[content_offset..];

        // Parent directory reference (first 6 bytes at offset 0)
        let parent_ref = u64::from_le_bytes([
            content[0], content[1], content[2], content[3],
            content[4], content[5], 0, 0
        ]) & 0x0000FFFFFFFFFFFF;

        // File flags at offset 56
        if content_offset + 60 > attr_data.len() {
            return None;
        }
        let flags = u32::from_le_bytes([
            content[56], content[57], content[58], content[59]
        ]);
        let is_directory = (flags & 0x10000000) != 0;

        // Filename length (in characters, not bytes) at offset 64
        if content_offset + 65 > attr_data.len() {
            return None;
        }
        let name_length = content[64] as usize;
        
        // Namespace at offset 65
        let namespace = content[65];

        // Filename starts at offset 66, UTF-16 LE
        let name_start = 66;
        let name_end = name_start + (name_length * 2);
        
        if content_offset + name_end > attr_data.len() {
            return None;
        }

        // Parse UTF-16 LE
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
            // Root directory
            return format!("{}:\\{}", self.drive_letter, entry.name);
        }

        let mut path_parts = vec![entry.name.clone()];
        let mut current_ref = entry.parent_ref;
        let mut seen = std::collections::HashSet::new();
        seen.insert(entry_ref);

        // Traverse up to root (with cycle detection)
        for _ in 0..100 {
            if seen.contains(&current_ref) {
                break; // Cycle detected
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

    fn search(&self, query: &str, folder_filter: Option<&str>, ext_filter: Option<&str>) -> Vec<String> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        for entry in self.entries.values() {
            if let Some(full_path) = &entry.full_path {
                let name_lower = entry.name.to_lowercase();
                
                // Check if name matches query
                if !name_lower.contains(&query_lower) {
                    continue;
                }

                // Check folder filter
                if let Some(folder) = folder_filter {
                    let folder_norm = folder.to_lowercase().replace('/', "\\");
                    let path_lower = full_path.to_lowercase();
                    if !path_lower.starts_with(&folder_norm) {
                        continue;
                    }
                }

                // Check extension filter
                if let Some(ext) = ext_filter {
                    let ext_with_dot = if ext.starts_with('.') {
                        ext.to_lowercase()
                    } else {
                        format!(".{}", ext.to_lowercase())
                    };
                    
                    if !name_lower.ends_with(&ext_with_dot) {
                        continue;
                    }
                }

                results.push(full_path.clone());
            }
        }

        results.sort();
        results
    }
}

fn main() -> io::Result<()> {
    println!("MFT File Search Tool");
    println!("===================");
    println!("Note: This program requires Administrator privileges to read the MFT.\n");

    print!("Enter drive letter to index (e.g., C): ");
    io::stdout().flush()?;
    let mut drive_input = String::new();
    io::stdin().read_line(&mut drive_input)?;
    let drive_letter = drive_input.trim().chars().next()
        .unwrap_or('C')
        .to_ascii_uppercase();

    println!("\nIndexing drive {}:...", drive_letter);
    let mut reader = MftReader::new(drive_letter)?;
    
    match reader.read_mft() {
        Ok(_) => {
            println!("Successfully indexed {} files/folders\n", reader.entries.len());
        }
        Err(e) => {
            eprintln!("Error reading MFT: {}", e);
            eprintln!("Make sure you're running as Administrator!");
            return Err(e);
        }
    }

    loop {
        print!("\nEnter search query (or 'quit' to exit): ");
        io::stdout().flush()?;
        let mut query = String::new();
        io::stdin().read_line(&mut query)?;
        let query = query.trim();

        if query.eq_ignore_ascii_case("quit") {
            break;
        }

        if query.is_empty() {
            continue;
        }

        print!("Filter by folder (optional, press Enter to skip): ");
        io::stdout().flush()?;
        let mut folder_filter = String::new();
        io::stdin().read_line(&mut folder_filter)?;
        let folder_filter = folder_filter.trim();
        let folder_opt = if folder_filter.is_empty() { None } else { Some(folder_filter) };

        print!("Filter by extension (optional, e.g., 'txt' or '.txt'): ");
        io::stdout().flush()?;
        let mut ext_filter = String::new();
        io::stdin().read_line(&mut ext_filter)?;
        let ext_filter = ext_filter.trim();
        let ext_opt = if ext_filter.is_empty() { None } else { Some(ext_filter) };

        let results = reader.search(query, folder_opt, ext_opt);
        
        println!("\nFound {} results:", results.len());
        for (i, result) in results.iter().take(100).enumerate() {
            println!("{}: {}", i + 1, result);
        }
        
        if results.len() > 100 {
            println!("... and {} more results (showing first 100)", results.len() - 100);
        }
    }

    Ok(())
}