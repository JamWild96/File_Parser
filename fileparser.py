#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import tkinter as tk
from tkinter import filedialog, ttk
from datetime import datetime
import subprocess
import platform

class FileInfoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File and Folder Information Tool")
        self.root.geometry("1200x900")

        # Create GUI elements
        self.setup_ui()

    def setup_ui(self):
        # Top frame for file/folder selection
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Select file or folder:").pack(side=tk.LEFT)

        self.path_var = tk.StringVar()
        ttk.Entry(top_frame, textvariable=self.path_var, width=60).pack(side=tk.LEFT, padx=5)

        ttk.Button(top_frame, text="Browse File", command=self.browse_file).pack(side=tk.LEFT)
        ttk.Button(top_frame, text="Browse Folder", command=self.browse_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Analyze", command=self.analyze_path).pack(side=tk.LEFT, padx=5)

        # Checkbox for recursive folder analysis
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top_frame, text="Analyze Recursively", variable=self.recursive_var).pack(side=tk.LEFT, padx=5)

        # Results area
        result_frame = ttk.LabelFrame(self.root, text="Information", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create text widget with scrollbar for results
        scrollbar = ttk.Scrollbar(result_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.result_text = tk.Text(result_frame, wrap=tk.WORD, width=80, height=30, yscrollcommand=scrollbar.set)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.result_text.yview)

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select a file",
            filetypes=(("All files", "*.*"),)
        )
        if filename:
            self.path_var.set(filename)

    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select a folder")
        if folder:
            self.path_var.set(folder)

    def analyze_path(self):
        path = self.path_var.get()
        if not path or not os.path.exists(path):
            self.show_result("Please select a valid file or folder.")
            return

        try:
            if os.path.isfile(path):
                self.analyze_file(path)
            else:  # It's a directory
                self.analyze_folder(path)
        except Exception as e:
            self.show_result(f"Error during analysis: {str(e)}")

    def analyze_file(self, file_path, indent="", inside_folder=False):
        try:
            # Get file stats
            stats = os.stat(file_path)

            # Calculate file checksums
            file_md5 = self.calculate_file_checksum(file_path, "md5")
            file_sha1 = self.calculate_file_checksum(file_path, "sha1")

            # Format dates
            mod_time = datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            access_time = datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S')

            # Get additional date info if on macOS
            opened_time = "Not available"
            if platform.system() == 'Darwin':
                opened_time = self.get_mac_last_opened(file_path)

            # Get creation time
            if hasattr(stats, 'st_birthtime'):  # macOS
                birth_time = datetime.fromtimestamp(stats.st_birthtime).strftime('%Y-%m-%d %H:%M:%S')
            else:
                birth_time = datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')

            # Prepare result
            result = ""
            if not inside_folder:  # If not part of folder analysis, show header
                result = f"File Information for: {os.path.basename(file_path)}\n"
                result += f"{'='*80}\n\n"

            result += f"{indent}Name: {os.path.basename(file_path)}\n"
            result += f"{indent}Type: File\n"
            result += f"{indent}Full Path: {file_path}\n"
            result += f"{indent}Size: {self.format_size(stats.st_size)}\n\n"

            result += f"{indent}Last Modified: {mod_time}\n"
            result += f"{indent}Last Accessed: {access_time}\n"
            result += f"{indent}Created: {birth_time}\n"
            result += f"{indent}Last Opened: {opened_time}\n\n"

            result += f"{indent}File Checksums:\n"
            result += f"{indent}MD5: {file_md5}\n"
            result += f"{indent}SHA1: {file_sha1}\n"

            # Try to analyze content if it's a text file
            try:
                if self.is_text_file(file_path):
                    with open(file_path, 'r', errors='replace') as f:
                        content = f.read()

                    result += f"\n{indent}Content Analysis:\n"
                    result += f"{indent}Text Length: {len(content)} characters\n"
                    result += f"{indent}Line Count: {content.count(os.linesep) + 1}\n"

                    # Calculate content checksum
                    content_md5 = hashlib.md5(content.encode('utf-8')).hexdigest()
                    result += f"{indent}Content MD5: {content_md5}\n"
            except:
                result += f"\n{indent}Content analysis not available (binary or inaccessible file)"

            if not inside_folder:  # If standalone file analysis
                self.show_result(result)
            return result

        except Exception as e:
            if not inside_folder:
                self.show_result(f"Error analyzing file: {str(e)}")
            return f"{indent}Error analyzing file: {str(e)}"

    def analyze_folder(self, folder_path, indent=""):
        try:
            stats = os.stat(folder_path)

            # Format dates
            mod_time = datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            access_time = datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S')

            # Get additional date info if on macOS
            opened_time = "Not available"
            if platform.system() == 'Darwin':
                opened_time = self.get_mac_last_opened(folder_path)

            # Get creation time
            if hasattr(stats, 'st_birthtime'):  # macOS
                birth_time = datetime.fromtimestamp(stats.st_birthtime).strftime('%Y-%m-%d %H:%M:%S')
            else:
                birth_time = datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')

            # Folder info
            result = f"Folder Information for: {os.path.basename(folder_path)}\n"
            result += f"{'='*80}\n\n"
            result += f"{indent}Name: {os.path.basename(folder_path)}\n"
            result += f"{indent}Type: Folder/Directory\n"
            result += f"{indent}Full Path: {folder_path}\n\n"
            result += f"{indent}Last Modified: {mod_time}\n"
            result += f"{indent}Last Accessed: {access_time}\n"
            result += f"{indent}Created: {birth_time}\n"
            result += f"{indent}Last Opened: {opened_time}\n\n"

            # List contents
            items = os.listdir(folder_path)
            result += f"{indent}Contents: {len(items)} items\n"

            # Calculate collective checksum for folder (hashes of all filenames and their sizes)
            folder_hash = hashlib.md5()
            for item in sorted(items):
                item_path = os.path.join(folder_path, item)
                try:
                    item_stat = os.stat(item_path)
                    folder_hash.update(f"{item}:{item_stat.st_size}:{item_stat.st_mtime}".encode())
                except:
                    folder_hash.update(f"{item}:error".encode())

            result += f"{indent}Folder Checksum: {folder_hash.hexdigest()} (based on names, sizes, and modification times)\n\n"

            # Show contents if recursive is enabled
            result += f"{indent}Contents Details:\n"
            result += f"{indent}{'-'*40}\n\n"

            for item in sorted(items):
                item_path = os.path.join(folder_path, item)
                try:
                    if os.path.isfile(item_path):
                        result += self.analyze_file(item_path, indent + "  ", True)
                    else:
                        # For subdirectories, we provide folder info
                        sub_stats = os.stat(item_path)
                        sub_mod_time = datetime.fromtimestamp(sub_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        sub_access_time = datetime.fromtimestamp(sub_stats.st_atime).strftime('%Y-%m-%d %H:%M:%S')

                        if hasattr(sub_stats, 'st_birthtime'):
                            sub_birth_time = datetime.fromtimestamp(sub_stats.st_birthtime).strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            sub_birth_time = datetime.fromtimestamp(sub_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')

                        sub_opened_time = "Not available"
                        if platform.system() == 'Darwin':
                            sub_opened_time = self.get_mac_last_opened(item_path)

                        # Calculate folder checksum
                        sub_folder_hash = hashlib.md5()
                        try:
                            sub_items = os.listdir(item_path)
                            for sub_item in sorted(sub_items):
                                sub_item_path = os.path.join(item_path, sub_item)
                                try:
                                    sub_item_stat = os.stat(sub_item_path)
                                    sub_folder_hash.update(f"{sub_item}:{sub_item_stat.st_size}:{sub_item_stat.st_mtime}".encode())
                                except:
                                    sub_folder_hash.update(f"{sub_item}:error".encode())
                        except:
                            pass

                        result += f"{indent}  [Folder] {os.path.basename(item_path)}\n"
                        result += f"{indent}    Path: {item_path}\n"
                        result += f"{indent}    Last Modified: {sub_mod_time}\n"
                        result += f"{indent}    Last Accessed: {sub_access_time}\n"
                        result += f"{indent}    Created: {sub_birth_time}\n"
                        result += f"{indent}    Last Opened: {sub_opened_time}\n"
                        result += f"{indent}    Folder Checksum: {sub_folder_hash.hexdigest()}\n"

                        try:
                            sub_items = os.listdir(item_path)
                            result += f"{indent}    Content Count: {len(sub_items)} items\n"

                            # If recursive, analyze contents of this subfolder too
                            if self.recursive_var.get():
                                result += f"\n{indent}    Subfolder Contents:\n"
                                result += f"{indent}    {'-'*36}\n\n"

                                for sub_item in sorted(sub_items):
                                    sub_item_path = os.path.join(item_path, sub_item)
                                    if os.path.isfile(sub_item_path):
                                        # Analyze each file and show its checksum
                                        result += self.analyze_file(sub_item_path, indent + "      ", True)
                                        result += f"\n{indent}    {'-'*36}\n\n"
                                    elif os.path.isdir(sub_item_path) and self.recursive_var.get():
                                        # For sub-subdirectories, just show basic info with checksums
                                        subsub_stats = os.stat(sub_item_path)
                                        subsub_mod_time = datetime.fromtimestamp(subsub_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

                                        # Calculate folder checksum
                                        subsub_folder_hash = hashlib.md5()
                                        try:
                                            subsub_items = os.listdir(sub_item_path)
                                            for subsub_item in sorted(subsub_items):
                                                subsub_item_path = os.path.join(sub_item_path, subsub_item)
                                                try:
                                                    subsub_item_stat = os.stat(subsub_item_path)
                                                    subsub_folder_hash.update(f"{subsub_item}:{subsub_item_stat.st_size}:{subsub_item_stat.st_mtime}".encode())
                                                except:
                                                    subsub_folder_hash.update(f"{subsub_item}:error".encode())
                                        except:
                                            pass

                                        result += f"{indent}      [Subfolder] {os.path.basename(sub_item_path)}\n"
                                        result += f"{indent}        Path: {sub_item_path}\n"
                                        result += f"{indent}        Last Modified: {subsub_mod_time}\n"
                                        result += f"{indent}        Folder Checksum: {subsub_folder_hash.hexdigest()}\n"
                                        result += f"{indent}        Content Count: {len(os.listdir(sub_item_path))} items\n"
                                        result += f"\n{indent}    {'-'*36}\n\n"
                        except Exception as e:
                            result += f"{indent}    Error accessing contents: {str(e)}\n"

                    result += f"\n{indent}{'-'*40}\n\n"
                except Exception as e:
                    result += f"{indent}  Error processing {item}: {str(e)}\n\n"
                    result += f"{indent}{'-'*40}\n\n"

            self.show_result(result)

        except Exception as e:
            self.show_result(f"Error analyzing folder: {str(e)}")

    def get_mac_last_opened(self, file_path):
        """Use macOS mdls command to get last opened date if available"""
        try:
            result = subprocess.run(['mdls', '-name', 'kMDItemLastUsedDate', file_path],
                                   capture_output=True, text=True, check=False)
            if result.returncode == 0:
                output = result.stdout.strip()
                if "null" not in output:
                    date_str = output.split('=')[-1].strip()
                    # Return the macOS date format
                    if date_str:
                        return date_str
        except Exception:
            pass
        return "Not available"

    def show_result(self, text):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)

    def calculate_file_checksum(self, filepath, algorithm="md5"):
        hash_alg = None
        if algorithm.lower() == "md5":
            hash_alg = hashlib.md5()
        elif algorithm.lower() == "sha1":
            hash_alg = hashlib.sha1()
        elif algorithm.lower() == "sha256":
            hash_alg = hashlib.sha256()
        else:
            return "Unsupported algorithm"

        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_alg.update(chunk)
            return hash_alg.hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"

    def format_size(self, size_bytes):
        # Format file size in human-readable format
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0

    def is_text_file(self, filepath, sample_size=8192):
        try:
            with open(filepath, 'rb') as f:
                sample = f.read(sample_size)
                if b'\0' in sample:  # Null bytes suggest binary file
                    return False

                # Try decoding as text
                sample.decode('utf-8')
                return True
        except:
            return False

if __name__ == "__main__":
    root = tk.Tk()
    app = FileInfoApp(root)
    root.mainloop()
