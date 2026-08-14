import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import subprocess
import threading
import os
import sys
import re
import time  # 1. 導入時間模組
import ast # 需在文件開頭匯入

class SmartNuitkaPackager:
    def __init__(self, root):
        self.root = root
        self.root.title("Nuitka 智能打包大師 v3.5 - 靈活極簡版")
        self.root.geometry("850x820")
        
        self.py_path = tk.StringVar()
        self.auto_plugins = []
        self.auto_data_dirs = []
        self.auto_runtime_files = []
        
        self.plugin_rules = {
            r'PySide6': 'pyside6',
            r'PyQt5': 'pyqt5',
            r'PyQt6': 'pyqt6',
            r'OpenGL|glCompute|glGenBuffers': 'PyOpenGL', 
            r'numpy': 'numpy',
            r'pandas': 'pandas',
            r'matplotlib': 'matplotlib',
            r'tkinter|tk-inter': 'tk-inter',
            r'torch': 'torch',
            r'tensorflow': 'tensorflow',
            r'scipy': 'scipy',
            r'requests': 'requests'
        }

        self.nuitka_official_plugins = [
            'pyside6', 'pyqt5', 'pyqt6', 'numpy', 'matplotlib', 
            'tk-inter', 'torch', 'tensorflow', 'scipy'
        ]
        
        self.setup_ui()

    def setup_ui(self):
        top_frame = tk.Frame(self.root, pady=15)
        top_frame.pack(fill="x", padx=20)
        
        tk.Label(top_frame, text="目標腳本:", font=("微軟正黑體", 10, "bold")).pack(side="left")
        self.entry_path = tk.Entry(top_frame, textvariable=self.py_path, width=55, font=("Consolas", 10))
        self.entry_path.pack(side="left", padx=10)
        tk.Button(top_frame, text="🔍 選擇並智能分析", command=self.select_and_analyze, 
                  bg="#0078d7", fg="white", padx=10).pack(side="left")

        self.info_frame = tk.LabelFrame(self.root, text="🕵️ 智能掃邊結果", padx=15, pady=10, fg="#2c3e50", font=("微軟正黑體", 10, "bold"))
        self.info_frame.pack(fill="x", padx=20, pady=10)
        
        self.plugin_tags_frame = tk.Frame(self.info_frame)
        self.plugin_tags_frame.pack(fill="x", pady=5)
        tk.Label(self.plugin_tags_frame, text="偵測到的庫/插件:").pack(side="left")
        self.lbl_plugins = tk.Label(self.plugin_tags_frame, text="等待分析...", fg="#e67e22", font=("Consolas", 10, "bold"))
        self.lbl_plugins.pack(side="left", padx=5)

        self.dir_tags_frame = tk.Frame(self.info_frame)
        self.dir_tags_frame.pack(fill="x", pady=5)
        tk.Label(self.dir_tags_frame, text="包含的資源目錄:").pack(side="left")
        self.lbl_dirs = tk.Label(self.dir_tags_frame, text="等待分析...", fg="#27ae60", font=("Consolas", 10, "bold"))
        self.lbl_dirs.pack(side="left", padx=5)

        extra_frame = tk.Frame(self.root)
        extra_frame.pack(fill="x", padx=20, pady=5)
        tk.Label(extra_frame, text="自定義附加參數 (選填):").pack(side="left")
        self.extra_args = tk.Entry(extra_frame, width=60, font=("Consolas", 10))
        self.extra_args.pack(side="left", padx=10)
        self.extra_args.insert(0, "--follow-imports")

        opt_frame = tk.LabelFrame(self.root, text="📦 打包模式設定", padx=10, pady=10)
        opt_frame.pack(fill="x", padx=20, pady=5)
        
        self.var_mode = tk.StringVar(value="simple")
        tk.Radiobutton(opt_frame, text="極簡模式 (Simple)", variable=self.var_mode, value="simple").pack(side="left", padx=10)
        tk.Radiobutton(opt_frame, text="獨立目錄 (Standalone)", variable=self.var_mode, value="standalone").pack(side="left", padx=10)
        tk.Radiobutton(opt_frame, text="單一文件 (Onefile)", variable=self.var_mode, value="onefile").pack(side="left", padx=10)
        
        self.var_console = tk.BooleanVar(value=False)
        self.chk_console = tk.Checkbutton(opt_frame, text="隱藏控制台 (GUI模式)", variable=self.var_console)
        self.chk_console.pack(side="left", padx=20)

        self.log_area = scrolledtext.ScrolledText(self.root, height=18, bg="#1e1e1e", fg="#ecf0f1", font=("Consolas", 9))
        self.log_area.pack(fill="both", expand=True, padx=20, pady=5)

        self.btn_build = tk.Button(self.root, text="🔥 開始編譯", height=2, font=("微軟正黑體", 12, "bold"),
                                   command=self.start_build, bg="#c0392b", fg="white", state="disabled")
        self.btn_build.pack(fill="x", padx=20, pady=15)

    def select_and_analyze(self):
        path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])
        if not path: return
        self.py_path.set(path)
        
        self.log(f"🔍 正在精確追蹤依賴鏈: {os.path.basename(path)}")
        
        try:
            project_root = os.path.dirname(path)
            # 儲存真正有用到的外部庫與本地路徑
            used_libraries = set()
            visited_files = set()
            files_to_scan = [os.path.abspath(path)]

            # 遞迴掃描依賴鏈
            while files_to_scan:
                current_file = files_to_scan.pop()
                if current_file in visited_files or not os.path.exists(current_file):
                    continue
                
                visited_files.add(current_file)
                self.log(f"  -> 解析: {os.path.relpath(current_file, project_root)}")

                # 讀取並解析 AST (utf-8-sig 可容忍 BOM，避免 ast.parse 失敗)
                with open(current_file, 'r', encoding='utf-8-sig', errors='ignore') as f:
                    content = f.read()

                try:
                    tree = ast.parse(content)
                except Exception:
                    tree = None # 語法錯誤則跳過 AST，改用文字掃描兜底

                # 文字層級掃描：即使 AST 失敗也能抓到 import (例如 BOM、註解內 import 等)
                text_imports = set()
                for m in re.findall(r'^\s*(?:from|import)\s+(\w+)', content, re.MULTILINE):
                    text_imports.add(m.split('.')[0])

                module_names = set()
                if tree is not None:
                    for node in ast.walk(tree):
                        # 處理 import XXX
                        if isinstance(node, ast.Import):
                            for n in node.names:
                                module_names.add(n.name.split('.')[0])
                        # 處理 from XXX import YYY
                        elif isinstance(node, ast.ImportFrom):
                            if node.level == 0 and node.module: # 絕對匯入
                                module_names.add(node.module.split('.')[0])
                            elif node.level > 0: # 相對匯入 (例如 from . import xxx)
                                pass
                module_names |= text_imports

                for m_name in module_names:
                    # 1. 判斷是否為本地檔案/資料夾
                    potential_path = os.path.join(project_root, m_name)
                    py_file = potential_path + ".py"
                    init_file = os.path.join(potential_path, "__init__.py")

                    if os.path.exists(py_file):
                        files_to_scan.append(os.path.abspath(py_file))
                    elif os.path.exists(init_file):
                        # 如果是一個 package，掃描其下所有 py 檔案 (通常 Nuitka 會全包)
                        files_to_scan.append(os.path.abspath(init_file))
                    else:
                        # 2. 如果不是本地檔案，視為外部庫
                        used_libraries.add(m_name)

            # 根據真正用到的外部庫，匹配 Nuitka 插件規則
            self.auto_plugins = []
            for lib in used_libraries:
                for pattern, display_name in self.plugin_rules.items():
                    if re.search(pattern, lib, re.IGNORECASE):
                        if display_name not in self.auto_plugins:
                            self.auto_plugins.append(display_name)

            # 偵測資源目錄 (維持原樣，檢查根目錄下的預設資料夾)
            self.auto_data_dirs = [d for d in os.listdir(project_root)
                                   if os.path.isdir(os.path.join(project_root, d))
                                   and d.lower() in ['libs', 'assets', 'resources', 'img', 'images', 'locale']]

            # 偵測專案執行時期支援檔案 (ctypes 載入的 DLL / 驅動)，打包時一併帶入
            # 注意: vcruntime140.dll 由 Nuitka 自動包含，不需 (也不能) 手動重複指定
            self.auto_runtime_files = [f for f in ['NetRedirector.dll', 'WinDivert.dll', 'WinDivert64.sys',
                                                   'config.json']
                                       if os.path.isfile(os.path.join(project_root, f))]

            # 更新 UI
            self.lbl_plugins.config(text=" + ".join(self.auto_plugins) if self.auto_plugins else "無 (純腳本)")
            dirs_text = ", ".join(self.auto_data_dirs) if self.auto_data_dirs else "無"
            files_text = ", ".join(self.auto_runtime_files) if self.auto_runtime_files else "無"
            self.lbl_dirs.config(text=f"{dirs_text}" + (f" | 支援檔案: {files_text}" if files_text else ""))
            
            gui_libs = ['pyside6', 'pyqt5', 'pyqt6', 'tk-inter', 'PyOpenGL']
            if any(p in gui_libs for p in self.auto_plugins):
                self.var_console.set(True)
            
            self.btn_build.config(state="normal")
            self.log(f"✅ 精確分析完成！共追蹤 {len(visited_files)} 個本地檔案。")

        except Exception as e:
            messagebox.showerror("分析失敗", f"追蹤依賴時出錯: {str(e)}")

    def log(self, msg):
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)

    def start_build(self):
        script = self.py_path.get()
        if not script: return

        mode = self.var_mode.get()
        cmd = [sys.executable, "-m", "nuitka"]
        
        if self.var_console.get():
            cmd.append("--windows-console-mode=disable")

        if mode == "simple":
            self.log("ℹ️ 模式：極簡編譯 (僅編譯主程式，依賴本地環境)")
        else:
            cmd.append(f"--{mode}")
            for p in self.auto_plugins:
                if p.lower() in self.nuitka_official_plugins:
                    cmd.append(f"--enable-plugin={p.lower()}")
                if p == 'PyOpenGL':
                    cmd.append("--include-package=OpenGL")
                    if 'numpy' not in self.auto_plugins:
                        cmd.append("--enable-plugin=numpy")
            
            script_dir = os.path.dirname(script)
            for d in self.auto_data_dirs:
                full_path = os.path.join(script_dir, d).replace('\\', '/')
                cmd.append(f"--include-data-dir={full_path}={d}")

            # 執行時期支援檔案 (NetRedirector/WinDivert DLL、驅動、設定檔)
            for f in self.auto_runtime_files:
                src = os.path.join(script_dir, f).replace('\\', '/')
                cmd.append(f"--include-data-files={src}={f}")
            
            extra = self.extra_args.get().split()
            if extra: cmd.extend(extra)

        cmd.extend(["--remove-output", script])
        
        self.btn_build.config(state="disabled", text="🚧 正在編譯...")
        self.log_area.delete(1.0, tk.END)
        threading.Thread(target=self.run_process, args=(cmd,)).start()

    def run_process(self, cmd):
        # 2. 記錄開始時間
        start_time = time.time()
        
        self.log(f"🚀 啟動編譯...")
        self.log(f"指令詳情: {' '.join(cmd)}\n" + "="*60)
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                       text=True, encoding='utf-8', errors='replace')
            
            for line in process.stdout:
                self.log(line.strip())
            
            process.wait()
            
            # 3. 計算總耗時
            end_time = time.time()
            elapsed_time = end_time - start_time
            minutes = int(elapsed_time // 60)
            seconds = int(elapsed_time % 60)
            time_str = f"{minutes} 分 {seconds} 秒" if minutes > 0 else f"{seconds} 秒"

            if process.returncode == 0:
                self.log("\n" + "="*60)
                self.log(f"✨ 編譯成功！")
                self.log(f"⏱️ 總共花費時間: {time_str}")
                self.log("="*60)
                messagebox.showinfo("成功", f"打包已完成！\n耗時：{time_str}")
            else:
                self.log(f"\n❌ 打包失敗，返回碼: {process.returncode}")
                self.log(f"⏱️ 雖然失敗，但已執行了: {time_str}")
                
        except Exception as e:
            self.log(f"☢️ 系統錯誤: {str(e)}")
        finally:
            self.btn_build.config(state="normal", text="🔥 開始編譯")

if __name__ == "__main__":
    root = tk.Tk()
    app = SmartNuitkaPackager(root)
    root.mainloop()