import tkinter as tk
from tkinter import ttk, messagebox
import queue
import os
import sys
import ctypes
from datetime import datetime
from NetRedirector import NetRedirectorWrapper, RuleAction, ProxyType, RuleProtocol

class ToolTip(object):
    """簡單的工具提示 Helper"""
    def __init__(self, widget, text='widget info'):
        self.waittime = 500     # miliseconds
        self.wraplength = 180   # pixels
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.id = None
        self.tw = None

    def enter(self, event=None):
        self.schedule()

    def leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.waittime, self.showtip)

    def unschedule(self):
        id = self.id
        self.id = None
        if id:
            self.widget.after_cancel(id)

    def showtip(self, event=None):
        x = y = 0
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(self.tw, text=self.text, justify='left',
                       background="#ffffe0", relief='solid', borderwidth=1,
                       wraplength = self.wraplength)
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tw
        self.tw= None
        if tw:
            tw.destroy()

class NetRedirectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetRedirector Professional")
        self.root.geometry("1000x700")
        
        # --- 初始化核心 ---
        try:
            self.bridge = NetRedirectorWrapper("NetRedirector.dll")
        except Exception as e:
            messagebox.showerror("Critical Error", f"Failed to load NetRedirector.dll: {e}\nEnsure windivert.dll/sys are present.")
            sys.exit(1)

        # --- 狀態數據 ---
        self.is_running = False
        
        # 模仿 C# 的 ObservableCollection
        self.proxy_configs = [] # List of dict: {'id', 'name', 'ip', 'port', 'type', 'user', 'pass', 'enabled'}
        self.rules = []         # List of dict: {'id', 'process', 'hosts', 'ports', 'proto', 'action', 'proxy_id'}
        
        # 緩衝區 (參考 C# _pendingConnectionLogs)
        self.log_queue = queue.Queue()
        self.traffic_queue = queue.Queue()
        self.traffic_buffer = [] 
        
        # UI 變數
        self.var_dns_proxy = tk.BooleanVar(value=True)
        
        # 設置 UI
        self.setup_ui()
        
        # 設置回調
        self.bridge.set_log_callback(self.on_dll_log)
        self.bridge.set_connection_callback(self.on_traffic_event)

        # 啟動定時器 (UI 更新循環)
        self.root.after(100, self.process_queues)           # 處理 Log
        self.root.after(500, self.flush_traffic_buffer)     # 處理流量表 (500ms 刷新一次，模仿 C#)

        # 關閉事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.log_system("Application initialized.")

    def setup_ui(self):
        # --- 頂部狀態列 ---
        top_frame = ttk.Frame(self.root, padding=5)
        top_frame.pack(fill=tk.X)
        
        self.btn_start = ttk.Button(top_frame, text="Start Service", command=self.toggle_service)
        self.btn_start.pack(side=tk.LEFT, padx=5)
        
        self.lbl_status = ttk.Label(top_frame, text="Status: STOPPED", foreground="red", font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(side=tk.LEFT, padx=10)

        # --- 主要分頁 (Tabs) ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Tab 1: Monitor (監控)
        self.tab_monitor = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_monitor, text="Monitor")
        self.build_monitor_tab()

        # Tab 2: Rules (規則)
        self.tab_rules = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_rules, text="Rules")
        self.build_rules_tab()

        # Tab 3: Proxies (命名代理管理)
        self.tab_proxies = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_proxies, text="Named Proxies")
        self.build_proxies_tab()

        # Tab 4: Settings (全局設置 & 默認代理)
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text="Settings")
        self.build_settings_tab()

    def build_monitor_tab(self):
        paned = ttk.PanedWindow(self.tab_monitor, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # 流量列表
        frame_traffic = ttk.LabelFrame(paned, text="Connection Activity", padding=5)
        paned.add(frame_traffic, weight=3)

        cols = ("Time", "Process", "PID", "Destination", "Info")
        self.tree_traffic = ttk.Treeview(frame_traffic, columns=cols, show="headings", selectmode="browse")
        
        self.tree_traffic.column("Time", width=80, anchor="center")
        self.tree_traffic.column("Process", width=150)
        self.tree_traffic.column("PID", width=60, anchor="center")
        self.tree_traffic.column("Destination", width=200)
        self.tree_traffic.column("Info", width=200)

        for c in cols:
            self.tree_traffic.heading(c, text=c)

        scroll_y = ttk.Scrollbar(frame_traffic, orient=tk.VERTICAL, command=self.tree_traffic.yview)
        self.tree_traffic.configure(yscroll=scroll_y.set)
        
        self.tree_traffic.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        # --- [新增] 綁定右鍵選單 ---
        self.traffic_menu = tk.Menu(self.root, tearoff=0)
        self.traffic_menu.add_command(label="Add Rule for this PID", command=self.add_rule_from_log)
        self.traffic_menu.add_command(label="Add Rule for Process Name", command=self.add_rule_name_from_log)
        
        # Windows/Linux 使用 Button-3，Mac 可能需要 Button-2，這裡主要針對 Windows
        self.tree_traffic.bind("<Button-3>", self.show_traffic_context_menu)

        btn_clear = ttk.Button(frame_traffic, text="Clear Logs", command=self.clear_traffic_logs)
        btn_clear.pack(side=tk.BOTTOM, anchor="e", pady=2)

        # 系統日誌
        frame_log = ttk.LabelFrame(paned, text="System Logs", padding=5)
        paned.add(frame_log, weight=1)

        self.txt_log = tk.Text(frame_log, height=8, state='disabled', font=("Consolas", 9))
        self.txt_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        log_scroll = ttk.Scrollbar(frame_log, orient=tk.VERTICAL, command=self.txt_log.yview)
        self.txt_log.configure(yscroll=log_scroll.set)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def build_proxies_tab(self):
        # 模仿 C# ProxyConfigManager
        toolbar = ttk.Frame(self.tab_proxies, padding=5)
        toolbar.pack(fill=tk.X)
        
        ttk.Button(toolbar, text="Add Proxy", command=self.add_proxy_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Edit", command=self.edit_proxy_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Delete", command=self.delete_proxy).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Toggle Enable/Disable", command=self.toggle_proxy_enable).pack(side=tk.LEFT, padx=2)

        # Proxy List
        cols = ("ID", "Name", "Type", "IP", "Port", "Auth", "Status")
        self.tree_proxies = ttk.Treeview(self.tab_proxies, columns=cols, show="headings", selectmode="browse")
        
        for c in cols:
            self.tree_proxies.heading(c, text=c)
            self.tree_proxies.column(c, width=100)
            
        self.tree_proxies.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def build_rules_tab(self):
        # 模仿 C# ProxyRulesViewModel
        toolbar = ttk.Frame(self.tab_rules, padding=5)
        toolbar.pack(fill=tk.X)
        
        ttk.Button(toolbar, text="Add Rule", command=self.add_rule_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Edit Rule", command=self.edit_rule_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Delete Rule", command=self.delete_rule).pack(side=tk.LEFT, padx=2)

        # Rule List
        cols = ("ID", "PID", "Process", "Hosts", "Ports", "Proto", "Action", "Via Proxy")
        self.tree_rules = ttk.Treeview(self.tab_rules, columns=cols, show="headings", selectmode="browse")
        
        self.tree_rules.heading("ID", text="ID")
        self.tree_rules.column("ID", width=40, anchor="center")
        
        # --- 修改點 2: 設定 PID 欄位的標題與寬度 ---
        self.tree_rules.heading("PID", text="PID")
        self.tree_rules.column("PID", width=60, anchor="center")

        self.tree_rules.heading("Process", text="Process Name")
        self.tree_rules.column("Process", width=150)
        self.tree_rules.heading("Hosts", text="Target Hosts")
        self.tree_rules.heading("Ports", text="Ports")
        self.tree_rules.column("Ports", width=80)
        self.tree_rules.heading("Proto", text="Protocol")
        self.tree_rules.column("Proto", width=60, anchor="center")
        self.tree_rules.heading("Action", text="Action")
        self.tree_rules.column("Action", width=80, anchor="center")
        self.tree_rules.heading("Via Proxy", text="Via Proxy")
        
        self.tree_rules.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def build_settings_tab(self):
        frame = ttk.LabelFrame(self.tab_settings, text="Default Proxy & Global Settings", padding=15)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Default Proxy Form
        grid_frame = ttk.Frame(frame)
        grid_frame.pack(fill=tk.X, pady=5)

        ttk.Label(grid_frame, text="Default Type:").grid(row=0, column=0, sticky="w", pady=5)
        self.cb_def_type = ttk.Combobox(grid_frame, values=["SOCKS5", "HTTP"], state="readonly", width=10)
        self.cb_def_type.current(0)
        self.cb_def_type.grid(row=0, column=1, sticky="w")

        ttk.Label(grid_frame, text="IP Address:").grid(row=1, column=0, sticky="w", pady=5)
        self.ent_def_ip = ttk.Entry(grid_frame, width=20)
        self.ent_def_ip.insert(0, "127.0.0.1")
        self.ent_def_ip.grid(row=1, column=1, sticky="w")

        ttk.Label(grid_frame, text="Port:").grid(row=2, column=0, sticky="w", pady=5)
        self.ent_def_port = ttk.Entry(grid_frame, width=10)
        self.ent_def_port.insert(0, "30678")
        self.ent_def_port.grid(row=2, column=1, sticky="w")

        ttk.Label(grid_frame, text="Username:").grid(row=3, column=0, sticky="w", pady=5)
        self.ent_def_user = ttk.Entry(grid_frame, width=20)
        self.ent_def_user.grid(row=3, column=1, sticky="w")

        ttk.Label(grid_frame, text="Password:").grid(row=4, column=0, sticky="w", pady=5)
        self.ent_def_pass = ttk.Entry(grid_frame, width=20, show="*")
        self.ent_def_pass.grid(row=4, column=1, sticky="w")

        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=15)

        # Global Options
        chk_dns = ttk.Checkbutton(frame, text="Route DNS queries through default proxy (Prevent DNS Leaks)", variable=self.var_dns_proxy, command=self.update_dns_setting)
        chk_dns.pack(anchor="w")

        ttk.Button(frame, text="Save Default Proxy", command=self.save_default_proxy).pack(anchor="w", pady=15)

    # --- 邏輯功能 ---

    def process_queues(self):
        """處理後台線程的日誌"""
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.log_system(msg, from_queue=True)
        self.root.after(100, self.process_queues)

    def flush_traffic_buffer(self):
        """處理緩衝的流量數據 (模仿 C# DispatcherTimer)"""
        if not self.traffic_buffer:
            pass # No traffic
        else:
            # 取出所有並清空
            buffer_copy = list(self.traffic_buffer)
            self.traffic_buffer.clear()
            
            for item in buffer_copy:
                # item = (time, process, pid, dest_ip, dest_port, info)
                dest_str = f"{item[3]}:{item[4]}"
                self.tree_traffic.insert("", 0, values=(item[0], item[1], item[2], dest_str, item[5]))
            
            # 限制行數
            children = self.tree_traffic.get_children()
            if len(children) > 500:
                for child in children[500:]:
                    self.tree_traffic.delete(child)

        self.root.after(500, self.flush_traffic_buffer)

    def on_dll_log(self, msg):
        self.log_queue.put(msg)

    def on_traffic_event(self, process, pid, ip, port, info):
        # 不顯示本程式自己產生的流量
        if pid == os.getpid():
            return
        # 存入緩衝區，不直接更新 UI
        time_str = datetime.now().strftime("%H:%M:%S")
        self.traffic_buffer.append((time_str, process, pid, ip, port, info))

    def log_system(self, msg, from_queue=False):
        if not from_queue:
            msg = f"[System] {msg}"
        
        self.txt_log.configure(state='normal')
        self.txt_log.insert(tk.END, f"{msg}\n")
        self.txt_log.see(tk.END)
        self.txt_log.configure(state='disabled')

    # --- 服務控制 ---

    def show_traffic_context_menu(self, event):
        """顯示右鍵選單，並自動選取滑鼠指到的那一行"""
        # 找出滑鼠位置對應的行
        item = self.tree_traffic.identify_row(event.y)
        if item:
            # 選取該行
            self.tree_traffic.selection_set(item)
            # 彈出選單
            self.traffic_menu.post(event.x_root, event.y_root)

    def add_rule_from_log(self):
        """從流量日誌中提取 PID 並打開規則視窗"""
        sel = self.tree_traffic.selection()
        if not sel: return
        
        # cols = ("Time", "Process", "PID", "Destination", "Info")
        # values索引: 0=Time, 1=Process, 2=PID, ...
        vals = self.tree_traffic.item(sel[0], "values")
        pid_str = vals[2]
        
        if pid_str and pid_str.isdigit():
            # 呼叫規則視窗，並傳入預填的 PID
            self._rule_dialog(prefill_pid=int(pid_str))
        else:
            messagebox.showwarning("Info", "Invalid PID selected.")

    def add_rule_name_from_log(self):
        """從流量日誌中提取 Process Name 並打開規則視窗"""
        sel = self.tree_traffic.selection()
        if not sel: return
        vals = self.tree_traffic.item(sel[0], "values")
        proc_name = vals[1] # Process Name
        
        if proc_name and proc_name != "Unknown":
            self._rule_dialog(prefill_name=proc_name)

    def toggle_service(self):
        if not self.is_running:
            # Start
            self.save_default_proxy(silent=True)
            self.update_dns_setting()
            
            if self.bridge.start():
                self.is_running = True
                self.btn_start.config(text="Stop Service")
                self.lbl_status.config(text="Status: RUNNING", foreground="green")
                self.log_system("NetRedirector Service Started.")
            else:
                messagebox.showerror("Error", "Failed to start service. Check Admin privileges.")
        else:
            # Stop
            self.bridge.stop()
            self.is_running = False
            self.btn_start.config(text="Start Service")
            self.lbl_status.config(text="Status: STOPPED", foreground="red")
            self.log_system("NetRedirector Service Stopped.")

    def save_default_proxy(self, silent=False):
        try:
            ptype_str = self.cb_def_type.get()
            ptype = ProxyType.SOCKS5 if ptype_str == "SOCKS5" else ProxyType.HTTP
            ip = self.ent_def_ip.get()
            port = int(self.ent_def_port.get())
            user = self.ent_def_user.get()
            pwd = self.ent_def_pass.get()

            success = self.bridge.set_default_proxy(ip, port, ptype, user, pwd)
            if success:
                if not silent: messagebox.showinfo("Success", "Default proxy settings applied.")
            else:
                messagebox.showerror("Error", "Invalid proxy configuration.")
        except ValueError:
            messagebox.showerror("Error", "Port must be a number.")

    def update_dns_setting(self):
        # 呼叫 DLL 設定 DNS
        # 注意：Python wrapper 需要暴露這個函數，如果你的 wrapper 沒這行，這裡會報錯
        # 假設你的 DLL 有 NetRedirector_SetDnsViaProxy
        try:
            enable = self.var_dns_proxy.get()
            # 這裡需要你在 NetRedirector.py 增加 set_dns_via_proxy 函數
            # 如果沒有，請手動添加
            if hasattr(self.bridge, 'lib') and hasattr(self.bridge.lib, 'NetRedirector_SetDnsViaProxy'):
                 self.bridge.lib.NetRedirector_SetDnsViaProxy(enable)
                 self.log_system(f"DNS via Proxy set to: {enable}")
        except Exception:
            pass

    # --- 命名代理管理 (Named Proxies) ---

    def refresh_proxies_list(self):
        for item in self.tree_proxies.get_children():
            self.tree_proxies.delete(item)
        
        for p in self.proxy_configs:
            # cols = ("ID", "Name", "Type", "IP", "Port", "Auth", "Status")
            ptype = "SOCKS5" if p['type'] == ProxyType.SOCKS5 else "HTTP"
            auth = "Yes" if p['user'] else "No"
            status = "Enabled" if p['enabled'] else "Disabled"
            self.tree_proxies.insert("", tk.END, values=(p['id'], p['name'], ptype, p['ip'], p['port'], auth, status))

    def add_proxy_dialog(self):
        self._proxy_dialog(None)

    def edit_proxy_dialog(self):
        sel = self.tree_proxies.selection()
        if not sel: return
        # 找到對應的 config
        pid = self.tree_proxies.item(sel[0], "values")[0]
        config = next((x for x in self.proxy_configs if str(x['id']) == str(pid)), None)
        if config:
            self._proxy_dialog(config)

    def _proxy_dialog(self, config=None):
        # 彈出視窗
        dlg = tk.Toplevel(self.root)
        dlg.title("Proxy Configuration")
        dlg.geometry("350x400")
        dlg.transient(self.root)
        dlg.grab_set()

        ttk.Label(dlg, text="Name:").pack(pady=5)
        ent_name = ttk.Entry(dlg)
        ent_name.pack()
        if config: ent_name.insert(0, config['name'])
        else: ent_name.insert(0, f"Proxy {len(self.proxy_configs)+1}")

        ttk.Label(dlg, text="Type:").pack(pady=5)
        cb_type = ttk.Combobox(dlg, values=["SOCKS5", "HTTP"], state="readonly")
        cb_type.current(0 if not config or config['type'] == ProxyType.SOCKS5 else 1)
        cb_type.pack()

        ttk.Label(dlg, text="IP:").pack(pady=5)
        ent_ip = ttk.Entry(dlg)
        ent_ip.pack()
        if config: ent_ip.insert(0, config['ip'])
        else: ent_ip.insert(0, "127.0.0.1")

        ttk.Label(dlg, text="Port:").pack(pady=5)
        ent_port = ttk.Entry(dlg)
        ent_port.pack()
        if config: ent_port.insert(0, config['port'])
        else: ent_port.insert(0, "1080")

        ttk.Label(dlg, text="Username (Optional):").pack(pady=5)
        ent_user = ttk.Entry(dlg)
        ent_user.pack()
        if config and config['user']: ent_user.insert(0, config['user'])

        ttk.Label(dlg, text="Password (Optional):").pack(pady=5)
        ent_pass = ttk.Entry(dlg, show="*")
        ent_pass.pack()
        if config and config['pass']: ent_pass.insert(0, config['pass'])

        def save():
            name = ent_name.get()
            ip = ent_ip.get()
            try:
                port = int(ent_port.get())
            except:
                messagebox.showerror("Error", "Port must be number")
                return
            
            ptype = ProxyType.SOCKS5 if cb_type.get() == "SOCKS5" else ProxyType.HTTP
            user = ent_user.get()
            pwd = ent_pass.get()

            if config:
                # 編輯模式：先刪除舊的再新增 (因為 DLL API 可能沒有直接編輯)
                # 或者如果有 EditProxyConfig，這裡調用 Edit
                # 簡單起見，我們調用 Wrapper 的 add/edit
                # 假設 wrapper 尚未實現 edit，我們用 C# 邏輯： Delete + Add
                # 但這樣 ID 會變，所以最好使用 wrapper 的 edit_proxy_config
                
                # 更新 list
                config['name'] = name
                config['ip'] = ip
                config['port'] = port
                config['type'] = ptype
                config['user'] = user
                config['pass'] = pwd
                
                # 調用 DLL Edit
                # self.bridge.lib.NetRedirector_EditProxyConfig(config['id'], ...)
                # 這裡假設您會在 wrapper 補上 edit_proxy_config，如果沒有，請用 add 代替
                if hasattr(self.bridge.lib, 'NetRedirector_EditProxyConfig'):
                     self.bridge.lib.NetRedirector_EditProxyConfig(
                         config['id'], ptype, name.encode('utf-8'), ip.encode('utf-8'), port,
                         user.encode('utf-8'), pwd.encode('utf-8'), config['enabled']
                     )
            else:
                # 新增模式
                pid = self.bridge.add_proxy(ip, port, user, pwd, ptype, name)
                if pid > 0:
                    self.proxy_configs.append({
                        'id': pid, 'name': name, 'ip': ip, 'port': port, 'type': ptype,
                        'user': user, 'pass': pwd, 'enabled': True
                    })

            self.refresh_proxies_list()
            dlg.destroy()

        ttk.Button(dlg, text="Save", command=save).pack(pady=20)

    def delete_proxy(self):
        sel = self.tree_proxies.selection()
        if not sel: return
        pid = int(self.tree_proxies.item(sel[0], "values")[0])
        
        # 調用 DLL 刪除
        if hasattr(self.bridge.lib, 'NetRedirector_DeleteProxyConfig'):
             self.bridge.lib.NetRedirector_DeleteProxyConfig(pid)
        
        self.proxy_configs = [p for p in self.proxy_configs if p['id'] != pid]
        self.refresh_proxies_list()

    def toggle_proxy_enable(self):
        sel = self.tree_proxies.selection()
        if not sel: return
        pid = int(self.tree_proxies.item(sel[0], "values")[0])
        config = next((x for x in self.proxy_configs if x['id'] == pid), None)
        if config:
            config['enabled'] = not config['enabled']
            # 調用 DLL
            if config['enabled']:
                self.bridge.lib.NetRedirector_EnableProxyConfig(pid)
            else:
                self.bridge.lib.NetRedirector_DisableProxyConfig(pid)
            self.refresh_proxies_list()

    # --- 規則管理 (Rules) ---

    def refresh_rules_list(self):
        for item in self.tree_rules.get_children():
            self.tree_rules.delete(item)
            
        for r in self.rules:
            # cols = ("ID", "PID", "Process", "Hosts", "Ports", "Proto", "Action", "Via Proxy")
            act_str = "PROXY" if r['action'] == RuleAction.PROXY else ("DIRECT" if r['action'] == RuleAction.DIRECT else "BLOCK")
            proto_str = "TCP" if r['proto'] == RuleProtocol.TCP else ("UDP" if r['proto'] == RuleProtocol.UDP else "BOTH")
            
            proxy_name = "Default"
            if r['proxy_id'] > 0:
                p = next((x for x in self.proxy_configs if x['id'] == r['proxy_id']), None)
                if p: proxy_name = p['name']
                else: proxy_name = f"Unknown ID {r['proxy_id']}"
            elif r['action'] != RuleAction.PROXY:
                proxy_name = "-"
            
            # --- 修改點 3: 處理 PID 顯示字串 ---
            # 如果 target_pid 存在且大於 0，顯示數字，否則顯示 "-"
            pid_val = r.get('target_pid', 0)
            pid_str = str(pid_val) if pid_val > 0 else "-"
                
            # --- 修改點 4: 在 values 中插入 pid_str ---
            self.tree_rules.insert("", tk.END, values=(r['id'], pid_str, r['process'], r['hosts'], r['ports'], proto_str, act_str, proxy_name))

    def add_rule_dialog(self):
        self._rule_dialog(None)
        
    def edit_rule_dialog(self):
        sel = self.tree_rules.selection()
        if not sel: return
        rid = int(self.tree_rules.item(sel[0], "values")[0])
        rule = next((x for x in self.rules if x['id'] == rid), None)
        if rule:
            self._rule_dialog(rule)

    # 修改函式簽名，增加 prefill 參數
    def _rule_dialog(self, rule=None, prefill_pid=None, prefill_name=None):
        dlg = tk.Toplevel(self.root)
        dlg.title("Rule Configuration")
        dlg.geometry("400x550")
        dlg.transient(self.root)
        dlg.grab_set()
        
        # --- 規則類型選擇 ---
        type_frame = ttk.Frame(dlg)
        type_frame.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(type_frame, text="Match By:").pack(side=tk.LEFT)
        
        var_rule_type = tk.IntVar(value=0) # 0=Name, 1=PID
        
        # 邏輯判斷：如果是 PID 模式 (編輯既有 PID 規則 OR 從 Log 傳入 PID)
        is_pid_mode = False
        if rule and rule.get('target_pid', 0) > 0:
            is_pid_mode = True
        elif prefill_pid is not None:
            is_pid_mode = True
            
        if is_pid_mode:
            var_rule_type.set(1)

        # UI 元素定義
        lbl_target = ttk.Label(dlg, text="Process Name (e.g., chrome.exe):")
        ent_process = ttk.Entry(dlg)

        def on_type_change():
            if var_rule_type.get() == 0:
                lbl_target.config(text="Process Name (e.g., chrome.exe):")
            else:
                lbl_target.config(text="Process ID (Number):")
        
        rb_name = ttk.Radiobutton(type_frame, text="Process Name", variable=var_rule_type, value=0, command=on_type_change)
        rb_name.pack(side=tk.LEFT, padx=10)
        rb_pid = ttk.Radiobutton(type_frame, text="Process ID", variable=var_rule_type, value=1, command=on_type_change)
        rb_pid.pack(side=tk.LEFT)

        # Target Input
        lbl_target.pack(anchor="w", padx=10, pady=(10,0))
        ent_process.pack(fill="x", padx=10)
        
        # --- 初始化輸入框內容 ---
        if rule:
            # 編輯現有規則
            if rule.get('target_pid', 0) > 0:
                ent_process.insert(0, str(rule['target_pid']))
            else:
                ent_process.insert(0, rule['process'])
        elif prefill_pid is not None:
            # 從 Log 右鍵新增 PID
            ent_process.insert(0, str(prefill_pid))
        elif prefill_name is not None:
            # 從 Log 右鍵新增名稱
            ent_process.insert(0, prefill_name)
        else:
            # 空白新增
            ent_process.insert(0, "*")
            
        # 觸發一次更新 Label 文字
        on_type_change()

        # Hosts
        ttk.Label(dlg, text="Target Hosts (IPs, *):").pack(anchor="w", padx=10, pady=(10,0))
        ent_hosts = ttk.Entry(dlg)
        ent_hosts.pack(fill="x", padx=10)
        if rule: ent_hosts.insert(0, rule['hosts'])
        else: ent_hosts.insert(0, "*")
        
        # Ports
        ttk.Label(dlg, text="Target Ports (80, 80-90, *):").pack(anchor="w", padx=10, pady=(10,0))
        ent_ports = ttk.Entry(dlg)
        ent_ports.pack(fill="x", padx=10)
        if rule: ent_ports.insert(0, rule['ports'])
        else: ent_ports.insert(0, "*")
        
        # Protocol
        ttk.Label(dlg, text="Protocol:").pack(anchor="w", padx=10, pady=(10,0))
        cb_proto = ttk.Combobox(dlg, values=["TCP", "UDP", "BOTH"], state="readonly")
        cb_proto.pack(fill="x", padx=10)
        current_proto = "TCP"
        if rule:
             if rule['proto'] == RuleProtocol.UDP: current_proto = "UDP"
             elif rule['proto'] == RuleProtocol.BOTH: current_proto = "BOTH"
        cb_proto.set(current_proto)
        
        # Action
        ttk.Label(dlg, text="Action:").pack(anchor="w", padx=10, pady=(10,0))
        cb_action = ttk.Combobox(dlg, values=["PROXY", "DIRECT", "BLOCK"], state="readonly")
        cb_action.pack(fill="x", padx=10)
        current_action = "PROXY"
        if rule:
             if rule['action'] == RuleAction.DIRECT: current_action = "DIRECT"
             elif rule['action'] == RuleAction.BLOCK: current_action = "BLOCK"
        cb_action.set(current_action)

        # Proxy Select
        ttk.Label(dlg, text="Use Specific Proxy (Optional):").pack(anchor="w", padx=10, pady=(10,0))
        proxy_options = ["Default (0)"]
        proxy_name_to_id = {"Default (0)": 0}
        for p in self.proxy_configs:
            name_str = f"{p['name']} ({p['id']})"
            proxy_options.append(name_str)
            proxy_name_to_id[name_str] = p['id']
        cb_proxy = ttk.Combobox(dlg, values=proxy_options, state="readonly")
        cb_proxy.pack(fill="x", padx=10)
        if rule and rule['proxy_id'] > 0:
            target_str = next((k for k, v in proxy_name_to_id.items() if v == rule['proxy_id']), "Default (0)")
            cb_proxy.set(target_str)
        else:
            cb_proxy.current(0)

        def save():
            # ... (Save 邏輯保持之前修改過的支援 PID 的版本) ...
            raw_input = ent_process.get()
            hosts = ent_hosts.get()
            ports = ent_ports.get()
            
            p_str = cb_proto.get()
            proto = RuleProtocol.TCP
            if p_str == "UDP": proto = RuleProtocol.UDP
            elif p_str == "BOTH": proto = RuleProtocol.BOTH
            
            a_str = cb_action.get()
            action = RuleAction.PROXY
            if a_str == "DIRECT": action = RuleAction.DIRECT
            elif a_str == "BLOCK": action = RuleAction.BLOCK
            
            sel_proxy = cb_proxy.get()
            pid_proxy = proxy_name_to_id.get(sel_proxy, 0)

            # 判斷是否為 PID 模式
            is_pid_mode_now = (var_rule_type.get() == 1)
            target_pid_val = 0
            process_name_val = "*"

            if is_pid_mode_now:
                if not raw_input.isdigit():
                    messagebox.showerror("Error", "PID must be a number.")
                    return
                target_pid_val = int(raw_input)
            else:
                process_name_val = raw_input

            # 編輯邏輯：先刪後加
            if rule:
                self.bridge.lib.NetRedirector_DeleteRule(rule['id'])
                self.rules = [r for r in self.rules if r['id'] != rule['id']]

            # 新增邏輯
            rid = 0
            if is_pid_mode_now:
                rid = self.bridge.add_rule_by_pid(target_pid_val, hosts, ports, proto, action, pid_proxy)
            else:
                rid = self.bridge.lib.NetRedirector_AddRuleWithProxy(
                    process_name_val.encode('utf-8'), hosts.encode('utf-8'), ports.encode('utf-8'),
                    proto, action, pid_proxy
                )

            if rid > 0:
                self.rules.append({
                    'id': rid,
                    'process': process_name_val,
                    'target_pid': target_pid_val,
                    'hosts': hosts,
                    'ports': ports,
                    'proto': proto,
                    'action': action,
                    'proxy_id': pid_proxy
                })
                self.refresh_rules_list()
                dlg.destroy()
            else:
                messagebox.showerror("Error", "Failed to add rule (DLL returned 0).")

        ttk.Button(dlg, text="Save Rule", command=save).pack(pady=20)

    def delete_rule(self):
        sel = self.tree_rules.selection()
        if not sel: return
        rid = int(self.tree_rules.item(sel[0], "values")[0])
        
        self.bridge.lib.NetRedirector_DeleteRule(rid)
        self.rules = [r for r in self.rules if r['id'] != rid]
        self.refresh_rules_list()

    def clear_traffic_logs(self):
        for item in self.tree_traffic.get_children():
            self.tree_traffic.delete(item)

    def on_close(self):
        if self.is_running:
            self.bridge.stop()
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    # 管理員檢查
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        messagebox.showwarning("Permission Required", "Please run as Administrator!")
        sys.exit(1)

    root = tk.Tk()
    
    # 嘗試優化顯示 (Windows DPI)
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
        
    style = ttk.Style()
    style.theme_use('clam') # 'vista', 'clam', 'alt', 'default'
    
    app = NetRedirectorApp(root)
    root.mainloop()