# ProxyDesk

Windows 进程级代理应用启动台。**只给从这里启动的子进程注入代理环境**，不开启 TUN、不修改系统代理、不写环境变量注册表，也不影响通过桌面快捷方式打开的其它程序。

Python 纯标准库实现，零第三方依赖。

---

## 核心特性

- **双层代理注入**
  - **普通 / Node 应用**：注入 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY`。
  - **Electron / Chromium 应用**：自动根据同目录特征文件识别，并额外注入 `--proxy-server` 与 `--proxy-bypass-list`（解决 Windows 下 Chromium 忽略 `*_PROXY` 环境变量的问题），在启动前对已运行实例做单实例锁提示。
- **独立轻量桌面壳**
  - 自动使用本机 Chrome / Edge `--app=` 模式搭配独立用户目录与 `--no-proxy-server` 打开界面，自身不受外部代理干扰。
  - 支持单实例复用（重复启动时尝试置前已有窗口）、延迟关闭（`F5` 刷新不断连）、空闲自动退出守护。
- **原生 Windows 体验**
  - 通过 Win32 API 原生文件选择器（`GetOpenFileNameW`）选取 `.exe`，无需手动复制路径。
  - 自动提取目标 `.exe` 的真实图标展示在应用卡片上（失败时自动回退为首字母头像）。
  - 使用 `Toolhelp32` + `QueryFullProcessImageNameW` 进程全路径枚举运行状态，不闪黑框。
- **本地接口防护**
  - 每次启动生成随机 `API_TOKEN`，校验 `Host`、`Origin` 与 `X-ProxyDesk-Token`。

---

## 运行环境

- Windows 10 / 11
- Python 3（仅使用标准库，无需 `pip install`）
- Google Chrome 或 Microsoft Edge（用于独立窗口展示）
- 本地代理客户端（如 Clash Verge，默认配置示例端口为 `127.0.0.1:7897`）

---

## 快速使用

1. **配置（可选）**
   - 首次启动会自动生成本地 `config.json`，也可以将 `config.example.json` 复制为 `config.json` 后按需修改代理端口、直连例外列表与应用列表。
   - `config.json` 已加入 `.gitignore`，不会提交个人配置与内网规则。
2. **启动 ProxyDesk**
   - `launch_desk.vbs`：推荐方式，静默启动无控制台黑窗。
   - `launch_desk.bat`：备选无黑窗启动脚本（适合 `.vbs` 被拦截的环境）。
   - `debug_desk.bat`：保留控制台窗口启动，方便查看运行或报错输出。
3. **创建桌面快捷方式（可选）**
   - 双击 `create_desktop_shortcut.vbs` 即可在桌面生成带图标的 `ProxyDesk.lnk` 快捷方式（支持直接固定到任务栏）。

---

## 目录说明

| 文件 | 说明 |
| --- | --- |
| `desk.py` | 后端 HTTP 服务、进程级代理注入、Win32 进程检测与图标提取 |
| `index.html` | 单文件前端界面 |
| `config.example.json` | 默认配置模板（首次运行会自动生成本地 `config.json`） |
| `proxydesk.ico` / `.png` / `.svg` | 应用图标资源 |
| `launch_desk.vbs` / `.bat` | 静默启动脚本 |
| `debug_desk.bat` | 调试启动脚本 |
| `create_desktop_shortcut.vbs` | 一键创建桌面快捷方式脚本 |
