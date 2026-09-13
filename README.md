# VPS Quality Lab

把一台 VPS 交付为 **可复用的 SSH 连接、VLESS + REALITY 节点，以及带原始终端截图的评测报告**。Skill 组织需求，Python + Typer CLI 执行、验收并保存恢复状态。默认以 VPS 自身作为固定出口，可配置机场作为前置。

支持 macOS/Linux 客户端、Debian/Ubuntu 服务端；Shadowrocket 导入适配 macOS。测试用独立 sing-box 监听和指定物理网卡，不切换系统主代理。安装软件、节点已生成、客户端已导入和实际出口已验证是不同状态。

## 安装

需要 Python 3.11+、OpenSSH、curl、sing-box。项目尚未发布到 PyPI；从私有 [GitHub Releases](https://github.com/0xTotoroX/vps-quality-lab/releases) 下载 wheel，或从源码安装：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[screenshots]'
.venv/bin/python -m playwright install chromium
.venv/bin/vps-lab --version
```

下载 wheel 后可在自己的虚拟环境中执行 `python -m pip install './vps_quality_lab-0.1.1-py3-none-any.whl[screenshots]'`，再用该环境的 Python 安装 Chromium。截图依赖可选；缺失时如实记录截图阶段未完成。

将 Release 中 Skill ZIP 解压后的 `vps-quality-lab` 文件夹安装到 `~/.codex/skills/`。已有同名 Skill 时先对比，不直接覆盖。项目中的版本位于 [skills/vps-quality-lab](skills/vps-quality-lab/SKILL.md)，可随仓库一起维护。

## 第一次交付

参考 [脱敏配置](examples/config.json)。以下 `192.0.2.10` 是文档地址，须换成实际 VPS；密码通过进程环境变量提供，不放进命令参数或配置文件。

```sh
vps-lab trust-host --host 192.0.2.10 --fingerprint SHA256:TRUSTED_FINGERPRINT --output /private/location/known_hosts
vps-lab init --host 192.0.2.10 --expected-exit 192.0.2.10 --interface en0 --known-hosts /private/location/known_hosts --password-env VPS_LAB_SSH_PASSWORD --output /private/location/vps.json
vps-lab --json plan --config /private/location/vps.json
vps-lab --json run --config /private/location/vps.json --label daytime
```

主机指纹应从 VPS 控制台或其他可信来源取得，不能把未经验证的 `ssh-keyscan` 当作信任依据。已有 verified known_hosts 时跳过 trust-host。`init` 默认采用已有服务；全新服务器在私有配置中设置 `mode: deploy` 与 `allow_deploy: true`。已有公钥可用时指定 `ssh.key_file`，会直接采用。

`run` 的第一步自动建立或复用专用 SSH 密钥、保留并增量更新 authorized_keys、生成工具专用连接别名，然后用全新的 BatchMode 公钥连接验收。成功前不会进入节点部署；不改密码策略、root 登录、SSH 端口或防火墙。若服务器关闭了公钥认证，已授权 SSH 初始化时可开启 `ssh.enable_public_key`；工具会备份原配置，只为当前用户启用公钥，校验后 reload，第二连接失败则恢复本轮策略变更。可单独运行 `ssh-bootstrap`、`ssh-status`，或用 `doctor` 做只读检查。

根据用途调整 `profile`、套餐 `plan`、测试 `limits` 和 `external_tools`。没有显式 `limits` 时，AI/视频/综合用途分别使用 5/20/10 MB 下载样本。默认启用 IPQuality；`net` 为 NetQuality，使用低数据模式主动跳过 Speedtest/iperf 吞吐；`hardware` 为 HardwareQuality，须显式开启 `allow_stress`。自动装检测工具依赖另由 `allow_external_install` 控制。检测工具的入口脚本均固定提交和 SHA256，采用隐私模式禁用在线报告上传。源信息见 [sources.json](src/vps_quality_lab/assets/sources.json)。

## 结果与续跑

```sh
vps-lab status /path/to/run
vps-lab resume /path/to/run
vps-lab node-export /path/to/run --output /private/location/node
vps-lab client-import /path/to/run
vps-lab client-check /path/to/run --proxy socks5h://127.0.0.1:CLIENT_PORT
vps-lab report /path/to/run --obsidian
vps-lab report /path/to/run --output /path/to/export --share
```

`CLIENT_PORT` 使用实际 Shadowrocket 本地监听端口；CLI 会检查监听进程归属。导入不会自动选择节点，应用可能要求原生确认。无法安全操作客户端时，仍可交付链接和二维码、完成独立路径验证，并保留客户端未验证状态。

运行目录默认 `~/.local/share/vps-quality-lab`，可用 `VPS_LAB_HOME` 指定。凭据和报告分开；完整运行目录、原始终端图片和 Obsidian 导出可能包含主机 IP，按私有资料保管。分享版移除原图和常见标识，不导出节点或 SSH 密钥。

`success / partial / failed / skipped` 均写入 JSON。错误出口、非 2xx HTTP、下载字节不全、缺失 JSON 和显式证据冲突不会成为质量得分。TTFB、单连接、并发总量、上传、TCP/ICMP、去回程和服务端交叉检查分别保存。中断期间的 ANSI 会流式保存；远端证据取回失败时保留临时目录并记录恢复路径。报告生成失败会写入失败状态，可用 `resume RUN --stages report` 重试。不同时间用新 `--label` 批次；`compare` 仅接受验证过出口且测试形状一致的完整样本。比较契约包含上传、下载和 TTFB 目标、协议版本及测试规模；旧批次可继续读取和导出，缺少契约时须重测后再排名。

原始 ANSI 与 JSON 一起归档；截图通过 xterm.js 重放原始 ANSI 后直接获取像素，截取最终报告或末尾终端视口，保留颜色并记录源 SHA256 和截取范围，不使用 OCR。完整原始流继续保留。HTTPS 探针不等于账号登录、AI 对话或视频播放；UDP 与跨时段稳定性也不能由一次 TCP 测试推断。

完整命令、副作用和退出码见 [CLI 契约](docs/cli-contract.md)，故障恢复与备份见 [恢复说明](docs/recovery.md)。

## 开发与验证

```sh
python -m pip install -e '.[dev,screenshots]'
pytest -q
ruff check src tests tools
python tools/package.py
```

CI 检查可观察契约、失败传播、SSH 增量更新、断点续跑、构建和包内容。真实 VPS 验收与新服务器部署验收分别记录；测试替身不算实机成功。发布验证记录见 [docs/validation.md](docs/validation.md)。

产品目录：`src/` 执行核心与截图资源，`tests/` 契约测试，`skills/` Agent 工作流，`docs/` 契约及恢复，`examples/` 脱敏配置，`tools/` 发布打包，`.github/` CI。

当前工作区另有历史 `scripts/`、`vendor/`、`results/`、`reports/`、`legacy/`、`private/`、`.runtime/`，均保留原位置、兼容链接和数据，不纳入 Git 或发行包。历史脚本依赖当时机器参数；新交付请使用 CLI。

设计参考 [personal-edge-proxy](https://github.com/yding-git/personal-edge-proxy) 的入口/出口职责分离和真实请求验收；未照搬其 WARP 或个人分流策略。[第三方来源与许可](THIRD_PARTY_NOTICES.md)。
