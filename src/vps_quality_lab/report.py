"""Original ANSI screenshots and reports without node/SSH credentials."""

import hashlib
import json
import re
import statistics
import sys
from importlib.resources import files
from pathlib import Path

from .models import RunResult, StageResult, Status
from .security import redact_urls
from .storage import LabError, private_dir, write_json, write_private


def capture_ansi(source: Path, output: Path):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise LabError("Install vps-quality-lab[screenshots] and run playwright install chromium", 4) from exc
    ansi = source.read_bytes()
    if len(ansi) > 8_000_000:
        raise LabError("ANSI evidence exceeds capture size limit")
    assets = files("vps_quality_lab").joinpath("assets")
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=True)
        except Exception as exc:
            raise LabError("Chromium unavailable; run python -m playwright install chromium", 4) from exc
        try:
            page = browser.new_page(viewport={"width": 1600, "height": 1200}, device_scale_factor=1)
            # No upstream HTML and no network. Xterm interprets the original ANSI bytes.
            page.route("**/*", lambda route: route.abort())
            page.set_content('<html><meta charset="utf-8"><body style="margin:0;background:#101418">'
                             '<div id="terminal" style="padding:16px;width:max-content"></div></body></html>')
            page.add_style_tag(content=assets.joinpath("xterm.css").read_text())
            page.add_script_tag(content=assets.joinpath("xterm.js").read_text())
            page.evaluate("""() => {
                window.term = new Terminal({cols:160,rows:60,scrollback:20000,fontSize:14,
                    fontFamily:'Menlo, Consolas, monospace',convertEol:true,disableStdin:true,
                    theme:{background:'#101418',foreground:'#e7edf4'},allowProposedApi:false});
                term.open(document.getElementById('terminal'));
            }""")
            page.evaluate("data => new Promise(resolve => term.write(data, resolve))",
                          ansi.decode(errors="replace"))
            dimensions = page.evaluate("""() => {
                let buffer=term.buffer.active,last=buffer.length;
                while(last>1 && !buffer.getLine(last-1).translateToString(true).trim()) last--;
                let reportStart=-1;
                for(let i=0;i<last;i++){
                    if(/(?:QUALITY|HARDWARE|NETWORK) CHECK REPORT/i.test(buffer.getLine(i).translateToString(true))) reportStart=i;
                }
                let start=reportStart>=0 && last-reportStart<=300 ? Math.max(0,reportStart-1) : Math.max(0,last-120);
                term.resize(160,Math.max(15,Math.min(last-start+2,300)));
                term.scrollToBottom();
                return {lines:last,rows:term.rows,captured_start:start,
                        selection:reportStart>=0 && last-reportStart<=300 ? 'final report' : 'final terminal viewport'};
            }""")
            page.evaluate("() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
            outputs = []
            for i, offset in enumerate([dimensions["captured_start"]]):
                page.evaluate("() => term.scrollToBottom()")
                page.evaluate("() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
                path = output.with_name(output.stem + (f"-{i+1}" if i else "") + ".png")
                write_private(path, page.locator("#terminal").screenshot())
                outputs.append(str(path))
            provenance = {"source_sha256": hashlib.sha256(ansi).hexdigest(),
                          "method": "Original ANSI replayed in xterm.js 5.5.0; browser pixel screenshot; no OCR",
                          "columns": 160, **dimensions, "images": outputs}
            write_json(output.with_suffix(".capture.json"), provenance)
            return provenance
        finally:
            browser.close()


def screenshots(run: Path) -> StageResult:
    # Retain every raw attempt on disk; the report shows the newest attempt per tool.
    latest = {path.name: path for path in sorted((run / "evidence").rglob("*.ansi"))}
    sources = list(latest.values())
    if not sources:
        return StageResult(status=Status.skipped, message="No raw terminal evidence is available")
    captures, failures = [], []
    for source in sources:
        try:
            captures.append(capture_ansi(source, source.with_suffix(".png")))
        except LabError as exc:
            failures.append(str(exc))
    return StageResult(status=Status.partial if failures else Status.success,
                       message="Original terminal screenshots saved" if not failures else "; ".join(sorted(set(failures))),
                       data={"captures": captures}, evidence=[p for c in captures for p in c["images"]])


def median(rows, key, factor=1):
    values = [r[key] * factor for r in rows if r.get("valid") and isinstance(r.get(key), (int, float))]
    return statistics.median(values) if values else None


def metrics(state: RunResult):
    stage = state.stages.get("network")
    verified = state.stages.get("verify")
    if not stage or not stage.data.get("eligible") or not verified or verified.status != Status.success:
        return {"fresh_ttfb_ms": None, "reused_ttfb_ms": None, "single_mbps": None,
                "parallel_mbps": None, "upload_mbps": None}
    data = stage.data
    pairs = data.get("ttfb_pairs", [])
    first = [p[0] for p in pairs if p]
    reused = [p[1] for p in pairs if len(p) > 1 and p[1].get("num_connects") == 0]
    return {"fresh_ttfb_ms": median(first, "time_starttransfer", 1000),
            "reused_ttfb_ms": median(reused, "time_starttransfer", 1000),
            "single_mbps": median(data.get("single", []), "speed_download", 8/1e6),
            "parallel_mbps": data.get("parallel_mbps"),
            "upload_mbps": median(data.get("upload", []), "speed_upload", 8/1e6)}


def escape(text):
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def measurement_context(state, run):
    config_file = run / "private/config.json"
    if not config_file.is_file():
        return []
    config = json.loads(config_file.read_text())
    route = state.stages.get("verify", StageResult(status=Status.skipped, message="")).data.get("route", {})
    limits = config["limits"]
    lines = ["", f"测试路径：物理网卡 `{escape(config['interface'])}` → "
             f"{'前置代理 → ' if config.get('upstream_file') else ''}VPS → 目标站点。",
             f"本轮入口：{escape(route.get('entry_selected', '未验证'))}；预期固定出口：{escape(config['expected_exit'])}。",
             f"测试规模：每目标 {limits['samples']} 组样本；下载 {limits['download_bytes'] / 1e6:g} MB/次；"
             f"上传 {limits['upload_bytes'] / 1e6:g} MB/次；并发 {limits['concurrency']}；请求超时 {limits['request_timeout']} 秒。"]
    plan = config.get("plan", {})
    lines.append("套餐声明：" + ("；".join(f"{escape(k)}={escape(v)}" for k, v in plan.items())
                              if plan else "未提供，本次不判断是否达到套餐配置或带宽。"))
    net = state.stages.get("network")
    if net:
        lines += [f"网络采样完成时间：{escape(net.finished_at)}。续跑保留成功样本的原始时间。",
                  "下载目标：" + "、".join(escape(u) for u in net.data.get("download_endpoints", [])) + "。"]
        samples = net.data.get("server_crosscheck", {}).get("samples", [])
        lines.append(f"服务器到下载目标的独立交叉检查：{sum(bool(s.get('valid')) for s in samples)}/{len(samples)} 有效；不混入本地到 VPS 吞吐。")
    return lines


def report_text(state: RunResult, run: Path, share=False):
    labels = {"ai": "固定 AI 出口", "video": "视频与下载", "balanced": "综合评测"}
    lines = [f"# {escape(state.name)} · VPS 评测", "",
             f"批次：`{state.run_id}` · 时段标签：{escape(state.label) or '未指定'} · {state.created_at}", "",
             f"用途：{labels.get(state.profile,state.profile)}。本批结果：**{state.status.value}**。",
             f"SSH：**{state.ssh_delivery}**；节点交付：**{state.node_delivery}**。", ""]
    lines += measurement_context(state, run) + [""]
    if state.ranking_eligible:
        lines.append("独立 REALITY 链路已在测量前后通过两家 HTTPS 出口核对；有效样本可用于相同测试形状的比较。")
    else:
        lines.append("本批数据未满足链路排名条件，不据此给出质量排名或用缺失值计算零分。")
    lines += ["", "| 指标 | 观测值 |", "| --- | --- |"]
    metric_labels = {"fresh_ttfb_ms": "新连接 TTFB（ms）", "reused_ttfb_ms": "复用连接 TTFB（ms）",
                     "single_mbps": "单连接下载（Mbps）", "parallel_mbps": "并发总吞吐（Mbps）",
                     "upload_mbps": "上传（Mbps）"}
    for key, value in metrics(state).items():
        label = metric_labels[key]
        lines.append(f"| {label} | {value:.2f} |" if value is not None else f"| {label} | 缺失或不可采用 |")
    focus = {"ai": "AI 用途优先观察新连接及实际复用连接的 TTFB；这些是 HTTPS 网络探针，不是模型生成首 token 的耗时。",
             "video": "视频与下载用途优先观察单连接有效吞吐；并发总量不能替代单流表现，下载文件不能代替实际视频播放。",
             "balanced": "综合用途同时观察连接延迟、有效吞吐、上传和缺失项，不把不同来源压缩成一个未经校准的总分。"}
    lines += ["", focus[state.profile]]
    lines += ["", "TTFB 包含请求完整链路。single 为有效单连接样本中位数，parallel 为实际完成字节数除以墙钟耗时。",
              "带宽、IP 标签、单一风险分数和 TCP 连通均不能替代实际用途验证。", "",
              "| 阶段 | 状态 | 说明 |", "| --- | --- | --- |"]
    for name, stage in state.stages.items():
        lines.append(f"| {name} | {stage.status.value} | {escape(stage.message)} |")
    routes = state.stages.get("routes")
    if routes:
        lines += ["", "| 路由观测 | 状态或观测值 |", "| --- | --- |"]
        for name, probe in routes.data.items():
            if name == "tcp_entry":
                rows = probe.get("samples", [])
                values = [r["seconds"] * 1000 for r in rows if r.get("status") == "success"]
                value = f"{len(values)}/{len(rows)} 成功；中位数 {statistics.median(values):.2f} ms" if values else "无有效 TCP 样本"
            else:
                value = escape(probe.get("status")) + "；" + escape(probe.get("reason") or probe.get("caution") or "原始证据见 result.json")
            lines.append(f"| {escape(name)} | {value} |")
    external_net = state.stages.get("net")
    if external_net and external_net.message != "Not selected":
        lines += ["", "NetQuality 使用低数据模式：Speedtest 与 iperf 吞吐主动跳过；上表吞吐来自独立 HTTP 测量。",
                  "外部检测限制为 1 CPU、512 MB 内存和 256 个任务。进程创建失败可能来自这些限制或服务器资源不足，不能据此判断线路质量。"]
    hardware = state.stages.get("hardware")
    if hardware and hardware.data:
        data = hardware.data
        lines += ["", f"服务器：{escape(data.get('os'))} {escape(data.get('version'))}，"
                  f"{escape(data.get('cpu_count'))} CPU，内存 {escape(data.get('memory_total'))}。"]
    ip = state.stages.get("ip")
    if ip and ip.data.get("eligible") and state.stages.get("verify") and state.stages["verify"].status == Status.success:
        data = ip.data.get("structured") or {}
        lines += ["", "IPQuality 原始结构化字段（不同来源可能相互矛盾）：", "", "```json",
                  json.dumps({k: data.get(k) for k in ["Info", "Type", "Score", "Media"]}, indent=2, ensure_ascii=False), "```"]
    if ip and ip.data.get("conflicts"):
        lines += ["", "证据冲突（不据此评分）：", ""]
        for item in ip.data["conflicts"]:
            lines.append(f"- {escape(item['metric'])}：JSON 为 {escape(item['json'])}，原始终端为 {escape(item['terminal'])}。")
    lines += ["", "HTTPS 探针不等于账号登录、实际 AI 对话或视频播放验收；未执行的 UDP、跨时段及浏览器业务样本保持未验证。"]
    captures = state.stages.get("screenshots")
    if captures and captures.evidence and not share:
        lines += ["", "## 原始终端截图", "",
                  "以下图片由本批原始 ANSI 在 xterm.js 中重放后直接截图，保留颜色；截取最终报告或末尾终端视口，未使用 OCR 或重写文字。完整原始流保留在运行目录，源哈希与截取范围见 capture.json。", ""]
        for image in captures.evidence:
            relative = Path(image).relative_to(run).as_posix()
            lines += [f"![{Path(image).stem}]({relative})", ""]
    if share:
        lines += ["", "分享版不包含原始截图、原始日志、主机地址或连接凭据。原始证据保存在本机私有批次。"]
    else:
        lines += ["", "节点链接、二维码和 SSH 私钥与本报告分开保存。运行目录仍可能包含主机 IP 与个人路径，请按私有资料保管。"]
    text = "\n".join(lines) + "\n"
    return redact(text) if share else text


def redact(text: str):
    text = redact_urls(text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP redacted]", text)
    text = re.sub(r"/(?:Users|home)/[^\s\"`|]+", "[local path]", text)
    text = re.sub(r"(?:vless|trojan|ss)://\S+", "[node redacted]", text)
    text = re.sub(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", "[identifier]", text)
    return text


def generate(state: RunResult, run: Path):
    write_private(run / "report.md", report_text(state, run))
    write_private(run / "report-share.md", report_text(state, run, share=True))
    return str(run / "report.md")


def current_vault() -> Path:
    config = (Path.home() / "Library/Application Support/obsidian/obsidian.json" if sys.platform == "darwin"
              else Path.home() / ".config/obsidian/obsidian.json")
    if not config.is_file():
        raise LabError("Obsidian vault could not be discovered; pass --output", 2)
    vaults = json.loads(config.read_text()).get("vaults", {}).values()
    opened = sorted([v for v in vaults if v.get("open")], key=lambda v: v.get("ts", 0), reverse=True)
    if not opened:
        raise LabError("No currently open Obsidian vault; pass --output", 2)
    vault = Path(opened[0]["path"])
    if not (vault / ".obsidian").is_dir():
        raise LabError("Discovered Obsidian vault is unavailable", 4)
    return vault


def export(state: RunResult, run: Path, destination: Path, share=False):
    target = destination / (state.run_id + ("-share" if share else ""))
    if target.exists():
        raise LabError("Export destination already exists; choose another output directory", 4)
    private_dir(target)
    write_private(target / "report.md", report_text(state, run, share))
    if not share:
        for image in state.stages.get("screenshots", StageResult(status=Status.skipped, message="")).evidence:
            source = Path(image)
            relative = source.relative_to(run)
            write_private(target / relative, source.read_bytes())
        # Only result data; the config snapshot and node credentials are never exported.
        write_json(target / "result.json", state.model_dump(mode="json"))
    return target
