#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import numpy as np
from PIL import Image, ImageGrab
from pywinauto.application import Application
from pywinauto import Desktop
from pywinauto import keyboard, mouse
import win32con
import win32gui


WindowLike = object


DEFAULT_POINTS: Dict[str, Tuple[float, float]] = {
    # Main window
    "scan_tab1": (0.045, 0.22),
    "scan_tab2": (0.105, 0.22),
    "toolbar_settings": (0.123, 0.125),
    "open_memory_view": (0.073, 0.695),
    "open_add_address": (0.905, 0.845),
    # Add dialog
    "add_dialog_pointer_checkbox": (0.073, 0.695),
    # Memory Viewer menu bar
    "mv_menu_file": (0.035, 0.062),
    "mv_menu_search": (0.085, 0.062),
    "mv_menu_view": (0.135, 0.062),
    "mv_menu_debug": (0.185, 0.062),
}


def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def wait_until(cond: Callable[[], bool], timeout: float, interval: float = 0.15) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(interval)
    return False


def safe_close_window(win: WindowLike) -> None:
    try:
        win.close()
    except Exception:
        try:
            win.set_focus()
            keyboard.send_keys("{ESC}")
        except Exception:
            pass


def grab_window_image(win: WindowLike) -> Image.Image:
    rect = win.rectangle()
    return ImageGrab.grab(bbox=(rect.left, rect.top, rect.right, rect.bottom)).convert("RGB")


def open_window(title_re: str, timeout_s: float = 4.0, process_id: Optional[int] = None) -> Optional[WindowLike]:
    desk = Desktop(backend="win32")
    holder: Dict[str, WindowLike] = {}

    def _probe() -> bool:
        try:
            if process_id is not None:
                w = desk.window(title_re=title_re, process=process_id)
            else:
                w = desk.window(title_re=title_re)
            if w.exists(timeout=0.2):
                holder["w"] = w
                return True
        except Exception:
            return False
        return False

    if not wait_until(_probe, timeout_s):
        return None
    return holder.get("w")


@dataclass
class ScenarioResult:
    idx: int
    ok: bool
    message: str
    capture_path: Optional[Path]


class GuiComparer:
    def __init__(
        self,
        exe_path: Path,
        baseline_dir: Path,
        out_dir: Path,
        window_width: int,
        window_height: int,
        points: Dict[str, Tuple[float, float]],
    ) -> None:
        self.exe_path = exe_path
        self.baseline_dir = baseline_dir
        self.out_dir = out_dir
        self.capture_dir = out_dir / "captures"
        self.diff_dir = out_dir / "diff"
        self.points = points
        self.window_width = window_width
        self.window_height = window_height
        self.proc: Optional[subprocess.Popen] = None
        self.app: Optional[Application] = None
        self.main = None
        self.memory = None
        self.settings = None
        self.add_dialog = None
        ensure_dir(self.out_dir)
        ensure_dir(self.capture_dir)
        ensure_dir(self.diff_dir)

    def reset_output(self) -> None:
        for d in [self.capture_dir, self.diff_dir]:
            if not d.exists():
                continue
            for p in d.glob("*.png"):
                try:
                    p.unlink()
                except Exception:
                    pass

    def log(self, msg: str) -> None:
        print(f"[{now_ts()}] {msg}")

    def start(self) -> None:
        if not self.exe_path.exists():
            raise FileNotFoundError(f"可执行文件不存在: {self.exe_path}")
        self.log(f"启动: {self.exe_path}")
        self.proc = subprocess.Popen([str(self.exe_path)], cwd=str(self.exe_path.parent))
        connected = False
        for _ in range(40):
            try:
                self.app = Application(backend="win32").connect(process=self.proc.pid, timeout=0.4)
                connected = True
                break
            except Exception:
                time.sleep(0.2)
        if not connected:
            raise RuntimeError("无法连接到被测进程窗口")
        candidates = [
            r"R3 Android Debug Client",
            r"R3 .*Debug Client",
            r"R3 .*调试.*客户端",
        ]
        for pat in candidates:
            self.main = open_window(pat, timeout_s=3.0, process_id=self.proc.pid)
            if self.main is not None:
                break
        if self.main is None:
            raise RuntimeError("主窗口未出现: R3 Android Debug Client")
        self.main.restore()
        self.main.move_window(x=90, y=70, width=self.window_width, height=self.window_height, repaint=True)
        self.main.set_focus()
        time.sleep(0.45)

    def stop(self) -> None:
        for win in [self.add_dialog, self.settings, self.memory, self.main]:
            if win is not None:
                safe_close_window(win)
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

    def click_norm(self, win: WindowLike, x_norm: float, y_norm: float, double: bool = False) -> None:
        rect = win.rectangle()
        x = rect.left + int(round(max(0.0, min(1.0, x_norm)) * (rect.width() - 1)))
        y = rect.top + int(round(max(0.0, min(1.0, y_norm)) * (rect.height() - 1)))
        if double:
            mouse.double_click(button="left", coords=(x, y))
        else:
            mouse.click(button="left", coords=(x, y))
        time.sleep(0.18)

    def post_command(self, win: WindowLike, cmd_id: int) -> None:
        hwnd = int(win.handle)
        win32gui.PostMessage(hwnd, win32con.WM_COMMAND, int(cmd_id), 0)
        time.sleep(0.18)

    def capture(self, win: WindowLike, path: Path) -> None:
        img = grab_window_image(win)
        img.save(path)
        time.sleep(0.12)

    def ensure_settings(self) -> bool:
        if self.settings and self.settings.exists(timeout=0.2):
            return True
        # Menu command: 设置
        self.post_command(self.main, 40005)
        self.settings = open_window(r"设置", timeout_s=2.0, process_id=self.proc.pid if self.proc else None)
        if self.settings is not None:
            return True
        self.click_norm(self.main, *self.points["toolbar_settings"])
        self.settings = open_window(r"设置", timeout_s=4.0, process_id=self.proc.pid if self.proc else None)
        return self.settings is not None

    def ensure_add_dialog(self) -> bool:
        if self.add_dialog and self.add_dialog.exists(timeout=0.2):
            return True
        self.click_norm(self.main, *self.points["open_add_address"])
        self.add_dialog = open_window(r"添加地址", timeout_s=4.0, process_id=self.proc.pid if self.proc else None)
        return self.add_dialog is not None

    def ensure_memory(self) -> bool:
        if self.memory and self.memory.exists(timeout=0.2):
            return True
        # Main menu command: 查看内存
        self.post_command(self.main, 40004)
        self.memory = open_window(r"Memory View(er)?", timeout_s=4.0, process_id=self.proc.pid if self.proc else None)
        return self.memory is not None

    def scenario_main(self, idx: int, tab2: bool = False) -> ScenarioResult:
        try:
            self.main.set_focus()
            if tab2:
                self.click_norm(self.main, *self.points["scan_tab2"])
            else:
                self.click_norm(self.main, *self.points["scan_tab1"])
            out = self.capture_dir / f"{idx}.png"
            self.capture(self.main, out)
            return ScenarioResult(idx, True, "ok", out)
        except Exception as e:
            return ScenarioResult(idx, False, f"主窗口截图失败: {e}", None)

    def scenario_settings(self, idx: int) -> ScenarioResult:
        try:
            if not self.ensure_settings():
                return ScenarioResult(idx, False, "未能打开设置窗口", None)
            self.settings.set_focus()
            out = self.capture_dir / f"{idx}.png"
            self.capture(self.settings, out)
            return ScenarioResult(idx, True, "ok", out)
        except Exception as e:
            return ScenarioResult(idx, False, f"设置窗口截图失败: {e}", None)

    def scenario_add_dialog(self, idx: int, pointer: bool = False) -> ScenarioResult:
        try:
            if not self.ensure_add_dialog():
                return ScenarioResult(idx, False, "未能打开添加地址窗口", None)
            self.add_dialog.set_focus()
            if pointer:
                self.click_norm(self.add_dialog, *self.points["add_dialog_pointer_checkbox"])
            out = self.capture_dir / f"{idx}.png"
            self.capture(self.add_dialog, out)
            return ScenarioResult(idx, True, "ok", out)
        except Exception as e:
            return ScenarioResult(idx, False, f"添加地址截图失败: {e}", None)

    def scenario_memory(self, idx: int, menu_key: Optional[str] = None) -> ScenarioResult:
        try:
            if not self.ensure_memory():
                return ScenarioResult(idx, False, "未能打开Memory View窗口", None)
            self.memory.set_focus()
            if menu_key:
                self.click_norm(self.memory, *self.points[menu_key])
                time.sleep(0.18)
            out = self.capture_dir / f"{idx}.png"
            self.capture(self.memory, out)
            return ScenarioResult(idx, True, "ok", out)
        except Exception as e:
            return ScenarioResult(idx, False, f"Memory View截图失败: {e}", None)

    def run_scenarios(self) -> List[ScenarioResult]:
        results: List[ScenarioResult] = []
        # main / tabs
        results.append(self.scenario_main(1, tab2=False))
        results.append(self.scenario_main(2, tab2=False))
        # settings
        results.append(self.scenario_settings(3))
        # main variants
        if self.settings is not None:
            safe_close_window(self.settings)
            self.settings = None
            time.sleep(0.15)
        results.append(self.scenario_main(4, tab2=False))
        results.append(self.scenario_main(5, tab2=True))
        # add address
        results.append(self.scenario_add_dialog(6, pointer=False))
        results.append(self.scenario_add_dialog(7, pointer=True))
        if self.add_dialog is not None:
            safe_close_window(self.add_dialog)
            self.add_dialog = None
            time.sleep(0.15)
        # memory viewer + menus
        results.append(self.scenario_memory(8, None))
        results.append(self.scenario_memory(9, "mv_menu_file"))
        results.append(self.scenario_memory(10, "mv_menu_search"))
        results.append(self.scenario_memory(11, "mv_menu_view"))
        results.append(self.scenario_memory(12, "mv_menu_debug"))
        return results

    @staticmethod
    def _resize_to_baseline(capture: Image.Image, baseline: Image.Image) -> Image.Image:
        if capture.size == baseline.size:
            return capture
        return capture.resize(baseline.size, Image.Resampling.LANCZOS)

    @staticmethod
    def _metrics_and_diff(base_img: Image.Image, cap_img: Image.Image) -> Tuple[Dict[str, float], Image.Image]:
        base = np.asarray(base_img).astype(np.float32) / 255.0
        cap = np.asarray(cap_img).astype(np.float32) / 255.0
        diff = np.abs(base - cap)
        mae = float(diff.mean())
        mse = float((diff * diff).mean())
        psnr = 99.0 if mse <= 1e-12 else float(20.0 * math.log10(1.0 / math.sqrt(mse)))
        # edge-ish metric: compare simple gradients
        gx0 = np.abs(np.diff(base, axis=1)).mean(axis=2)
        gy0 = np.abs(np.diff(base, axis=0)).mean(axis=2)
        gx1 = np.abs(np.diff(cap, axis=1)).mean(axis=2)
        gy1 = np.abs(np.diff(cap, axis=0)).mean(axis=2)
        gmae = float((np.abs(gx0 - gx1).mean() + np.abs(gy0 - gy1).mean()) * 0.5)
        score = max(0.0, 100.0 * (1.0 - (0.75 * mae + 0.25 * gmae)))

        d = diff.mean(axis=2)
        d_norm = np.clip(d * 2.2, 0.0, 1.0)
        overlay = np.zeros_like(base)
        overlay[..., 0] = d_norm
        vis = np.clip(base * 0.72 + overlay * 0.9, 0.0, 1.0)
        vis_img = Image.fromarray((vis * 255.0).astype(np.uint8), mode="RGB")
        return {
            "mae": mae,
            "mse": mse,
            "psnr": psnr,
            "edge_mae": gmae,
            "score": score,
        }, vis_img

    def compare(self, threshold: float, scenario_results: Optional[List[ScenarioResult]] = None) -> Dict[str, object]:
        detail = []
        pass_count = 0
        total = 0
        scenario_map = {r.idx: r for r in (scenario_results or [])}

        for idx in range(1, 13):
            total += 1
            base_path = self.baseline_dir / f"{idx}.png"
            cap_path = self.capture_dir / f"{idx}.png"
            item = {
                "id": idx,
                "baseline": str(base_path),
                "capture": str(cap_path),
                "ok": False,
                "reason": "",
            }
            scenario = scenario_map.get(idx)
            if scenario is not None and not scenario.ok:
                item["reason"] = f"scenario_failed: {scenario.message}"
                detail.append(item)
                continue
            if not base_path.exists():
                item["reason"] = "baseline_missing"
                detail.append(item)
                continue
            if not cap_path.exists():
                item["reason"] = "capture_missing"
                detail.append(item)
                continue

            base_img = Image.open(base_path).convert("RGB")
            cap_img = Image.open(cap_path).convert("RGB")
            cap_img = self._resize_to_baseline(cap_img, base_img)

            metrics, diff_img = self._metrics_and_diff(base_img, cap_img)
            diff_path = self.diff_dir / f"{idx}_diff.png"
            diff_img.save(diff_path)

            item.update(metrics)
            item["diff"] = str(diff_path)
            item["ok"] = metrics["score"] >= threshold
            item["reason"] = "ok" if item["ok"] else "score_below_threshold"
            if item["ok"]:
                pass_count += 1
            detail.append(item)

        summary = {
            "threshold": threshold,
            "pass_count": pass_count,
            "total": total,
            "pass_rate": 0.0 if total == 0 else pass_count / total,
            "generated_at": now_ts(),
            "detail": detail,
        }
        (self.out_dir / "report.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        self._write_markdown_report(summary)
        return summary

    def _write_markdown_report(self, summary: Dict[str, object]) -> None:
        lines = []
        lines.append(f"# GUI 对比报告")
        lines.append("")
        lines.append(f"- 生成时间: {summary['generated_at']}")
        lines.append(f"- 阈值: {summary['threshold']}")
        lines.append(f"- 通过: {summary['pass_count']}/{summary['total']} ({summary['pass_rate']:.2%})")
        lines.append("")
        lines.append("| 图号 | 分数 | MAE | EdgeMAE | 结论 |")
        lines.append("|---:|---:|---:|---:|---|")
        for d in summary["detail"]:
            if "score" in d:
                lines.append(
                    f"| {d['id']} | {d['score']:.2f} | {d['mae']:.4f} | {d['edge_mae']:.4f} | {d['reason']} |"
                )
            else:
                lines.append(f"| {d['id']} | - | - | - | {d['reason']} |")
        (self.out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def load_points(default_points: Dict[str, Tuple[float, float]], points_json: Optional[Path]) -> Dict[str, Tuple[float, float]]:
    points = dict(default_points)
    if points_json is None:
        return points
    if not points_json.exists():
        raise FileNotFoundError(f"坐标配置不存在: {points_json}")
    data = json.loads(points_json.read_text(encoding="utf-8"))
    for k, v in data.items():
        if not isinstance(v, list) or len(v) != 2:
            raise ValueError(f"坐标配置格式错误: {k}={v}")
        points[k] = (float(v[0]), float(v[1]))
    return points


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="R3 Windows Client Qt GUI 自动截图与对比工具")
    p.add_argument(
        "--exe",
        default=str(Path("core/build/windows_client/src/windows_client_qt/r3_windows_client_qt.exe")),
        help="被测 exe 路径",
    )
    p.add_argument("--baseline-dir", default=str(Path("core/png_t")), help="基准图目录(1.png..12.png)")
    p.add_argument("--out-dir", default=str(Path("core/build/gui_compare")), help="输出目录")
    p.add_argument("--window-size", default="1280x820", help="主窗体尺寸，例如 1280x820")
    p.add_argument("--threshold", type=float, default=70.0, help="通过阈值(0~100)")
    p.add_argument("--points-json", default="", help="坐标覆盖 JSON 文件")
    p.add_argument("--no-run", action="store_true", help="只做对比，不启动应用(使用已有截图)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        w_str, h_str = args.window_size.lower().split("x")
        win_w = int(w_str.strip())
        win_h = int(h_str.strip())
    except Exception:
        print("window-size 格式错误，应为 WxH，例如 1280x820", file=sys.stderr)
        return 2

    exe = Path(args.exe).resolve()
    baseline = Path(args.baseline_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    points_json = Path(args.points_json).resolve() if args.points_json else None
    points = load_points(DEFAULT_POINTS, points_json)

    comparer = GuiComparer(
        exe_path=exe,
        baseline_dir=baseline,
        out_dir=out_dir,
        window_width=win_w,
        window_height=win_h,
        points=points,
    )
    scenario_results: List[ScenarioResult] = []

    try:
        if not args.no_run:
            comparer.reset_output()
            comparer.start()
            scenario_results = comparer.run_scenarios()
            for r in scenario_results:
                state = "OK" if r.ok else "FAIL"
                print(f"[scenario {r.idx}] {state} - {r.message}")
    finally:
        if not args.no_run:
            comparer.stop()

    summary = comparer.compare(args.threshold, scenario_results=scenario_results)
    print("")
    print(f"对比完成: {summary['pass_count']}/{summary['total']} 通过, pass_rate={summary['pass_rate']:.2%}")
    print(f"报告: {out_dir / 'report.md'}")
    print(f"JSON: {out_dir / 'report.json'}")
    print(f"截图: {out_dir / 'captures'}")
    print(f"差异: {out_dir / 'diff'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
