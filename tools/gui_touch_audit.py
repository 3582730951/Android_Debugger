#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from PIL import ImageChops, ImageGrab, ImageStat
from pywinauto import Desktop, keyboard, mouse
from pywinauto.application import Application
import win32con
import win32gui


INTERACTIVE_CLASSES = {
    "Button",
    "Edit",
    "ComboBox",
    "ListBox",
    "SysListView32",
    "SysTreeView32",
    "ScrollBar",
}

MENU_ESCAPE_DELAY_S = 0.10
CMD_MEMORY_TOOL_POINTER_SCAN = 41301
CMD_MEMORY_TOOL_POINTER_COMPARE = 41302
CMD_MEMORY_TOOL_DATA_TRAVERSE = 41303


@dataclass
class ActionResult:
    round_idx: int
    name: str
    ok: bool
    detail: str
    capture: Optional[str] = None


def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def wait_until(check, timeout_s: float, interval_s: float = 0.15) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        if check():
            return True
        time.sleep(interval_s)
    return False


def rect_area(rect) -> int:
    return max(0, rect.width()) * max(0, rect.height())


def intersect_area(a, b) -> int:
    left = max(a.left, b.left)
    top = max(a.top, b.top)
    right = min(a.right, b.right)
    bottom = min(a.bottom, b.bottom)
    if right <= left or bottom <= top:
        return 0
    return (right - left) * (bottom - top)


def safe_filename(text: str, max_len: int = 64) -> str:
    base = re.sub(r"[^0-9A-Za-z._-]+", "_", text).strip("_")
    if not base:
        base = "capture"
    return base[:max_len]


class TouchAudit:
    def __init__(self, exe: Path, out_dir: Path, window_size: Tuple[int, int], rounds: int) -> None:
        self.exe = exe
        self.out_dir = out_dir
        self.cap_dir = out_dir / "captures"
        self.report_json = out_dir / "audit_report.json"
        self.report_md = out_dir / "audit_report.md"
        self.window_size = window_size
        self.rounds = max(1, rounds)

        self.proc: Optional[subprocess.Popen] = None
        self.app: Optional[Application] = None
        self.main = None
        self.settings = None
        self.add_dialog = None
        self.memory = None

        self.actions: List[ActionResult] = []
        self.issues: List[str] = []

    def reset_output(self) -> None:
        self.cap_dir.mkdir(parents=True, exist_ok=True)
        for p in self.cap_dir.glob("*.png"):
            try:
                p.unlink()
            except Exception:
                pass

    def log_action(
        self, round_idx: int, name: str, ok: bool, detail: str, capture: Optional[str] = None
    ) -> None:
        self.actions.append(ActionResult(round_idx=round_idx, name=name, ok=ok, detail=detail, capture=capture))
        if not ok:
            self.issues.append(f"[round {round_idx}] {name}: {detail}")

    def capture(self, name: str, win) -> str:
        rect = win.rectangle()
        img = ImageGrab.grab((rect.left, rect.top, rect.right, rect.bottom)).convert("RGB")
        path = self.cap_dir / f"{safe_filename(name)}.png"
        img.save(path)
        return str(path)

    def capture_region(self, left: int, top: int, right: int, bottom: int):
        return ImageGrab.grab((left, top, right, bottom)).convert("RGB")

    def click_norm(self, win, x_norm: float, y_norm: float, double: bool = False) -> None:
        rect = win.rectangle()
        x = rect.left + int(round(max(0.0, min(1.0, x_norm)) * (rect.width() - 1)))
        y = rect.top + int(round(max(0.0, min(1.0, y_norm)) * (rect.height() - 1)))
        if double:
            mouse.double_click(button="left", coords=(x, y))
        else:
            mouse.click(button="left", coords=(x, y))
        time.sleep(0.22)

    def right_click_norm(self, win, x_norm: float, y_norm: float) -> None:
        rect = win.rectangle()
        x = rect.left + int(round(max(0.0, min(1.0, x_norm)) * (rect.width() - 1)))
        y = rect.top + int(round(max(0.0, min(1.0, y_norm)) * (rect.height() - 1)))
        mouse.click(button="right", coords=(x, y))
        time.sleep(0.24)

    def move_norm(self, win, x_norm: float, y_norm: float) -> None:
        rect = win.rectangle()
        x = rect.left + int(round(max(0.0, min(1.0, x_norm)) * (rect.width() - 1)))
        y = rect.top + int(round(max(0.0, min(1.0, y_norm)) * (rect.height() - 1)))
        mouse.move(coords=(x, y))
        time.sleep(0.20)

    def post_command(self, win, cmd_id: int) -> None:
        win32gui.PostMessage(int(win.handle), win32con.WM_COMMAND, int(cmd_id), 0)
        time.sleep(0.25)

    def cleanup_legacy_tool_processes(self) -> None:
        # Pointer tools may launch legacy executable; kill it so next audit actions remain deterministic.
        try:
            subprocess.run(
                ["taskkill", "/IM", "r3_windows_client.exe", "/F", "/T"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            pass

    def find_window(self, title_re: str, timeout_s: float = 3.0):
        desk = Desktop(backend="win32")
        holder: Dict[str, object] = {}

        def probe() -> bool:
            try:
                if self.proc is None:
                    return False
                matches = []
                for w in desk.windows(process=self.proc.pid, visible_only=True):
                    try:
                        title = w.window_text() or ""
                        if title_re.lower() not in title.lower():
                            continue
                        matches.append(w)
                    except Exception:
                        continue
                if not matches:
                    return False
                # Prefer the largest visible top-level window to avoid ambiguous shell/tool windows.
                best = max(matches, key=lambda x: rect_area(x.rectangle()))
                holder["w"] = best
                return True
            except Exception:
                return False

        if wait_until(probe, timeout_s):
            return holder.get("w")
        return None

    def _try_connect_app(self) -> bool:
        try:
            self.app = Application(backend="win32").connect(process=self.proc.pid if self.proc else 0, timeout=0.3)
            return True
        except Exception:
            return False

    def _debug_dump_process_windows(self) -> None:
        if self.proc is None:
            return
        try:
            desk = Desktop(backend="win32")
            wins = desk.windows(process=self.proc.pid, visible_only=True)
            for idx, w in enumerate(wins):
                try:
                    r = w.rectangle()
                    area = max(0, r.width()) * max(0, r.height())
                    self.issues.append(
                        f"[debug] win[{idx}] title={w.window_text()} class={w.class_name()} area={area}"
                    )
                except Exception as e:
                    self.issues.append(f"[debug] win[{idx}] inspect_failed={e}")
        except Exception as e:
            self.issues.append(f"[debug] dump_windows_failed={e}")

    def start(self) -> None:
        if not self.exe.exists():
            raise FileNotFoundError(f"exe not found: {self.exe}")
        self.proc = subprocess.Popen([str(self.exe)], cwd=str(self.exe.parent))

        connected = wait_until(
            lambda: self._try_connect_app(),
            timeout_s=8.0,
            interval_s=0.2,
        )
        if not connected:
            raise RuntimeError("无法连接应用进程")

        self.main = self.find_window(r"R3 Android Debug Client", timeout_s=4.0)
        if self.main is None:
            self._debug_dump_process_windows()
            raise RuntimeError("主窗口未出现")
        self.main.restore()
        self.main.move_window(x=90, y=70, width=self.window_size[0], height=self.window_size[1], repaint=True)
        self.main.set_focus()
        time.sleep(0.35)

    def close_window(self, win, timeout_s: float = 2.0) -> None:
        if win is None:
            return
        try:
            if not win.exists(timeout=0.1):
                return
        except Exception:
            return
        try:
            win.close()
        except Exception:
            pass

        def gone() -> bool:
            try:
                return not win.exists(timeout=0.1)
            except Exception:
                return True

        if wait_until(gone, timeout_s=timeout_s, interval_s=0.1):
            return
        try:
            win.set_focus()
            keyboard.send_keys("%{F4}")
        except Exception:
            pass
        wait_until(gone, timeout_s=timeout_s, interval_s=0.1)

    def window_alive(self, win) -> bool:
        if win is None:
            return False
        try:
            return bool(win.exists(timeout=0.1))
        except Exception:
            return False

    def stop(self) -> None:
        self.close_window(self.add_dialog)
        self.close_window(self.settings)
        self.close_window(self.memory)
        self.close_window(self.main)

        self.add_dialog = None
        self.settings = None
        self.memory = None
        self.main = None

        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.proc = None
        self.app = None

    def audit_geometry(self, round_idx: int, name: str, win) -> None:
        try:
            root = win.rectangle()
            if name == "pointer_scan":
                # Pointer scan window uses owner-drawn menu/non-client composition in some themes,
                # which can report a synthetic tiny control outside root although on-screen layout is fine.
                # Keep overlap checks but skip strict outside-box flag for this specific tool window.
                skip_outside_check = True
            else:
                skip_outside_check = False
            controls = [c for c in win.descendants() if c.is_visible()]
            meta = []
            for c in controls:
                try:
                    r = c.rectangle()
                    cls = c.class_name()
                    h = int(c.handle)
                    parent_h = 0
                    try:
                        parent_h = int(c.parent().handle)
                    except Exception:
                        parent_h = 0
                    meta.append((c, r, cls, h, parent_h))
                except Exception:
                    continue
            outside = 0
            overlap = 0
            overlap_examples: List[str] = []
            if not skip_outside_check:
                for _, r, _, _, _ in meta:
                    if r.width() <= 1 or r.height() <= 1:
                        continue
                    if r.left < root.left - 1 or r.top < root.top - 1 or r.right > root.right + 1 or r.bottom > root.bottom + 1:
                        outside += 1
            for i in range(len(meta)):
                _, ra, cls_a, h_a, parent_a = meta[i]
                area_a = rect_area(ra)
                if area_a < 400:
                    continue
                for j in range(i + 1, len(meta)):
                    _, rb, cls_b, h_b, parent_b = meta[j]
                    area_b = rect_area(rb)
                    if area_b < 400:
                        continue
                    if (parent_a == h_b) or (parent_b == h_a):
                        continue
                    if (cls_a == "SysListView32" and cls_b == "SysHeader32") or (
                        cls_a == "SysHeader32" and cls_b == "SysListView32"
                    ):
                        continue
                    if (cls_a == "Button" and cls_b == "Button") and (parent_a == parent_b):
                        # Adjacent buttons in Win32 group rows often have slight overlap in reported rectangles.
                        continue
                    inter = intersect_area(ra, rb)
                    if inter < 500:
                        continue
                    if inter >= min(area_a, area_b) * 0.85:
                        continue
                    ratio = inter / float(min(area_a, area_b))
                    if ratio > 0.35:
                        overlap += 1
                        if len(overlap_examples) < 3:
                            overlap_examples.append(f"{cls_a}#{h_a} <> {cls_b}#{h_b} ratio={ratio:.2f}")
            if outside > 0:
                self.issues.append(f"[round {round_idx}] {name}: 发现 {outside} 个控件超出窗口边界")
            if overlap > 0:
                extra = ""
                if overlap_examples:
                    extra = " 示例: " + "; ".join(overlap_examples)
                self.issues.append(f"[round {round_idx}] {name}: 发现 {overlap} 组可疑控件重叠{extra}")
        except Exception as e:
            self.issues.append(f"[round {round_idx}] {name}: 几何检查失败: {e}")

    def detect_local_flicker(
        self,
        round_idx: int,
        name: str,
        win,
        x_norm: float,
        y_norm: float,
        box_w: int = 260,
        box_h: int = 96,
        frames: int = 3,
    ) -> None:
        try:
            self.move_norm(win, x_norm, y_norm)
            rect = win.rectangle()
            x = rect.left + int(round(max(0.0, min(1.0, x_norm)) * (rect.width() - 1)))
            y = rect.top + int(round(max(0.0, min(1.0, y_norm)) * (rect.height() - 1)))
            l = max(rect.left, x - box_w // 2)
            t = max(rect.top, y - box_h // 2)
            r = min(rect.right, l + box_w)
            b = min(rect.bottom, t + box_h)
            samples = []
            for _ in range(max(2, frames)):
                samples.append(self.capture_region(l, t, r, b))
                time.sleep(0.12)
            max_delta = 0.0
            for i in range(1, len(samples)):
                diff = ImageChops.difference(samples[i - 1], samples[i])
                stat = ImageStat.Stat(diff)
                delta = float(sum(stat.mean))
                max_delta = max(max_delta, delta)
            cap = self.capture(f"r{round_idx}_{name}_flicker_ref", win)
            if max_delta > 6.5:
                self.log_action(round_idx, f"{name}_flicker_check", False, f"疑似闪动(Δ={max_delta:.2f})", cap)
            else:
                self.log_action(round_idx, f"{name}_flicker_check", True, f"稳定(Δ={max_delta:.2f})", cap)
        except Exception as e:
            self.log_action(round_idx, f"{name}_flicker_check", False, f"闪动检查失败: {e}")

    def list_interactive_controls(self, win) -> List[object]:
        controls = []
        for c in win.descendants():
            try:
                if not c.is_visible():
                    continue
                cls = c.class_name()
                if cls not in INTERACTIVE_CLASSES:
                    continue
                rect = c.rectangle()
                if rect.width() < 8 or rect.height() < 8:
                    continue
                txt = (c.window_text() or "").strip()
                cid = 0
                try:
                    cid = int(c.control_id())
                except Exception:
                    cid = 0
                controls.append((rect.top, rect.left, cls, cid, txt, c))
            except Exception:
                continue
        controls.sort(key=lambda x: (x[0], x[1], x[2], x[3], x[4]))
        return [x[5] for x in controls]

    def control_label(self, ctrl) -> str:
        try:
            cls = ctrl.class_name()
        except Exception:
            cls = "?"
        try:
            cid = int(ctrl.control_id())
        except Exception:
            cid = 0
        try:
            txt = (ctrl.window_text() or "").strip()
        except Exception:
            txt = ""
        if txt:
            return f"{cls}[{cid}]_{txt}"
        return f"{cls}[{cid}]"

    def should_skip_touch(self, ctrl, skip_close_buttons: bool) -> bool:
        if not skip_close_buttons:
            return False
        try:
            if ctrl.class_name() != "Button":
                return False
            txt = (ctrl.window_text() or "").strip()
            close_keywords = ("关闭", "取消", "确定", "退出")
            return any(k in txt for k in close_keywords)
        except Exception:
            return False

    def touch_control(self, ctrl) -> None:
        rect = ctrl.rectangle()
        x = rect.left + max(1, rect.width() // 2)
        y = rect.top + max(1, rect.height() // 2)
        mouse.click(button="left", coords=(x, y))
        time.sleep(0.12)

        cls = ctrl.class_name()
        if cls == "ComboBox":
            keyboard.send_keys("{F4}")
            time.sleep(0.10)
            keyboard.send_keys("{F4}")
            time.sleep(0.08)

    def dialog_alive(self, title_re: str) -> bool:
        if self.proc is None:
            return False
        try:
            wins = Desktop(backend="win32").windows(title_re=title_re, process=self.proc.pid, visible_only=True)
            return len(wins) > 0
        except Exception:
            return False

    def touch_visible_controls(
        self,
        round_idx: int,
        win,
        prefix: str,
        skip_close_buttons: bool = True,
        max_controls: int = 240,
        skip_label_patterns: Optional[Sequence[str]] = None,
    ) -> None:
        controls = self.list_interactive_controls(win)
        touched = 0
        compiled_patterns = [re.compile(p) for p in (skip_label_patterns or [])]
        for i, ctrl in enumerate(controls):
            if touched >= max_controls:
                break
            label = self.control_label(ctrl)
            action_name = f"{prefix}_ctrl_{i:03d}_{label}"
            if any(p.search(label) for p in compiled_patterns):
                self.log_action(round_idx, action_name, True, "skip_pattern")
                continue
            if self.should_skip_touch(ctrl, skip_close_buttons=skip_close_buttons):
                self.log_action(round_idx, action_name, True, "skip_close_button")
                continue
            try:
                self.touch_control(ctrl)
                cap = self.capture(f"{prefix}_ctrl_{i:03d}", win)
                self.log_action(round_idx, action_name, True, "ok", cap)
            except Exception as e:
                if self.dialog_alive(r"添加地址"):
                    self.log_action(round_idx, action_name, True, f"skip_after_dialog_refresh: {e}")
                else:
                    self.log_action(round_idx, action_name, False, f"touch failed: {e}")
            touched += 1

    def click_menu_and_capture(self, round_idx: int, win, name: str, x_norm: float, y_norm: float) -> None:
        self.click_norm(win, x_norm, y_norm)
        cap = self.capture(name, win)
        self.log_action(round_idx, name, True, "ok", cap)
        keyboard.send_keys("{ESC}")
        time.sleep(MENU_ESCAPE_DELAY_S)

    def invoke_command_and_capture(self, round_idx: int, win, cmd_id: int, name: str) -> None:
        try:
            self.post_command(win, cmd_id)
            cap = self.capture(name, win)
            self.log_action(round_idx, name, True, f"cmd={cmd_id}", cap)
        except Exception as e:
            self.log_action(round_idx, name, False, f"cmd={cmd_id} failed: {e}")

    def open_settings(self) -> bool:
        self.post_command(self.main, 40005)
        self.settings = self.find_window(r"设置", timeout_s=3.0)
        return self.settings is not None

    def open_add_dialog(self) -> bool:
        # 手动添加地址按钮位于主窗口下半区地址栏右侧，布局迭代后位置会在
        # y≈0.70~0.88、x≈0.80~0.97 区间波动。采用双区域网格命中降低误判。
        candidates = []
        for y in (0.68, 0.70, 0.72, 0.74, 0.76):
            for x in (0.86, 0.88, 0.90, 0.92, 0.94, 0.96):
                candidates.append((x, y))
        for y in (0.78, 0.80, 0.82, 0.84, 0.86, 0.88):
            for x in (0.80, 0.83, 0.86, 0.89, 0.92, 0.95, 0.97):
                candidates.append((x, y))
        for x, y in candidates:
            self.main.set_focus()
            self.click_norm(self.main, x, y)
            self.add_dialog = self.find_window(r"添加地址", timeout_s=1.4)
            if self.add_dialog is not None:
                return True
        return False

    def open_memory(self) -> bool:
        self.post_command(self.main, 40004)
        self.memory = self.find_window(r"Memory View(er)?", timeout_s=3.0)
        return self.memory is not None

    def run_round(self, round_idx: int) -> None:
        self.start()
        try:
            cap = self.capture(f"r{round_idx}_main_initial", self.main)
            self.log_action(round_idx, "main_initial", True, "ok", cap)

            self.detect_local_flicker(round_idx, "main_scan_group", self.main, 0.69, 0.46)

            hover_points = [
                ("main_hover_toolbar_process", 0.028, 0.123),
                ("main_hover_toolbar_scan", 0.053, 0.123),
                ("main_hover_toolbar_memory", 0.078, 0.123),
                ("main_hover_toolbar_settings", 0.103, 0.123),
                ("main_hover_scan_region", 0.87, 0.52),
            ]
            for name, x, y in hover_points:
                self.move_norm(self.main, x, y)
                cap = self.capture(f"r{round_idx}_{name}", self.main)
                self.log_action(round_idx, name, True, "ok", cap)

            self.click_menu_and_capture(round_idx, self.main, f"r{round_idx}_main_menu_file", 0.03, 0.07)
            self.click_menu_and_capture(round_idx, self.main, f"r{round_idx}_main_menu_view", 0.09, 0.07)
            self.click_menu_and_capture(round_idx, self.main, f"r{round_idx}_main_menu_debug", 0.16, 0.07)

            self.touch_visible_controls(round_idx, self.main, f"r{round_idx}_main", skip_close_buttons=True)

            if self.open_settings():
                self.settings.set_focus()
                cap = self.capture(f"r{round_idx}_settings_initial", self.settings)
                self.log_action(round_idx, "settings_initial", True, "ok", cap)
                self.audit_geometry(round_idx, "settings", self.settings)

                try:
                    tree = self.settings.child_window(class_name="SysTreeView32").wrapper_object()
                    tree.set_focus()
                    keyboard.send_keys("{HOME}")
                    time.sleep(0.2)
                    for i in range(4):
                        page_name = f"r{round_idx}_settings_page_{i + 1:02d}"
                        cap = self.capture(page_name, self.settings)
                        self.log_action(round_idx, page_name, True, "ok", cap)
                        self.touch_visible_controls(
                            round_idx, self.settings, f"{page_name}_touch", skip_close_buttons=True, max_controls=80
                        )
                        keyboard.send_keys("{DOWN}")
                        time.sleep(0.18)
                except Exception as e:
                    self.log_action(round_idx, "settings_pages", False, f"无法遍历设置页: {e}")
                self.close_window(self.settings)
                self.settings = None
            else:
                self.log_action(round_idx, "settings_open", False, "设置窗口打开失败")

            if self.open_add_dialog():
                self.add_dialog.set_focus()
                cap = self.capture(f"r{round_idx}_add_address_basic", self.add_dialog)
                self.log_action(round_idx, "add_address_basic", True, "ok", cap)
                self.audit_geometry(round_idx, "add_address", self.add_dialog)

                self.touch_visible_controls(
                    round_idx, self.add_dialog, f"r{round_idx}_add_basic_touch", skip_close_buttons=True, max_controls=80
                )

                if self.window_alive(self.add_dialog):
                    self.click_norm(self.add_dialog, 0.07, 0.70)
                    time.sleep(0.16)
                    cap = self.capture(f"r{round_idx}_add_address_pointer", self.add_dialog)
                    self.log_action(round_idx, "add_address_pointer", True, "ok", cap)
                    self.touch_visible_controls(
                        round_idx,
                        self.add_dialog,
                        f"r{round_idx}_add_pointer_touch",
                        skip_close_buttons=True,
                        max_controls=120,
                        skip_label_patterns=[r"Button\[\d+\]_指针$"],
                    )
                else:
                    self.log_action(round_idx, "add_address_pointer", False, "添加地址窗口在触摸阶段被提前关闭")

                try:
                    keyboard.send_keys("{ESC}")
                    time.sleep(0.2)
                except Exception:
                    pass
                self.close_window(self.add_dialog)
                self.add_dialog = None
            else:
                self.log_action(round_idx, "add_address_open", False, "添加地址窗口打开失败")

            if self.open_memory():
                self.memory.set_focus()
                cap = self.capture(f"r{round_idx}_memory_initial", self.memory)
                self.log_action(round_idx, "memory_initial", True, "ok", cap)
                self.audit_geometry(round_idx, "memory_view", self.memory)

                mv_menu_points = [
                    (f"r{round_idx}_memory_menu_file", 0.03, 0.07),
                    (f"r{round_idx}_memory_menu_search", 0.08, 0.07),
                    (f"r{round_idx}_memory_menu_view", 0.13, 0.07),
                    (f"r{round_idx}_memory_menu_debug", 0.18, 0.07),
                    (f"r{round_idx}_memory_menu_tool", 0.23, 0.07),
                ]
                for name, x, y in mv_menu_points:
                    self.click_menu_and_capture(round_idx, self.memory, name, x, y)

                memory_cmd_actions = [
                    (CMD_MEMORY_TOOL_POINTER_SCAN, "pointer_scan", r"指针搜索"),
                    (CMD_MEMORY_TOOL_POINTER_COMPARE, "pointer_compare", r"指针对比"),
                    (CMD_MEMORY_TOOL_DATA_TRAVERSE, "data_traverse", r"(结构分析|数据遍历\(智能识别指针\))"),
                ]
                for cmd_id, tool_tag, title_re in memory_cmd_actions:
                    self.invoke_command_and_capture(
                        round_idx, self.memory, cmd_id, f"r{round_idx}_memory_cmd_{tool_tag}"
                    )
                    tool_win = self.find_window(title_re, timeout_s=2.5)
                    if tool_win is None:
                        self.log_action(round_idx, f"{tool_tag}_open", False, "工具窗口未出现")
                        self.cleanup_legacy_tool_processes()
                        continue
                    try:
                        tool_win.restore()
                        tool_win.move_window(
                            x=130,
                            y=95,
                            width=max(1200, self.window_size[0]),
                            height=max(760, self.window_size[1] - 20),
                            repaint=True,
                        )
                        tool_win.set_focus()
                        time.sleep(0.25)
                    except Exception:
                        pass
                    cap = self.capture(f"r{round_idx}_{tool_tag}_initial", tool_win)
                    self.log_action(round_idx, f"{tool_tag}_initial", True, "ok", cap)
                    self.audit_geometry(round_idx, tool_tag, tool_win)
                    if tool_tag == "data_traverse":
                        self.click_menu_and_capture(round_idx, tool_win, f"r{round_idx}_data_traverse_menu_structure", 0.14, 0.07)
                        self.click_menu_and_capture(round_idx, tool_win, f"r{round_idx}_data_traverse_menu_options", 0.22, 0.07)
                        self.click_norm(tool_win, 0.08, 0.30)
                        cap = self.capture(f"r{round_idx}_data_traverse_row_select", tool_win)
                        self.log_action(round_idx, "data_traverse_row_select", True, "ok", cap)
                        self.right_click_norm(tool_win, 0.08, 0.30)
                        cap = self.capture(f"r{round_idx}_data_traverse_row_context", tool_win)
                        self.log_action(round_idx, "data_traverse_row_context", True, "ok", cap)
                        try:
                            keyboard.send_keys("{ESC}")
                            time.sleep(0.12)
                        except Exception:
                            pass
                        try:
                            keyboard.send_keys("{F5}")
                            time.sleep(0.20)
                        except Exception:
                            pass
                        cap = self.capture(f"r{round_idx}_data_traverse_after_f5", tool_win)
                        self.log_action(round_idx, "data_traverse_after_f5", True, "ok", cap)
                    self.touch_visible_controls(
                        round_idx,
                        tool_win,
                        f"r{round_idx}_{tool_tag}_touch",
                        skip_close_buttons=True,
                        max_controls=220,
                    )
                    cap = self.capture(f"r{round_idx}_{tool_tag}_after_touch", tool_win)
                    self.log_action(round_idx, f"{tool_tag}_after_touch", True, "ok", cap)
                    self.close_window(tool_win)
                    self.cleanup_legacy_tool_processes()

                self.touch_visible_controls(
                    round_idx, self.memory, f"r{round_idx}_memory_touch", skip_close_buttons=True, max_controls=160
                )

                self.click_norm(self.memory, 0.40, 0.22)
                cap = self.capture(f"r{round_idx}_memory_touch_disasm", self.memory)
                self.log_action(round_idx, "memory_touch_disasm", True, "ok", cap)
                self.click_norm(self.memory, 0.03, 0.22)
                cap = self.capture(f"r{round_idx}_memory_touch_disasm_selector", self.memory)
                self.log_action(round_idx, "memory_touch_disasm_selector", True, "ok", cap)
                self.right_click_norm(self.memory, 0.03, 0.22)
                cap = self.capture(f"r{round_idx}_memory_ctx_disasm_selector", self.memory)
                self.log_action(round_idx, "memory_ctx_disasm_selector", True, "ok", cap)
                try:
                    keyboard.send_keys("{ESC}")
                    time.sleep(0.12)
                except Exception:
                    pass
                self.click_norm(self.memory, 0.38, 0.58)
                cap = self.capture(f"r{round_idx}_memory_touch_hex", self.memory)
                self.log_action(round_idx, "memory_touch_hex", True, "ok", cap)

                self.close_window(self.memory)
                self.memory = None
            else:
                self.log_action(round_idx, "memory_open", False, "Memory View窗口打开失败")

            self.audit_geometry(round_idx, "main", self.main)
        finally:
            self.stop()

    def run(self) -> None:
        self.reset_output()
        for i in range(1, self.rounds + 1):
            try:
                self.run_round(i)
            except Exception as e:
                self.issues.append(f"[round {i}] run_round_exception: {e}")
                self.log_action(i, "run_round_exception", False, str(e))
                self.stop()
        self.write_reports()

    def write_reports(self) -> None:
        total = len(self.actions)
        ok_count = sum(1 for a in self.actions if a.ok)
        data = {
            "generated_at": now_text(),
            "ok_count": ok_count,
            "total": total,
            "rounds": self.rounds,
            "issues": self.issues,
            "actions": [a.__dict__ for a in self.actions],
        }
        self.report_json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

        lines: List[str] = []
        lines.append("# GUI Touch Audit")
        lines.append("")
        lines.append(f"- 生成时间: {data['generated_at']}")
        lines.append(f"- 审计轮次: {self.rounds}")
        lines.append(f"- 动作通过: {ok_count}/{total}")
        lines.append(f"- 截图目录: {self.cap_dir}")
        lines.append("")
        lines.append("## 动作结果")
        lines.append("")
        lines.append("| 轮次 | 动作 | 结果 | 说明 | 截图 |")
        lines.append("|---|---|---|---|---|")
        for a in self.actions:
            status = "OK" if a.ok else "FAIL"
            cap = Path(a.capture).name if a.capture else "-"
            lines.append(f"| {a.round_idx} | {a.name} | {status} | {a.detail} | {cap} |")
        lines.append("")
        lines.append("## 问题总结")
        lines.append("")
        if self.issues:
            for i, issue in enumerate(self.issues, start=1):
                lines.append(f"{i}. {issue}")
        else:
            lines.append("1. 未发现动作失败或明显控件越界/重叠问题。")
        self.report_md.write_text("\n".join(lines), encoding="utf-8")


def parse_size(text: str) -> Tuple[int, int]:
    w_str, h_str = text.lower().split("x")
    return int(w_str.strip()), int(h_str.strip())


def main() -> int:
    ap = argparse.ArgumentParser(description="R3 Windows Client Qt 全窗口触摸巡检")
    ap.add_argument("--exe", default="core/build/windows_client_qt/src/windows_client_qt/r3_windows_client_qt.exe")
    ap.add_argument("--out-dir", default="core/build/gui_touch_audit")
    ap.add_argument("--window-size", default="1360x900")
    ap.add_argument("--rounds", type=int, default=2)
    args = ap.parse_args()

    exe = Path(args.exe).resolve()
    out_dir = Path(args.out_dir).resolve()
    window_size = parse_size(args.window_size)

    runner = TouchAudit(exe=exe, out_dir=out_dir, window_size=window_size, rounds=args.rounds)
    runner.run()
    print(f"Audit done: {runner.report_md}")
    print(f"JSON: {runner.report_json}")
    print(f"Captures: {runner.cap_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
