import json
import re
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, VERTICAL, Y, filedialog, messagebox, ttk
import tkinter as tk


@dataclass
class FamilyMatch:
    name: str
    score: int
    reasons: list[str]
    summary: str
    indicators: dict
    response: list[str]
    resources: list[dict]
    decryption: dict


RANSOMWARE_DB = [
    {
        "name": "STOP/Djvu",
        "summary": "Common home-user ransomware that often appends a new extension and drops _readme.txt.",
        "extensions": [".djvu", ".djvuq", ".uudjvu", ".udjvu", ".tro", ".peet", ".bora"],
        "notes": ["_readme.txt"],
        "patterns": [r"id: [a-z0-9]+", r"personal id"],
        "response": [
            "Disconnect affected devices from the network.",
            "Preserve ransom notes and a few encrypted samples for analysis.",
            "Check whether your ID appears to be offline-key eligible before attempting recovery.",
            "Restore from clean backups only after removing the malware.",
        ],
        "resources": [
            {"label": "No More Ransom", "url": "https://www.nomoreransom.org/"},
            {"label": "Emsisoft STOP/Djvu info", "url": "https://www.emsisoft.com/ransomware-decryption-tools/stop-djvu"},
        ],
        "decryption": {
            "mode": "external",
            "status": "Public decryptors may exist for some cases, but local offline decryption is not bundled here.",
        },
    },
    {
        "name": "LockBit",
        "summary": "Enterprise-focused ransomware family that often uses varied extensions and a Restore-My-Files note.",
        "extensions": [".lockbit", ".lockbit2", ".lockbit3", ".abcd"],
        "notes": ["restore-my-files.txt", "restore-my-files.hta"],
        "patterns": [r"lockbit", r"restore my files"],
        "response": [
            "Isolate systems immediately and assume lateral movement until proven otherwise.",
            "Collect note files, encrypted filenames, and a timeline of suspicious activity.",
            "Check for shadow copy deletion and domain-wide persistence.",
            "Coordinate containment with backups, EDR, and identity teams before restoring.",
        ],
        "resources": [
            {"label": "No More Ransom", "url": "https://www.nomoreransom.org/"},
            {"label": "CISA ransomware guidance", "url": "https://www.cisa.gov/stopransomware"},
        ],
        "decryption": {
            "mode": "external",
            "status": "No built-in decryptor. Use public recovery resources only if a verified decryptor exists for your exact strain.",
        },
    },
    {
        "name": "Phobos",
        "summary": "Often targets small businesses and appends contact details plus an ID in filenames.",
        "extensions": [".phobos", ".8base", ".faust", ".eliof", ".devos"],
        "notes": ["info.txt", "info.hta"],
        "patterns": [r"id\[[^\]]+\]", r"\[[^\]]+@[^]]+\]"],
        "response": [
            "Preserve original encrypted filenames because their structure is a strong indicator.",
            "Review exposed RDP, VPN, and credential reuse as likely initial-access paths.",
            "Validate whether backups were touched before starting restoration.",
            "Rebuild compromised hosts rather than trusting in-place cleanup alone.",
        ],
        "resources": [
            {"label": "No More Ransom", "url": "https://www.nomoreransom.org/"},
            {"label": "CISA ransomware guidance", "url": "https://www.cisa.gov/stopransomware"},
        ],
        "decryption": {
            "mode": "external",
            "status": "No built-in decryptor. Preserve evidence and check trusted decryptor portals for your exact variant.",
        },
    },
    {
        "name": "Conti",
        "summary": "Large ransomware operation known for double-extortion playbooks and CONTI_README notes.",
        "extensions": [".conti"],
        "notes": ["conti_readme.txt"],
        "patterns": [r"conti"],
        "response": [
            "Treat the event as a likely broader breach, not just file encryption.",
            "Hunt for credential theft, scheduled tasks, and backup tampering.",
            "Preserve logs before cleanup to support response and recovery.",
            "Validate domain admin accounts and rotate credentials in scope.",
        ],
        "resources": [
            {"label": "No More Ransom", "url": "https://www.nomoreransom.org/"},
            {"label": "CISA ransomware guidance", "url": "https://www.cisa.gov/stopransomware"},
        ],
        "decryption": {
            "mode": "external",
            "status": "No built-in decryptor. Recovery usually depends on backups or a strain-specific public tool.",
        },
    },
    {
        "name": "Babuk",
        "summary": "Ransomware family seen against servers and NAS devices, often using .babyk or short custom extensions.",
        "extensions": [".babyk", ".babuk"],
        "notes": ["how_to_restore.txt"],
        "patterns": [r"babuk", r"how to restore your files"],
        "response": [
            "Prioritize isolating shared storage and virtualization hosts.",
            "Capture a few encrypted files and ransom notes for offline analysis.",
            "Assess whether ESXi, NAS, or backup appliances were impacted.",
            "Recover into segmented infrastructure after verifying the threat is removed.",
        ],
        "resources": [
            {"label": "No More Ransom", "url": "https://www.nomoreransom.org/"},
            {"label": "CISA ransomware guidance", "url": "https://www.cisa.gov/stopransomware"},
        ],
        "decryption": {
            "mode": "external",
            "status": "No built-in decryptor. Check trusted sources for a verified family-specific tool before attempting recovery.",
        },
    },
    {
        "name": "LabXOR Demo",
        "summary": "A built-in demo/lab family that uses repeating-key XOR so the app can perform local decryption when you know the key.",
        "extensions": [".labxor", ".xenc"],
        "notes": ["lab_note.txt"],
        "patterns": [r"labxor", r"training sample"],
        "response": [
            "Use this mode only for lab exercises or custom samples encrypted with the same XOR key.",
            "Provide the original XOR key in text or hex format.",
            "Write output to a separate folder so original encrypted samples stay untouched.",
        ],
        "resources": [
            {"label": "No More Ransom", "url": "https://www.nomoreransom.org/"},
        ],
        "decryption": {
            "mode": "local_xor",
            "status": "Built-in local decryption is available when you provide the correct XOR key.",
        },
    },
]


def normalize_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def score_family(sample_lines: list[str], note_text: str, family: dict) -> FamilyMatch | None:
    score = 0
    reasons: list[str] = []
    note_lower = note_text.lower()

    for line in sample_lines:
        lower = line.lower()
        for ext in family["extensions"]:
            if lower.endswith(ext.lower()):
                score += 35
                reasons.append(f"Matched file extension `{ext}` from `{line}`")
                break

        for note_name in family["notes"]:
            if note_name.lower() in lower:
                score += 30
                reasons.append(f"Matched ransom note name `{note_name}`")

        for pattern in family["patterns"]:
            if re.search(pattern, lower):
                score += 20
                reasons.append(f"Matched filename pattern `{pattern}`")

    if note_text:
        for note_name in family["notes"]:
            if note_name.lower() in note_lower:
                score += 20
                reasons.append(f"Ransom note text referenced `{note_name}`")

        for pattern in family["patterns"]:
            if re.search(pattern, note_lower):
                score += 18
                reasons.append(f"Ransom note text matched `{pattern}`")

    if score == 0:
        return None

    deduped_reasons = list(dict.fromkeys(reasons))
    return FamilyMatch(
        name=family["name"],
        score=score,
        reasons=deduped_reasons,
        summary=family["summary"],
        indicators={
            "extensions": family["extensions"],
            "notes": family["notes"],
            "patterns": family["patterns"],
        },
        response=family["response"],
        resources=family["resources"],
        decryption=family["decryption"],
    )


def analyze_inputs(file_samples: str, note_text: str) -> list[FamilyMatch]:
    sample_lines = normalize_lines(file_samples)
    matches = []
    for family in RANSOMWARE_DB:
        match = score_family(sample_lines, note_text, family)
        if match:
            matches.append(match)
    matches.sort(key=lambda item: item.score, reverse=True)
    return matches


def parse_key(key_text: str, key_format: str) -> bytes:
    raw = key_text.strip()
    if not raw:
        raise ValueError("Enter a decryption key first.")

    if key_format == "Hex":
        compact = raw.replace(" ", "")
        if len(compact) % 2 != 0:
            raise ValueError("Hex key must contain an even number of characters.")
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError("Hex key contains invalid characters.") from exc

    return raw.encode("utf-8")


def xor_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Key cannot be empty.")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def suggested_output_name(source: Path, known_extensions: list[str]) -> str:
    lower_name = source.name.lower()
    for extension in known_extensions:
        if lower_name.endswith(extension.lower()):
            return source.name[: -len(extension)]
    if source.suffix:
        return source.stem + ".decrypted"
    return source.name + ".decrypted"


def decrypt_file_xor(source: Path, destination_dir: Path, key: bytes, known_extensions: list[str]) -> Path:
    payload = source.read_bytes()
    decrypted = xor_crypt(payload, key)
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination_path = destination_dir / suggested_output_name(source, known_extensions)
    destination_path.write_bytes(decrypted)
    return destination_path


def assess_plaintext(data: bytes) -> tuple[bool, str]:
    if not data:
        return True, "Empty file."

    sample = data[:2048]
    printable = 0
    for byte in sample:
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            printable += 1
    ratio = printable / len(sample)

    if ratio >= 0.9:
        try:
            preview = sample.decode("utf-8")
        except UnicodeDecodeError:
            preview = sample.decode("latin-1", errors="replace")
        preview = preview[:240].strip()
        if not preview:
            preview = "Text output detected, but the preview is empty."
        return True, preview

    return False, "Output looks like binary data. That can still be correct if the original file was a document, image, archive, or spreadsheet."


def create_labxor_demo_file(destination_dir: Path, key: bytes) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    plaintext = (
        "Encrypt to Decrypt demo sample\n"
        "If you can read this after decryption, the key worked.\n"
        "Use this sample with Mode = LabXOR Demo and key = demo-key.\n"
    ).encode("utf-8")
    encrypted = xor_crypt(plaintext, key)
    output = destination_dir / "demo_message.txt.labxor"
    output.write_bytes(encrypted)
    return output


class ResourcePanel(ttk.Frame):
    def __init__(self, master: tk.Misc):
        super().__init__(master)
        self.buttons: list[ttk.Button] = []

    def set_resources(self, resources: list[dict]) -> None:
        for button in self.buttons:
            button.destroy()
        self.buttons.clear()

        for resource in resources:
            button = ttk.Button(
                self,
                text=resource["label"],
                command=lambda url=resource["url"]: webbrowser.open_new_tab(url),
            )
            button.pack(side=LEFT, padx=(0, 8), pady=4)
            self.buttons.append(button)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Encrypt to Decrypt")
        self.geometry("1180x760")
        self.minsize(980, 640)

        self.style = ttk.Style(self)
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")
        self.configure(bg="#f4efe7")
        self.style.configure("Card.TFrame", background="#fffaf2")
        self.style.configure("Hero.TFrame", background="#1f3a5f")
        self.style.configure("Hero.TLabel", background="#1f3a5f", foreground="#fffaf2")
        self.style.configure("Muted.TLabel", background="#fffaf2", foreground="#4f6075")
        self.style.configure("Title.TLabel", background="#fffaf2", foreground="#14263f", font=("Georgia", 22, "bold"))
        self.style.configure("Section.TLabel", background="#fffaf2", foreground="#14263f", font=("Georgia", 13, "bold"))
        self.style.configure("Result.TLabelframe", background="#fffaf2")
        self.style.configure("Result.TLabelframe.Label", background="#fffaf2", foreground="#14263f", font=("Georgia", 12, "bold"))
        self.style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        self.style.configure("Primary.TButton", font=("Segoe UI", 11, "bold"))

        self.matches: list[FamilyMatch] = []
        self.selected_match: FamilyMatch | None = None
        self.decrypt_target_files: list[Path] = []
        self.output_folder: Path | None = None
        self.decrypt_mode = tk.StringVar(value="Auto")
        self.key_format = tk.StringVar(value="Text")

        self._build_layout()
        self.bind("<Control-Return>", lambda _event: self.run_analysis())

    def _build_layout(self) -> None:
        outer = ttk.Frame(self, padding=14, style="Card.TFrame")
        outer.pack(fill=BOTH, expand=True)

        hero = ttk.Frame(outer, padding=18, style="Hero.TFrame")
        hero.pack(fill="x", pady=(0, 12))
        ttk.Label(hero, text="Encrypt to Decrypt", style="Hero.TLabel", font=("Georgia", 26, "bold")).pack(anchor="w")
        ttk.Label(
            hero,
            text="A desktop triage tool inspired by No More Ransom workflows: identify likely families, review response guidance, and jump to trusted recovery resources.",
            style="Hero.TLabel",
            wraplength=980,
            font=("Segoe UI", 11),
        ).pack(anchor="w", pady=(6, 0))

        content = ttk.Frame(outer, style="Card.TFrame")
        content.pack(fill=BOTH, expand=True)
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)
        content.rowconfigure(0, weight=1)

        left = ttk.Frame(content, padding=(0, 0, 12, 0), style="Card.TFrame")
        left.grid(row=0, column=0, sticky="nsew")
        right = ttk.Frame(content, style="Card.TFrame")
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)

        notebook = ttk.Notebook(left)
        notebook.pack(fill=BOTH, expand=True)

        triage_tab = ttk.Frame(notebook, padding=12, style="Card.TFrame")
        decrypt_tab = ttk.Frame(notebook, padding=12, style="Card.TFrame")
        notebook.add(triage_tab, text="Triage")
        notebook.add(decrypt_tab, text="Decryption")

        ttk.Label(triage_tab, text="Evidence Input", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            triage_tab,
            text="Paste encrypted filenames or extensions, then add ransom note text if you have it.",
            style="Muted.TLabel",
            wraplength=650,
        ).pack(anchor="w", pady=(4, 12))

        quick_actions = ttk.Frame(triage_tab, style="Card.TFrame")
        quick_actions.pack(fill="x", pady=(0, 12))
        ttk.Button(
            quick_actions,
            text="Analyze Evidence",
            style="Primary.TButton",
            command=self.run_analysis,
        ).pack(side=LEFT)
        ttk.Label(
            quick_actions,
            text="Shortcut: Ctrl+Enter",
            style="Muted.TLabel",
        ).pack(side=LEFT, padx=(12, 0), pady=(3, 0))

        file_frame = ttk.LabelFrame(triage_tab, text="Encrypted File Samples", padding=12, style="Result.TLabelframe")
        file_frame.pack(fill=BOTH)
        self.file_text = tk.Text(
            file_frame,
            height=11,
            wrap="word",
            font=("Consolas", 10),
            bg="#fffdf8",
            fg="#1a2840",
            insertbackground="#1a2840",
            relief="flat",
        )
        self.file_text.pack(fill=BOTH, expand=True)
        ttk.Button(file_frame, text="Load File List", command=self.load_file_list).pack(anchor="e", pady=(8, 0))

        note_frame = ttk.LabelFrame(triage_tab, text="Ransom Note Text", padding=12, style="Result.TLabelframe")
        note_frame.pack(fill=BOTH, pady=(12, 0))
        self.note_text = tk.Text(
            note_frame,
            height=9,
            wrap="word",
            font=("Consolas", 10),
            bg="#fffdf8",
            fg="#1a2840",
            insertbackground="#1a2840",
            relief="flat",
        )
        self.note_text.pack(fill=BOTH, expand=True)
        ttk.Button(note_frame, text="Load Note", command=self.load_note_file).pack(anchor="e", pady=(8, 0))

        triage_action_bar = ttk.Frame(triage_tab, style="Card.TFrame")
        triage_action_bar.pack(fill="x", pady=12)
        ttk.Button(triage_action_bar, text="Analyze", style="Accent.TButton", command=self.run_analysis).pack(side=LEFT)
        ttk.Button(triage_action_bar, text="Load Demo Data", command=self.load_demo).pack(side=LEFT, padx=(8, 0))
        ttk.Button(triage_action_bar, text="Clear", command=self.clear_inputs).pack(side=LEFT, padx=(8, 0))

        ttk.Label(decrypt_tab, text="Decryption Workspace", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            decrypt_tab,
            text="Choose encrypted files, select an output folder, then run a supported local decryptor.",
            style="Muted.TLabel",
            wraplength=650,
        ).pack(anchor="w", pady=(4, 12))

        decrypt_frame = ttk.LabelFrame(decrypt_tab, text="Decryption Controls", padding=12, style="Result.TLabelframe")
        decrypt_frame.pack(fill=BOTH, expand=True)
        decrypt_frame.columnconfigure(1, weight=1)

        ttk.Label(decrypt_frame, text="Files", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.decrypt_files_label = ttk.Label(
            decrypt_frame,
            text="No encrypted files selected",
            style="Muted.TLabel",
            wraplength=430,
        )
        self.decrypt_files_label.grid(row=0, column=1, sticky="w")
        ttk.Button(decrypt_frame, text="Choose Files", command=self.choose_decrypt_files).grid(row=0, column=2, padx=(8, 0))

        ttk.Label(decrypt_frame, text="Output", style="Section.TLabel").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.output_folder_label = ttk.Label(
            decrypt_frame,
            text="No output folder selected",
            style="Muted.TLabel",
            wraplength=430,
        )
        self.output_folder_label.grid(row=1, column=1, sticky="w", pady=(10, 0))
        ttk.Button(decrypt_frame, text="Choose Folder", command=self.choose_output_folder).grid(row=1, column=2, padx=(8, 0), pady=(10, 0))

        ttk.Label(decrypt_frame, text="Mode", style="Section.TLabel").grid(row=2, column=0, sticky="w", pady=(10, 0))
        mode_combo = ttk.Combobox(
            decrypt_frame,
            textvariable=self.decrypt_mode,
            values=["Auto", "LabXOR Demo"],
            state="readonly",
            width=20,
        )
        mode_combo.grid(row=2, column=1, sticky="w", pady=(10, 0))

        ttk.Label(decrypt_frame, text="Key Format", style="Section.TLabel").grid(row=3, column=0, sticky="w", pady=(10, 0))
        key_combo = ttk.Combobox(
            decrypt_frame,
            textvariable=self.key_format,
            values=["Text", "Hex"],
            state="readonly",
            width=20,
        )
        key_combo.grid(row=3, column=1, sticky="w", pady=(10, 0))

        ttk.Label(decrypt_frame, text="Key", style="Section.TLabel").grid(row=4, column=0, sticky="nw", pady=(10, 0))
        self.key_entry = tk.Text(
            decrypt_frame,
            height=3,
            wrap="word",
            font=("Consolas", 10),
            bg="#fffdf8",
            fg="#1a2840",
            insertbackground="#1a2840",
            relief="flat",
        )
        self.key_entry.grid(row=4, column=1, columnspan=2, sticky="ew", pady=(10, 0))

        self.decrypt_hint = ttk.Label(
            decrypt_frame,
            text="Auto uses the selected family. Only LabXOR Demo supports built-in local decryption in this version.",
            style="Muted.TLabel",
            wraplength=620,
        )
        self.decrypt_hint.grid(row=5, column=0, columnspan=3, sticky="w", pady=(10, 0))

        decrypt_actions = ttk.Frame(decrypt_frame, style="Card.TFrame")
        decrypt_actions.grid(row=6, column=0, columnspan=3, sticky="w", pady=(10, 0))
        ttk.Button(decrypt_actions, text="Decrypt Selected Files", style="Primary.TButton", command=self.decrypt_selected_files).pack(side=LEFT)
        ttk.Button(decrypt_actions, text="Load Demo Decryption", command=self.load_demo_decryption).pack(side=LEFT, padx=(8, 0))
        ttk.Button(decrypt_actions, text="Create Demo Sample", command=self.create_demo_sample).pack(side=LEFT, padx=(8, 0))

        result_frame = ttk.LabelFrame(right, text="Likely Matches", padding=12, style="Result.TLabelframe")
        result_frame.pack(fill=BOTH, expand=True)
        result_frame.rowconfigure(0, weight=1)
        result_frame.columnconfigure(0, weight=1)

        self.match_list = tk.Listbox(
            result_frame,
            font=("Segoe UI", 10),
            bg="#fffdf8",
            fg="#1a2840",
            activestyle="none",
            relief="flat",
        )
        self.match_list.grid(row=0, column=0, sticky="nsew")
        self.match_list.bind("<<ListboxSelect>>", self.on_select_match)
        scrollbar = ttk.Scrollbar(result_frame, orient=VERTICAL, command=self.match_list.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.match_list.configure(yscrollcommand=scrollbar.set)

        details_frame = ttk.LabelFrame(right, text="Match Details", padding=12, style="Result.TLabelframe")
        details_frame.pack(fill=BOTH, expand=True, pady=(12, 0))
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(1, weight=1)

        self.detail_title = ttk.Label(details_frame, text="No analysis yet", style="Section.TLabel")
        self.detail_title.grid(row=0, column=0, sticky="w")

        self.detail_text = tk.Text(
            details_frame,
            height=18,
            wrap="word",
            font=("Segoe UI", 10),
            bg="#fffdf8",
            fg="#1a2840",
            relief="flat",
            state="disabled",
        )
        self.detail_text.grid(row=1, column=0, sticky="nsew", pady=(10, 10))

        self.resource_panel = ResourcePanel(details_frame)
        self.resource_panel.grid(row=2, column=0, sticky="w")

        footer = ttk.Label(
            outer,
            text="This tool combines triage with limited local decryption support for supported formats. Real-world ransomware recovery still depends on containment, verified keys, public decryptors, or clean backups.",
            style="Muted.TLabel",
            wraplength=1040,
        )
        footer.pack(anchor="w", pady=(10, 0))

    def load_file_list(self) -> None:
        path = filedialog.askopenfilename(
            title="Open a text file with encrypted filenames",
            filetypes=[("Text files", "*.txt *.log"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            messagebox.showerror("Load error", f"Could not read file list:\n{exc}")
            return
        self.file_text.delete("1.0", END)
        self.file_text.insert("1.0", text)
        self.set_detail_from_text("File list loaded. Click 'Analyze Evidence' or press Ctrl+Enter.")

    def load_note_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open a ransom note text file",
            filetypes=[("Text files", "*.txt *.hta *.html"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            messagebox.showerror("Load error", f"Could not read note file:\n{exc}")
            return
        self.note_text.delete("1.0", END)
        self.note_text.insert("1.0", text)
        self.set_detail_from_text("Ransom note loaded. Click 'Analyze Evidence' or press Ctrl+Enter.")

    def load_demo(self) -> None:
        self.file_text.delete("1.0", END)
        self.file_text.insert(
            "1.0",
            "\n".join(
                [
                    "invoice.xlsx.djvu",
                    "family-photo.jpg.djvu",
                    "desktop/_readme.txt",
                    "archive.zip.djvu",
                ]
            ),
        )
        self.note_text.delete("1.0", END)
        self.note_text.insert(
            "1.0",
            "ATTENTION!\nDon't worry, you can return all your files.\nYour personal ID: 0123456789ABCDEF\n",
        )

    def load_demo_decryption(self) -> None:
        self.file_text.delete("1.0", END)
        self.file_text.insert(
            "1.0",
            "\n".join(
                [
                    "demo_message.txt.labxor",
                    "lab_note.txt",
                ]
            ),
        )
        self.note_text.delete("1.0", END)
        self.note_text.insert("1.0", "Training sample. Recover files using the shared lab key.\n")
        self.decrypt_mode.set("LabXOR Demo")
        self.key_format.set("Text")
        self.key_entry.delete("1.0", END)
        self.key_entry.insert("1.0", "demo-key")
        self.set_detail_from_text(
            "Demo decryption mode loaded.\n\n"
            "Use `Create Demo Sample` to generate a readable `.labxor` file, then choose it, select an output folder, keep the key as `demo-key`, and click `Decrypt Selected Files`."
        )

    def create_demo_sample(self) -> None:
        target = filedialog.askdirectory(title="Choose a folder to save the demo encrypted sample")
        if not target:
            return
        try:
            path = create_labxor_demo_file(Path(target), b"demo-key")
        except OSError as exc:
            messagebox.showerror("Create sample failed", str(exc))
            return

        self.decrypt_mode.set("LabXOR Demo")
        self.key_format.set("Text")
        self.key_entry.delete("1.0", END)
        self.key_entry.insert("1.0", "demo-key")
        self.decrypt_target_files = [path]
        self.decrypt_files_label.configure(text=path.name)
        self.set_detail_from_text(
            "Demo encrypted sample created.\n\n"
            f"Encrypted file: {path}\n"
            "Now choose an output folder and click `Decrypt Selected Files`.\n"
            "The decrypted output should be a readable `.txt` file."
        )

    def clear_inputs(self) -> None:
        self.file_text.delete("1.0", END)
        self.note_text.delete("1.0", END)
        self.match_list.delete(0, END)
        self.key_entry.delete("1.0", END)
        self.decrypt_target_files = []
        self.output_folder = None
        self.decrypt_mode.set("Auto")
        self.key_format.set("Text")
        self.decrypt_files_label.configure(text="No encrypted files selected")
        self.output_folder_label.configure(text="No output folder selected")
        self.set_detail(None)

    def run_analysis(self) -> None:
        file_samples = self.file_text.get("1.0", END).strip()
        note_text = self.note_text.get("1.0", END).strip()

        if not file_samples and not note_text:
            messagebox.showinfo("Add evidence", "Paste encrypted filenames or ransom note text first.")
            return

        self.matches = analyze_inputs(file_samples, note_text)
        self.match_list.delete(0, END)

        if not self.matches:
            self.match_list.insert(END, "No strong family match found")
            self.set_detail_from_text(
                "No confident match yet.\n\n"
                "Try adding:\n"
                "- full encrypted filenames\n"
                "- the exact ransom note filename\n"
                "- a larger excerpt of the note text\n\n"
                "Even without a family match, keep the note, samples, and backups untouched until containment is complete."
            )
            return

        for match in self.matches:
            self.match_list.insert(END, f"{match.name}  |  confidence score {match.score}")

        self.match_list.selection_set(0)
        self.on_select_match()

    def on_select_match(self, _event=None) -> None:
        selection = self.match_list.curselection()
        if not selection or not self.matches:
            return
        index = selection[0]
        if index >= len(self.matches):
            return
        self.set_detail(self.matches[index])

    def set_detail(self, match: FamilyMatch | None) -> None:
        self.selected_match = match
        if match is None:
            self.detail_title.configure(text="No analysis yet")
            self.set_detail_from_text("Run an analysis to see likely matches and recovery guidance.")
            self.resource_panel.set_resources([])
            return

        self.detail_title.configure(text=f"{match.name} analysis")
        detail = {
            "family": match.name,
            "confidence_score": match.score,
            "summary": match.summary,
            "why_it_matched": match.reasons,
            "known_extensions": match.indicators["extensions"],
            "common_note_names": match.indicators["notes"],
            "recommended_response": match.response,
            "decryption_status": match.decryption["status"],
        }
        detail_text = json.dumps(detail, indent=2)
        self.set_detail_from_text(detail_text)
        self.resource_panel.set_resources(match.resources)
        if self.decrypt_mode.get() == "Auto":
            self.refresh_decryption_hint(match)

    def set_detail_from_text(self, value: str) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", END)
        self.detail_text.insert("1.0", value)
        self.detail_text.configure(state="disabled")

    def choose_decrypt_files(self) -> None:
        selected = filedialog.askopenfilenames(
            title="Choose encrypted files to decrypt",
            filetypes=[("All files", "*.*")],
        )
        if not selected:
            return
        self.decrypt_target_files = [Path(item) for item in selected]
        preview = ", ".join(path.name for path in self.decrypt_target_files[:3])
        if len(self.decrypt_target_files) > 3:
            preview += f" and {len(self.decrypt_target_files) - 3} more"
        self.decrypt_files_label.configure(text=preview)

    def choose_output_folder(self) -> None:
        selected = filedialog.askdirectory(title="Choose output folder for decrypted files")
        if not selected:
            return
        self.output_folder = Path(selected)
        self.output_folder_label.configure(text=str(self.output_folder))

    def get_effective_family_for_decryption(self) -> dict | None:
        selected_mode = self.decrypt_mode.get()
        if selected_mode == "LabXOR Demo":
            return next((family for family in RANSOMWARE_DB if family["name"] == "LabXOR Demo"), None)
        if self.selected_match is None:
            return None
        return next((family for family in RANSOMWARE_DB if family["name"] == self.selected_match.name), None)

    def refresh_decryption_hint(self, match: FamilyMatch | None) -> None:
        if match is None:
            self.decrypt_hint.configure(
                text="Auto uses the selected family. Only LabXOR Demo supports built-in local decryption in this version."
            )
            return
        self.decrypt_hint.configure(text=f"Selected family decryption status: {match.decryption['status']}")

    def decrypt_selected_files(self) -> None:
        family = self.get_effective_family_for_decryption()
        if family is None:
            messagebox.showinfo("Choose a family", "Run analysis first or switch Mode to `LabXOR Demo`.")
            return
        if not self.decrypt_target_files:
            messagebox.showinfo("Choose files", "Select one or more encrypted files to decrypt.")
            return
        if self.output_folder is None:
            messagebox.showinfo("Choose output", "Select an output folder for decrypted files.")
            return

        decryption = family["decryption"]
        if decryption["mode"] != "local_xor":
            self.set_detail_from_text(
                f"{family['name']} does not have a bundled local decryptor.\n\n"
                f"Status: {decryption['status']}\n\n"
                "Use the trusted resource links for a verified public decryptor, or restore from clean backups."
            )
            messagebox.showwarning("No built-in decryptor", decryption["status"])
            return

        try:
            key = parse_key(self.key_entry.get("1.0", END), self.key_format.get())
        except ValueError as exc:
            messagebox.showerror("Invalid key", str(exc))
            return

        written_files: list[Path] = []
        failures: list[str] = []
        previews: list[str] = []
        for source in self.decrypt_target_files:
            try:
                written = decrypt_file_xor(source, self.output_folder, key, family["extensions"])
                written_files.append(written)
                is_text, preview = assess_plaintext(written.read_bytes())
                preview_label = "text preview" if is_text else "binary preview"
                previews.append(f"{written.name} ({preview_label}): {preview}")
            except OSError as exc:
                failures.append(f"{source.name}: {exc}")

        summary_lines = [
            f"Decryption mode: {family['name']}",
            f"Output folder: {self.output_folder}",
            f"Files processed: {len(self.decrypt_target_files)}",
            f"Files written: {len(written_files)}",
        ]
        if written_files:
            summary_lines.append("")
            summary_lines.append("Written files:")
            summary_lines.extend(str(path) for path in written_files[:10])
        if previews:
            summary_lines.append("")
            summary_lines.append("Output check:")
            summary_lines.extend(previews[:5])
        if failures:
            summary_lines.append("")
            summary_lines.append("Failures:")
            summary_lines.extend(failures[:10])

        self.set_detail_from_text("\n".join(summary_lines))
        if failures:
            messagebox.showwarning("Decryption finished with warnings", "\n".join(summary_lines[:6]))
        else:
            messagebox.showinfo("Decryption complete", f"Decrypted {len(written_files)} file(s) into:\n{self.output_folder}")


if __name__ == "__main__":
    app = App()
    app.mainloop()
