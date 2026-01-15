# vibe-coded with manual modifications

import os
import sys
from dataclasses import dataclass
from typing import Optional, List, Tuple

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog, QMessageBox,
    QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QLabel, QComboBox, QTableWidget, QTableWidgetItem, QGroupBox,
    QSplitter, QTextEdit, QDialog, QSpinBox
)

# PKCS#11
from pkcs11 import lib as pkcs11_lib
from pkcs11 import Mechanism, Attribute, ObjectClass, KeyType, Object
from pkcs11.exceptions import AttributeTypeInvalid, AttributeSensitive

@dataclass
class SlotInfo:
    slot_id: int
    description: str
    token_label: str
    token_serial: str
    has_token: bool


def safe_str(x) -> str:
    try:
        return str(x).strip()
    except Exception:
        return "<unprintable>"


class CreateObjectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Object")
        self.setModal(True)

        layout = QFormLayout(self)

        self.key_type_combo = QComboBox()
        self.key_type_combo.addItem("AES", KeyType.AES)
        self.key_type_combo.addItem("EC", KeyType.EC)

        self.key_size_spin = QSpinBox()
        self.key_size_spin.setMinimum(128)
        self.key_size_spin.setMaximum(4096)
        self.key_size_spin.setValue(256)
        self.key_size_spin.setSingleStep(8)

        self.label_edit = QLineEdit()
        self.label_edit.setPlaceholderText("(optional)")

        layout.addRow("Key Type:", self.key_type_combo)
        layout.addRow("Key Size (bits):", self.key_size_spin)
        layout.addRow("Label:", self.label_edit)

        buttons = QHBoxLayout()
        ok_btn = QPushButton("OK")
        cancel_btn = QPushButton("Cancel")
        ok_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(ok_btn)
        buttons.addWidget(cancel_btn)

        layout.addRow(buttons)

    def get_values(self):
        return (
            self.key_type_combo.currentData(),
            self.key_size_spin.value(),
            self.label_edit.text()
        )


class Worker(QThread):
    ok = Signal(object)
    err = Signal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            res = self.fn(*self.args, **self.kwargs)
            self.ok.emit(res)
        except Exception as e:
            self.err.emit(f"{type(e).__name__}: {e}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PKCS#11 GUI (Python)")

        self.pkcs11 = None
        self.module_path: Optional[str] = None

        self.current_slot_id: Optional[int] = None
        self.current_session = None  # pkcs11.Session

        self.listed_objects: List[Object] = []

        self._build_ui()
        self._set_connected(False)

    # ---------------- UI ----------------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # Top: module loader
        top = QGroupBox("PKCS#11 Module")
        top_l = QHBoxLayout(top)
        self.module_path_edit = QLineEdit()
        self.module_path_edit.setPlaceholderText("Path to PKCS#11 library (.so/.dll/.dylib)")
        browse_btn = QPushButton("Browse…")
        load_btn = QPushButton("Load")
        browse_btn.clicked.connect(self.on_browse_module)
        load_btn.clicked.connect(self.on_load_module)
        top_l.addWidget(self.module_path_edit, 1)
        top_l.addWidget(browse_btn)
        top_l.addWidget(load_btn)
        root.addWidget(top)

        splitter = QSplitter(Qt.Horizontal)
        root.addWidget(splitter, 1)

        # Left: slots + session controls
        left = QWidget()
        left_l = QVBoxLayout(left)
        splitter.addWidget(left)

        slots_box = QGroupBox("Slots / Tokens")
        slots_l = QVBoxLayout(slots_box)
        self.refresh_slots_btn = QPushButton("Refresh slots")
        self.refresh_slots_btn.clicked.connect(self.on_refresh_slots)
        self.slot_combo = QComboBox()
        self.slot_combo.currentIndexChanged.connect(self.on_slot_changed)

        slots_l.addWidget(self.refresh_slots_btn)
        slots_l.addWidget(QLabel("Select slot:"))
        slots_l.addWidget(self.slot_combo)
        left_l.addWidget(slots_box)

        sess_box = QGroupBox("Session")
        sess_l = QFormLayout(sess_box)
        self.pin_edit = QLineEdit()
        self.pin_edit.setEchoMode(QLineEdit.Password)
        self.open_session_btn = QPushButton("Open session")
        self.close_session_btn = QPushButton("Close session")

        self.open_session_btn.clicked.connect(self.on_open_session)
        self.close_session_btn.clicked.connect(self.on_close_session)

        sess_l.addRow("PIN:", self.pin_edit)

        sess_btns = QHBoxLayout()
        sess_btns.addWidget(self.open_session_btn)
        sess_btns.addWidget(self.close_session_btn)

        sess_l.addRow(sess_btns)
        left_l.addWidget(sess_box)

        # Right: objects + operations + log
        right = QWidget()
        right_l = QVBoxLayout(right)
        splitter.addWidget(right)
        splitter.setStretchFactor(1, 2)

        obj_box = QGroupBox("Objects")
        obj_l = QVBoxLayout(obj_box)

        obj_toolbar = QHBoxLayout()
        self.list_objects_btn = QPushButton("List objects")
        self.list_objects_btn.clicked.connect(self.on_list_objects)

        self.create_object_btn = QPushButton("Create object")
        self.create_object_btn.clicked.connect(self.on_create_object)

        self.delete_object_btn = QPushButton("Delete object")
        self.delete_object_btn.clicked.connect(self.on_delete_object)

        self.view_attrs_btn = QPushButton("View attributes")
        self.view_attrs_btn.clicked.connect(self.on_view_attributes)

        self.class_filter = QComboBox()
        self.class_filter.addItem("All", None)
        self.class_filter.addItem("Public Key", ObjectClass.PUBLIC_KEY)
        self.class_filter.addItem("Private Key", ObjectClass.PRIVATE_KEY)
        self.class_filter.addItem("Secret Key", ObjectClass.SECRET_KEY)
        self.class_filter.addItem("Certificate", ObjectClass.CERTIFICATE)
        self.class_filter.addItem("Data", ObjectClass.DATA)

        obj_toolbar.addWidget(QLabel("Filter:"))
        obj_toolbar.addWidget(self.class_filter)
        obj_toolbar.addStretch(1)
        obj_toolbar.addWidget(self.list_objects_btn)
        obj_toolbar.addWidget(self.create_object_btn)
        obj_toolbar.addWidget(self.view_attrs_btn)
        obj_toolbar.addWidget(self.delete_object_btn)

        self.obj_table = QTableWidget(0, 5)
        self.obj_table.setHorizontalHeaderLabels(["Handle", "Class", "Label", "ID (hex)", "Key Type"])
        self.obj_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.obj_table.setEditTriggers(QTableWidget.NoEditTriggers)

        obj_l.addLayout(obj_toolbar)
        obj_l.addWidget(self.obj_table, 1)
        right_l.addWidget(obj_box, 2)

        ops_box = QGroupBox("Operations")
        ops_l = QVBoxLayout(ops_box)
        sign_row = QHBoxLayout()
        self.sign_file_btn = QPushButton("Sign file…")
        self.sign_file_btn.clicked.connect(self.on_sign_file)
        self.mechanism_combo = QComboBox()
        self.mechanism_combo.addItem("RSA PKCS#1 v1.5 (SHA-256)", Mechanism.SHA256_RSA_PKCS)
        self.mechanism_combo.addItem("ECDSA (SHA-256)", Mechanism.ECDSA_SHA256)
        self.mechanism_combo.addItem("RSA-PSS (SHA-256)", Mechanism.SHA256_RSA_PKCS_PSS)
        self.mechanism_combo.addItem("EDDSA", Mechanism.EDDSA)
        sign_row.addWidget(QLabel("Mechanism:"))
        sign_row.addWidget(self.mechanism_combo, 1)
        sign_row.addWidget(self.sign_file_btn)
        ops_l.addLayout(sign_row)
        ops_l.addWidget(QLabel("Tip: select a PRIVATE KEY row above, then sign."))
        right_l.addWidget(ops_box)

        log_box = QGroupBox("Log")
        log_l = QVBoxLayout(log_box)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        log_l.addWidget(self.log)
        right_l.addWidget(log_box, 1)

    def _set_connected(self, loaded: bool):
        self.refresh_slots_btn.setEnabled(loaded)
        self.slot_combo.setEnabled(loaded)

        sess_enabled = loaded and self.current_slot_id is not None
        self.open_session_btn.setEnabled(sess_enabled and self.current_session is None)
        self.close_session_btn.setEnabled(sess_enabled and self.current_session is not None)

        obj_enabled = self.current_session is not None
        self.list_objects_btn.setEnabled(obj_enabled)
        self.create_object_btn.setEnabled(obj_enabled)
        self.view_attrs_btn.setEnabled(obj_enabled)
        self.class_filter.setEnabled(obj_enabled)
        self.sign_file_btn.setEnabled(obj_enabled)
        self.delete_object_btn.setEnabled(obj_enabled)

        if obj_enabled:
            self.on_list_objects()

    def _log(self, msg: str):
        self.log.append(msg)

    def _error(self, msg: str):
        QMessageBox.critical(self, "Error", msg)
        self._log(f"ERROR: {msg}")
    
    def on_delete_object(self):
        if not self.current_session:
            return

        object_index = self._selected_object_index()
        if object_index is None:
            self._error("Select an object row first.")
            return

        obj = self.listed_objects[object_index]
        label = obj[Attribute.LABEL]
        label_str = label.decode(errors="ignore") if isinstance(label, (bytes, bytearray)) else safe_str(label)

        reply = QMessageBox.warning(
            self,
            "Confirm Deletion",
            f"Delete object: {label_str}?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            def delete_obj():
                obj.destroy()

            self._log(f"Deleting object: {label_str}")
            w = Worker(delete_obj)
            w.ok.connect(lambda _: self._log(f"Object deleted.") or self.on_list_objects())
            w.err.connect(self._error)
            w.start()
            self._worker = w

    def on_view_attributes(self):
        if not self.current_session:
            return

        object_index = self._selected_object_index()
        if object_index is None:
            self._error("Select an object row first.")
            return

        obj = self.listed_objects[object_index]

        dialog = QDialog(self)
        dialog.setWindowTitle("Object Attributes")
        dialog.resize(600, 400)
        layout = QVBoxLayout(dialog)

        table = QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["Attribute", "Value", "Description"])
        table.setEditTriggers(QTableWidget.NoEditTriggers)

        # PKCS#11 attribute descriptions
        attr_descriptions = {
            Attribute.CLASS: "Object class (e.g., PUBLIC_KEY, PRIVATE_KEY, SECRET_KEY, CERTIFICATE, DATA)",
            Attribute.TOKEN: "Whether the object is stored on the token (persistent) or in session memory",
            Attribute.PRIVATE: "Whether the object is private and requires authentication to access",
            Attribute.LABEL: "Human-readable label for the object, useful for identification",
            Attribute.APPLICATION: "Identifies the application that manages the object",
            Attribute.ID: "Identifier for the object, often used to match public/private key pairs",
            Attribute.CERTIFICATE_TYPE: "Type of certificate (X.509, X.509 Attr, WTLS)",
            Attribute.ISSUER: "DER-encoded X.509 issuer name of the certificate",
            Attribute.SERIAL_NUMBER: "Certificate serial number assigned by the issuer",
            Attribute.AC_ISSUER: "Issuer of the attribute certificate",
            Attribute.OWNER: "DER-encoded owner name for attribute certificates",
            Attribute.ATTR_TYPES: "BER-encoded attribute types for attribute certificates",
            Attribute.TRUSTED: "Whether the certificate is trusted for its stated purpose",
            Attribute.JAVA_MIDP_SECURITY_DOMAIN: "Java MIDP security domain identifier",
            Attribute.URL: "URL value associated with the object",
            Attribute.HASH_OF_SUBJECT_PUBLIC_KEY: "SHA-1 hash of the subject's public key",
            Attribute.HASH_OF_ISSUER_PUBLIC_KEY: "SHA-1 hash of the issuer's public key",
            Attribute.CHECK_VALUE: "Check value (usually first/last bytes) for object verification",
            Attribute.KEY_TYPE: "Type of cryptographic key (RSA, EC, AES, DES, etc.)",
            Attribute.SUBJECT: "DER-encoded X.509 subject name",
            Attribute.SENSITIVE: "Whether the object is sensitive and cannot be read in plaintext",
            Attribute.ENCRYPT: "Whether the key can be used for encryption operations",
            Attribute.DECRYPT: "Whether the key can be used for decryption operations",
            Attribute.SIGN: "Whether the key can be used to create digital signatures",
            Attribute.VERIFY: "Whether the key can be used to verify digital signatures",
            Attribute.WRAP: "Whether the key can wrap (encrypt) other keys for transport",
            Attribute.UNWRAP: "Whether the key can unwrap (decrypt) other keys",
            Attribute.SIGN_RECOVER: "Whether the key supports signing with message recovery",
            Attribute.VERIFY_RECOVER: "Whether the key supports verification with message recovery",
            Attribute.DERIVE: "Whether the key can derive other keys using KDF mechanisms",
            Attribute.START_DATE: "Start date of object validity (YYYYMMDD format)",
            Attribute.END_DATE: "End date of object validity (YYYYMMDD format)",
            Attribute.MODULUS: "Modulus (N) of an RSA public or private key",
            Attribute.MODULUS_BITS: "Length of RSA modulus in bits",
            Attribute.PUBLIC_EXPONENT: "Public exponent (E) of an RSA key",
            Attribute.PRIVATE_EXPONENT: "Private exponent (D) of an RSA private key",
            Attribute.PRIME_1: "Prime factor P of RSA private key (part of CRT)",
            Attribute.PRIME_2: "Prime factor Q of RSA private key (part of CRT)",
            Attribute.EXPONENT_1: "Exponent 1 (D mod P-1) of RSA private key (CRT optimization)",
            Attribute.EXPONENT_2: "Exponent 2 (D mod Q-1) of RSA private key (CRT optimization)",
            Attribute.COEFFICIENT: "CRT coefficient (Q^-1 mod P) for RSA private key",
            Attribute.PRIME: "Prime (P) of a Diffie-Hellman key pair",
            Attribute.SUBPRIME: "Subprime (Q) of a Diffie-Hellman key pair",
            Attribute.BASE: "Base (G) of a Diffie-Hellman key pair",
            Attribute.PRIME_BITS: "Length of DH prime in bits",
            Attribute.SUBPRIME_BITS: "Length of DH subprime in bits",
            Attribute.VALUE_BITS: "Length of secret key value in bits",
            Attribute.VALUE_LEN: "Length of key value in bytes",
            Attribute.EXTRACTABLE: "Whether the key material can be extracted from the token",
            Attribute.LOCAL: "Whether the key was generated locally on the token",
            Attribute.NEVER_EXTRACTABLE: "Whether the key can never be extracted (enforced by token)",
            Attribute.ALWAYS_SENSITIVE: "Whether the key has always been marked as sensitive",
            Attribute.KEY_GEN_MECHANISM: "Mechanism type used to generate the key",
            Attribute.MODIFIABLE: "Whether the object attributes can be modified",
            Attribute.EC_PARAMS: "DER-encoded elliptic curve parameters (OID or explicit params)",
            Attribute.EC_POINT: "Elliptic curve point (public key) as octet string",
            Attribute.SECONDARY_AUTH: "Secondary authentication required for key use",
            Attribute.AUTH_PIN_FLAGS: "Authentication PIN flags for access control",
            Attribute.ALWAYS_AUTHENTICATE: "Whether user authentication is required before each use",
            Attribute.WRAP_WITH_TRUSTED: "Whether key wrapping must use a trusted key",
            Attribute.OTP_FORMAT: "Format of one-time password (DECIMAL, HEXADECIMAL, ALPHANUMERIC)",
            Attribute.OTP_LENGTH: "Length of generated one-time password",
            Attribute.OTP_TIME_INTERVAL: "Time interval in seconds for time-based OTP",
            Attribute.OTP_USER_FRIENDLY_MODE: "User-friendly mode for OTP (easier to read format)",
            Attribute.OTP_COUNTER: "Counter value for counter-based OTP",
            Attribute.GOSTR3410_PARAMS: "GOST R 34.10 elliptic curve parameters",
            Attribute.GOSTR3411_PARAMS: "GOST R 34.11 hash algorithm parameters",
            Attribute.GOST28147_PARAMS: "GOST 28147 symmetric cipher parameters",
            Attribute.HW_FEATURE_TYPE: "Type of hardware feature (CLOCK, MONOTONIC_COUNTER, etc.)",
            Attribute.RESET_ON_INIT: "Whether hardware feature resets on initialization",
            Attribute.HAS_RESET: "Whether the hardware feature has been reset",
        }
        for attr in Attribute:
            try:
                value = obj[attr]
            except AttributeTypeInvalid:
                continue
            except AttributeSensitive:
                value = "<sensitive>"
            except NotImplementedError:
                value = "<retrieval not implemented>"
            if isinstance(value, (bytes, bytearray)):
                value = value.hex()

            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(attr.name))
            table.setItem(row, 1, QTableWidgetItem(str(value)))
            description = attr_descriptions.get(attr, "No description available")
            table.setItem(row, 2, QTableWidgetItem(description))

        layout.addWidget(table)
        dialog.exec()

    def on_create_object(self):
        if not self.current_session:
            return

        dialog = CreateObjectDialog(self)
        if dialog.exec():
            key_type, key_size, label = dialog.get_values()

            def create_obj():
                template = {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: key_type,
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                    Attribute.SENSITIVE: True,
                    Attribute.DECRYPT: True,
                    Attribute.ENCRYPT: True,
                    Attribute.SIGN: True,
                    Attribute.VERIFY: True,
                    Attribute.WRAP: True,
                    Attribute.UNWRAP: True,
                }
                if label:
                    template[Attribute.LABEL] = label.encode()

                mech = Mechanism.AES_KEY_GEN if key_type == KeyType.AES else Mechanism.EC_KEY_PAIR_GEN
                obj = self.current_session.generate_secret_key(mech, template)
                return obj.handle

            self._log(f"Creating object: {label}")
            w = Worker(create_obj)
            w.ok.connect(lambda h: self._log(f"Object created with handle: {h}") or self.on_list_objects())
            w.err.connect(self._error)
            w.start()
            self._worker = w

    # ---------------- Actions ----------------
    def on_browse_module(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select PKCS#11 Library", "",
            "Libraries (*.so *.dll *.dylib);;All files (*)"
        )
        if path:
            self.module_path_edit.setText(path)

    def on_load_module(self):
        path = self.module_path_edit.text().strip()
        if not path or not os.path.exists(path):
            self._error("Please choose a valid PKCS#11 library path.")
            return

        def load():
            lib = pkcs11_lib(path)
            # Force a small call to validate it loads
            _ = list(lib.get_slots())
            return lib

        self._log(f"Loading module: {path}")
        w = Worker(load)
        w.ok.connect(self._on_loaded)
        w.err.connect(self._error)
        w.start()
        self._worker = w

    def _on_loaded(self, lib):
        self.pkcs11 = lib
        self.module_path = self.module_path_edit.text().strip()
        self._log("Module loaded.")
        self.on_refresh_slots()

    def on_refresh_slots(self):
        if not self.pkcs11:
            return

        def fetch_slots() -> List[SlotInfo]:
            out = []
            for s in self.pkcs11.get_slots(token_present=False):
                try:
                    token = s.get_token()
                    has_token = True
                    label = safe_str(token.label)
                    serial = safe_str(token.serial)
                except Exception:
                    has_token = False
                    label = ""
                    serial = ""
                out.append(SlotInfo(
                    slot_id=s.slot_id,
                    description=safe_str(s.slot_description),
                    token_label=label,
                    token_serial=serial,
                    has_token=has_token
                ))
            return out

        self._log("Refreshing slots…")
        w = Worker(fetch_slots)
        w.ok.connect(self._on_slots)
        w.err.connect(self._error)
        w.start()
        self._worker = w

    def _on_slots(self, slots: List[SlotInfo]):
        self.slot_combo.blockSignals(True)
        self.slot_combo.clear()

        for si in slots:
            if si.has_token:
                text = f"Slot {si.slot_id}: {si.token_label} (SN {si.token_serial})"
            else:
                text = f"Slot {si.slot_id}: (no token) {si.description}"
            self.slot_combo.addItem(text, si.slot_id)

        self.slot_combo.blockSignals(False)
        self.current_slot_id = self.slot_combo.currentData()
        self._log(f"Found {len(slots)} slots.")
        self._set_connected(True)

    def on_slot_changed(self, _idx: int):
        self.current_slot_id = self.slot_combo.currentData()
        self._log(f"Selected slot: {self.current_slot_id}")
        self._set_connected(self.pkcs11 is not None)

    def on_open_session(self):
        if not self.pkcs11 or self.current_slot_id is None:
            return

        def open_sess():
            slot = [s for s in self.pkcs11.get_slots(token_present=False) if s.slot_id == int(self.current_slot_id)][0]
            token = slot.get_token()
            sess = token.open(rw=True, user_pin=self.pin_edit.text() or None)
            return sess

        self._log("Opening session…")
        w = Worker(open_sess)
        w.ok.connect(self._on_session_opened)
        w.err.connect(self._error)
        w.start()
        self._worker = w

    def _on_session_opened(self, sess):
        self.current_session = sess
        self._log("Session opened.")
        self._set_connected(self.pkcs11 is not None)

    def on_close_session(self):
        if not self.current_session:
            return
        try:
            self.current_session.close()
            self._log("Session closed.")
        except Exception as e:
            self._error(str(e))
        self.current_session = None
        self.obj_table.setRowCount(0)
        self._set_connected(self.pkcs11 is not None)

    def on_list_objects(self):
        if not self.current_session:
            return

        cls = self.class_filter.currentData()

        def list_objs():
            template = {}
            if cls is not None:
                template[Attribute.CLASS] = cls

            objs = list(self.current_session.get_objects(template))
            rows = []
            self.listed_objects = objs
            for o in objs:
                # Best effort attributes
                klass = o[Attribute.CLASS]
                label = o[Attribute.LABEL]
                obj_id = o[Attribute.ID]
                key_type = o[Attribute.KEY_TYPE]
                class_name = ObjectClass(klass).name
                key_type_name = KeyType(key_type).name

                rows.append((
                    int(o.handle),
                    safe_str(class_name),
                    label.decode(errors="ignore") if isinstance(label, (bytes, bytearray)) else safe_str(label),
                    obj_id.hex() if isinstance(obj_id, (bytes, bytearray)) else safe_str(obj_id),
                    safe_str(key_type_name),
                ))
            return rows

        self._log("Listing objects…")
        w = Worker(list_objs)
        w.ok.connect(self._on_objects)
        w.err.connect(self._error)
        w.start()
        self._worker = w

    def _on_objects(self, rows: List[Tuple]):
        self.obj_table.setRowCount(0)
        for r, row in enumerate(rows):
            self.obj_table.insertRow(r)
            for c, val in enumerate(row):
                self.obj_table.setItem(r, c, QTableWidgetItem(str(val)))
        self._log(f"Objects: {len(rows)}")

    def _selected_object_handle(self) -> Optional[int]:
        sel = self.obj_table.selectionModel().selectedRows()
        if not sel:
            return None
        row = sel[0].row()
        try:
            return int(self.obj_table.item(row, 0).text())
        except Exception:
            return None

    def _selected_object_id(self) -> Optional[int]:
        sel = self.obj_table.selectionModel().selectedRows()
        if not sel:
            return None
        row = sel[0].row()
        try:
            return int(self.obj_table.item(row, 3).text(), 16)
        except Exception:
            return None

    def _selected_object_index(self) -> Optional[int]:
        sel = self.obj_table.selectionModel().selectedRows()
        if not sel:
            return None
        return sel[0].row()

    def on_sign_file(self):
        if not self.current_session:
            return

        object_index = self._selected_object_index()
        if object_index is None:
            self._error("Select a PRIVATE KEY object row first.")
            return

        in_path, _ = QFileDialog.getOpenFileName(self, "Select file to sign", "", "All files (*)")
        if not in_path:
            return

        mech = self.mechanism_combo.currentData()
        out_path = in_path + ".sig"

        def do_sign():
            with open(in_path, "rb") as f:
                data = f.read()

            # Many tokens expect "raw" data for the combined SHA256_RSA_PKCS / ECDSA_SHA256 mechanisms,
            # and they hash internally. Some tokens expect you to hash first depending on mechanism.
            # This example uses the "hashing" mechanisms in pkcs11 where supported.
            priv = self.listed_objects[object_index]

            sig = priv.sign(data, mechanism=mech)

            with open(out_path, "wb") as f:
                f.write(sig)

            return (len(data), len(sig), out_path)

        self._log(f"Signing: {in_path}")
        w = Worker(do_sign)
        w.ok.connect(lambda r: self._log(f"Signed {r[0]} bytes -> {r[1]} bytes signature: {r[2]}"))
        w.err.connect(self._error)
        w.start()
        self._worker = w


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.resize(1100, 700)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
