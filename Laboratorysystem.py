import os
import re
import csv
import logging
import sqlite3
import bcrypt
from datetime import datetime

# Optional Tkinter import for lab compliance
try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    TKINTER_AVAILABLE = True
except ImportError:
    tk = None
    messagebox = None
    ttk = None
    TKINTER_AVAILABLE = False

# Try importing psycopg for PostgreSQL (Supabase)
try:
    import psycopg
    from psycopg.rows import dict_row
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False

# ==========================================================
# CONFIGURATION
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "hardware_inventory.db")
DATABASE_URL = os.getenv("DATABASE_URL")

LOG_DIR = os.path.join(BASE_DIR, "app_logging")
LOG_FILE = os.path.join(LOG_DIR, "app.log")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

APP_TITLE = "Campus Hardware Inventory System"


# ==========================================================
# DATABASE WRAPPER & CONNECTION
# ==========================================================

class DBWrapper:
    """Wrapper to make PostgreSQL and SQLite look identical to controllers."""
    def __init__(self, conn, is_pg=False):
        self.conn = conn
        self.is_pg = is_pg

    def _convert_sql(self, sql):
        if self.is_pg:
            return sql.replace("?", "%s")
        return sql

    def execute(self, sql, params=()):
        sql = self._convert_sql(sql)
        cur = self.conn.cursor()
        cur.execute(sql, tuple(params))
        return cur

    def executemany(self, sql, param_seq):
        sql = self._convert_sql(sql)
        cur = self.conn.cursor()
        cur.executemany(sql, [tuple(p) for p in param_seq])
        return cur

    def commit(self):
        self.conn.commit()

    def rollback(self):
        try:
            self.conn.rollback()
        except Exception:
            pass

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def get_connection():
    db_url = os.getenv("DATABASE_URL")
    if db_url and PSYCOPG_AVAILABLE:
        conn = psycopg.connect(db_url, autocommit=True, row_factory=dict_row)
        return DBWrapper(conn, is_pg=True)
    else:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        return DBWrapper(conn, is_pg=False)


# ==========================================================
# ACTIVITY LOGGER
# ==========================================================

class ActivityLogger:
    @staticmethod
    def log_action(username, action, details=""):
        try:
            conn = get_connection()
            conn.execute("""
                INSERT INTO user_activity_logs (username, action, details)
                VALUES (?, ?, ?)
            """, (username, action, details))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error("Failed to record activity log: %s", e)

    @staticmethod
    def get_user_logs(username):
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT log_id, action, details, created_at
                FROM user_activity_logs
                WHERE username = ?
                ORDER BY log_id DESC
                LIMIT 50
            """, (username,)).fetchall()
            return rows
        finally:
            conn.close()


def init_db():
    conn = get_connection()

    # 1. Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            is_locked INTEGER NOT NULL DEFAULT 0,
            login_attempts INTEGER NOT NULL DEFAULT 0
        )
    """)

    # 2. Hardware table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hardware (
            item_id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_name TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            status TEXT NOT NULL
        )
    """)

    # 3. Password reset requests table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            request_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT,
            status TEXT NOT NULL DEFAULT 'PENDING',
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP
        )
    """)

    # 4. Loans table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS loans (
            loan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            item_id INTEGER,
            item_name TEXT,
            quantity INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'PENDING_BORROW',
            borrowed_at TIMESTAMP,
            expected_return TIMESTAMP,
            returned_at TIMESTAMP,
            remarks TEXT
        )
    """)

    # 5. User Activity Logs table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_activity_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    admin = conn.execute("SELECT id FROM users WHERE UPPER(role) = 'ADMIN' LIMIT 1").fetchone()
    if not admin:
        password_hash = bcrypt.hashpw(b"Admin@123", bcrypt.gensalt()).decode("utf-8")
        try:
            conn.execute("""
                INSERT INTO users (username, email, password_hash, role, is_locked, login_attempts)
                VALUES (?, ?, ?, 'ADMIN', 0, 0)
            """, ("admin", "admin@laboratory.local", password_hash))
            logging.info("Default ADMIN account created.")
        except Exception:
            pass

    conn.commit()
    conn.close()


# ==========================================================
# VALIDATION HELPERS
# ==========================================================

def validate_username(username):
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters long."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username must contain only letters, numbers, and underscores."
    return True, ""


def validate_email(email):
    if not email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return False, "Please enter a valid email address."
    return True, ""


def validate_password(password):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[@!$%&*]", password):
        return False, "Password must contain at least one special character (@, !, $, %, &, *)."
    return True, ""


def get_status(quantity):
    if quantity > 5:
        return "In Stock"
    elif quantity >= 1:
        return "Low Stock"
    return "Out of Stock"


# ==========================================================
# AUTH CONTROLLER
# ==========================================================

class AuthController:

    @staticmethod
    def login_user(username, password):
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            if not user:
                logging.warning("Failed login attempt: unknown username - %s", username)
                return False, "Invalid username or password.", None, False, None

            if user["is_locked"] == 1:
                return False, "This account is locked. Please request a password reset.", user["role"], True, user.get("email", "")

            try:
                stored_hash = user["password_hash"]
                if isinstance(stored_hash, str):
                    stored_hash_bytes = stored_hash.encode("utf-8")
                else:
                    stored_hash_bytes = bytes(stored_hash)

                password_matches = bcrypt.checkpw(
                    password.encode("utf-8"),
                    stored_hash_bytes
                )
            except Exception as e:
                logging.error("Password check exception: %s", e)
                password_matches = False

            if password_matches:
                conn.execute("UPDATE users SET login_attempts = 0 WHERE id = ?", (user["id"],))
                conn.commit()
                logging.info("Successful login: %s | Role: %s", username, user["role"])
                ActivityLogger.log_action(username, "USER_LOGIN", "Logged into system portal.")
                return True, "Login successful.", user["role"], False, user.get("email", "")

            attempts = (user["login_attempts"] or 0) + 1
            if attempts >= 3:
                conn.execute("UPDATE users SET login_attempts = ?, is_locked = 1 WHERE id = ?", (attempts, user["id"]))
                conn.commit()
                logging.warning("Account locked after 3 failed attempts: %s", username)
                ActivityLogger.log_action(username, "ACCOUNT_LOCKED", "Account locked due to 3 consecutive failed login attempts.")
                return False, "Account locked after 3 failed attempts.", user["role"], True, user.get("email", "")

            conn.execute("UPDATE users SET login_attempts = ? WHERE id = ?", (attempts, user["id"]))
            conn.commit()
            remaining = 3 - attempts
            return False, f"Invalid username or password. Remaining attempts: {remaining}", user["role"], False, user.get("email", "")

        except Exception as e:
            conn.rollback()
            logging.error("Database error during login: %s", e)
            return False, f"Database error: {e}", None, False, None
        finally:
            conn.close()

    @staticmethod
    def register_user(username, email, password, role="USER"):
        ok, msg = validate_username(username)
        if not ok:
            return False, msg
        ok, msg = validate_email(email)
        if not ok:
            return False, msg
        ok, msg = validate_password(password)
        if not ok:
            return False, msg

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        conn = get_connection()
        try:
            conn.execute("""
                INSERT INTO users (username, email, password_hash, role, is_locked, login_attempts)
                VALUES (?, ?, ?, ?, 0, 0)
            """, (username, email, pw_hash, role))
            conn.commit()
            logging.info("New account registered: %s | Role: %s", username, role)
            ActivityLogger.log_action(username, "ACCOUNT_REGISTERED", f"Account registered as {role}.")
            return True, "Registration successful! You may now log in."
        except Exception:
            conn.rollback()
            return False, "Username or email is already registered."
        finally:
            conn.close()

    @staticmethod
    def submit_password_reset_request(username, email, new_password):
        ok, msg = validate_password(new_password)
        if not ok:
            return False, msg

        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT id FROM users WHERE username = ? AND email = ?",
                (username, email)
            ).fetchone()

            if not user:
                return False, "Username and registered email do not match."

            pending = conn.execute(
                "SELECT request_id FROM password_resets WHERE username = ? AND status = 'PENDING'",
                (username,)
            ).fetchone()

            if pending:
                return False, "A reset request is already pending for this account."

            pw_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            conn.execute("""
                INSERT INTO password_resets (username, email, password_hash, status)
                VALUES (?, ?, ?, 'PENDING')
            """, (username, email, pw_hash))
            conn.commit()
            logging.info("Password reset request submitted: %s", username)
            ActivityLogger.log_action(username, "RESET_REQUESTED", "Submitted password reset request for admin approval.")
            return True, "Reset request submitted. An admin will review it."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def get_pending_resets():
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT request_id, username, email, requested_at
                FROM password_resets
                WHERE status = 'PENDING'
                ORDER BY request_id DESC
            """).fetchall()
            return rows
        finally:
            conn.close()

    @staticmethod
    def process_bulk_resets(request_ids, approve=True):
        if not request_ids:
            return False, "No requests selected."

        conn = get_connection()
        status = "APPROVED" if approve else "REJECTED"
        try:
            for rid in request_ids:
                req = conn.execute(
                    "SELECT * FROM password_resets WHERE request_id = ?", (rid,)
                ).fetchone()
                if req and req["status"] == "PENDING":
                    if approve:
                        conn.execute("""
                            UPDATE users 
                            SET password_hash = ?, is_locked = 0, login_attempts = 0
                            WHERE username = ?
                        """, (req["password_hash"], req["username"]))
                        ActivityLogger.log_action(req["username"], "RESET_APPROVED", "Admin approved account password reset.")
                    else:
                        ActivityLogger.log_action(req["username"], "RESET_REJECTED", "Admin rejected password reset request.")
                    conn.execute("""
                        UPDATE password_resets
                        SET status = ?, reviewed_at = CURRENT_TIMESTAMP
                        WHERE request_id = ?
                    """, (status, rid))
            conn.commit()
            return True, f"Selected reset request(s) {status.lower()}."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def change_password_direct(username, email, old_password, new_password):
        ok, msg = validate_password(new_password)
        if not ok:
            return False, msg

        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT id, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()

            if not user or not bcrypt.checkpw(old_password.encode("utf-8"), user["password_hash"].encode("utf-8")):
                return False, "Current password is incorrect."

            new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
            conn.commit()
            logging.info("Password changed by %s", username)
            ActivityLogger.log_action(username, "CHANGE_PASSWORD", "User successfully changed account password.")
            return True, "Password updated successfully."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()


# ==========================================================
# INVENTORY CONTROLLER
# ==========================================================

class InventoryController:

    @staticmethod
    def get_all_items(search_text="", category="ALL"):
        conn = get_connection()
        try:
            query = "SELECT item_id, item_name, category, quantity, unit_price, status FROM hardware WHERE 1=1"
            params = []

            if category and category != "ALL":
                query += " AND category = ?"
                params.append(category)

            if search_text:
                query += " AND (LOWER(item_name) LIKE ? OR LOWER(category) LIKE ?)"
                params.extend([f"%{search_text.lower()}%", f"%{search_text.lower()}%"])

            query += " ORDER BY item_id DESC"
            rows = conn.execute(query, params).fetchall()
            return [list(r.values()) if hasattr(r, 'values') else list(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def get_categories():
        conn = get_connection()
        try:
            rows = conn.execute("SELECT DISTINCT category FROM hardware ORDER BY category").fetchall()
            return [r["category"] for r in rows if r["category"]]
        finally:
            conn.close()

    @staticmethod
    def add_item(name, category, quantity, unit_price):
        if not name or not category:
            return False, "Name and Category are required."
        if quantity < 0 or unit_price < 0:
            return False, "Quantity and Unit Price cannot be negative."

        conn = get_connection()
        status = get_status(quantity)
        try:
            conn.execute("""
                INSERT INTO hardware (item_name, category, quantity, unit_price, status)
                VALUES (?, ?, ?, ?, ?)
            """, (name, category, quantity, unit_price, status))
            conn.commit()
            return True, "Equipment added successfully."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def update_item(item_id, name, category, quantity, unit_price):
        if not name or not category:
            return False, "Equipment name and category are required."
        if quantity < 0 or unit_price < 0:
            return False, "Quantity and Unit Price cannot be negative."

        conn = get_connection()
        status = get_status(quantity)
        try:
            conn.execute("""
                UPDATE hardware
                SET item_name = ?, category = ?, quantity = ?, unit_price = ?, status = ?
                WHERE item_id = ?
            """, (name, category, quantity, unit_price, status, item_id))
            conn.commit()
            return True, "Equipment updated successfully."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def delete_bulk_items(item_ids):
        if not item_ids:
            return False, "No items selected."
        conn = get_connection()
        try:
            conn.executemany("DELETE FROM hardware WHERE item_id = ?", [(i,) for i in item_ids])
            conn.commit()
            return True, "Selected equipment deleted successfully."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def borrow_item(username, item_id, quantity=1, borrow_date=None, return_date=None, remarks=""):
        conn = get_connection()
        try:
            item = conn.execute("SELECT quantity, item_name FROM hardware WHERE item_id = ?", (item_id,)).fetchone()
            if not item:
                return False, "Item not found."
            if item["quantity"] < quantity:
                return False, f"Not enough stock. Only {item['quantity']} available."

            conn.execute("""
                INSERT INTO loans (username, item_id, item_name, quantity, status, borrowed_at, expected_return, remarks)
                VALUES (?, ?, ?, ?, 'PENDING_BORROW', ?, ?, ?)
            """, (username, item_id, item["item_name"], quantity, borrow_date, return_date, remarks))
            conn.commit()
            ActivityLogger.log_action(username, "REQUEST_BORROW", f"Requested borrow for {quantity}x '{item['item_name']}'.")
            return True, "Borrow request submitted for administrator approval."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def request_bulk_item_returns(loan_ids):
        if not loan_ids:
            return False, "No items selected to return."
        conn = get_connection()
        try:
            conn.executemany("""
                UPDATE loans 
                SET status = 'PENDING_RETURN'
                WHERE loan_id = ? AND status = 'BORROWED'
            """, [(i,) for i in loan_ids])
            conn.commit()
            return True, "Return request submitted for administrator approval."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def get_user_active_loans(username):
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT l.loan_id, h.item_name, l.quantity, l.borrowed_at, l.expected_return, l.remarks
                FROM loans l JOIN hardware h ON l.item_id = h.item_id
                WHERE l.username = ? AND l.status = 'BORROWED'
                ORDER BY l.loan_id DESC
            """, (username,)).fetchall()
            return rows
        finally:
            conn.close()

    @staticmethod
    def get_user_pending_borrows(username):
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT l.loan_id, h.item_name, l.quantity, l.status, l.borrowed_at, l.expected_return, l.remarks
                FROM loans l JOIN hardware h ON l.item_id = h.item_id
                WHERE l.username = ? AND l.status = 'PENDING_BORROW'
                ORDER BY l.loan_id DESC
            """, (username,)).fetchall()
            return rows
        finally:
            conn.close()

    @staticmethod
    def get_user_loan_history(username):
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT l.loan_id, h.item_name, l.quantity, l.status, l.borrowed_at, l.returned_at
                FROM loans l JOIN hardware h ON l.item_id = h.item_id
                WHERE l.username = ?
                ORDER BY l.loan_id DESC
            """, (username,)).fetchall()
            return rows
        finally:
            conn.close()

    @staticmethod
    def get_pending_borrows():
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT l.loan_id, l.username, h.item_name, l.quantity, l.borrowed_at, l.expected_return, l.remarks
                FROM loans l JOIN hardware h ON l.item_id = h.item_id
                WHERE l.status = 'PENDING_BORROW'
                ORDER BY l.loan_id DESC
            """).fetchall()
            return rows
        finally:
            conn.close()

    @staticmethod
    def get_pending_returns():
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT l.loan_id, l.username, h.item_name, l.quantity
                FROM loans l JOIN hardware h ON l.item_id = h.item_id
                WHERE l.status = 'PENDING_RETURN'
                ORDER BY l.loan_id DESC
            """).fetchall()
            return rows
        finally:
            conn.close()

    @staticmethod
    def get_all_loans_history():
        conn = get_connection()
        try:
            rows = conn.execute("""
                SELECT l.loan_id, l.username, h.item_name, l.quantity, l.status, l.borrowed_at, l.returned_at
                FROM loans l JOIN hardware h ON l.item_id = h.item_id
                ORDER BY l.loan_id DESC
            """).fetchall()
            return rows
        finally:
            conn.close()

    @staticmethod
    def process_bulk_borrows(loan_ids, approve=True):
        if not loan_ids:
            return False, "No requests selected."
        conn = get_connection()
        try:
            for lid in loan_ids:
                loan = conn.execute("SELECT * FROM loans WHERE loan_id = ?", (lid,)).fetchone()
                if loan and loan["status"] == "PENDING_BORROW":
                    if approve:
                        item = conn.execute("SELECT quantity, item_name FROM hardware WHERE item_id = ?", (loan["item_id"],)).fetchone()
                        if item and item["quantity"] >= loan["quantity"]:
                            new_qty = item["quantity"] - loan["quantity"]
                            conn.execute("""
                                UPDATE hardware 
                                SET quantity = ?, status = ? 
                                WHERE item_id = ?
                            """, (new_qty, get_status(new_qty), loan["item_id"]))
                            conn.execute("""
                                UPDATE loans 
                                SET status = 'BORROWED', borrowed_at = CURRENT_TIMESTAMP
                                WHERE loan_id = ?
                            """, (lid,))
                            ActivityLogger.log_action(loan["username"], "BORROW_APPROVED", f"Admin approved borrow of {loan['quantity']}x '{item['item_name']}'.")
                    else:
                        conn.execute("UPDATE loans SET status = 'REJECTED' WHERE loan_id = ?", (lid,))
                        ActivityLogger.log_action(loan["username"], "BORROW_REJECTED", f"Admin rejected borrow request for Loan #{lid}.")
            conn.commit()
            return True, f"Borrow request(s) {'approved' if approve else 'rejected'}."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def process_bulk_returns(loan_ids, approve=True):
        if not loan_ids:
            return False, "No return requests selected."
        conn = get_connection()
        try:
            for lid in loan_ids:
                loan = conn.execute("SELECT * FROM loans WHERE loan_id = ?", (lid,)).fetchone()
                if loan and loan["status"] == "PENDING_RETURN":
                    if approve:
                        item = conn.execute("SELECT quantity, item_name FROM hardware WHERE item_id = ?", (loan["item_id"],)).fetchone()
                        if item:
                            new_qty = item["quantity"] + loan["quantity"]
                            conn.execute("""
                                UPDATE hardware 
                                SET quantity = ?, status = ? 
                                WHERE item_id = ?
                            """, (new_qty, get_status(new_qty), loan["item_id"]))
                            conn.execute("""
                                UPDATE loans 
                                SET status = 'RETURNED', returned_at = CURRENT_TIMESTAMP 
                                WHERE loan_id = ?
                            """, (lid,))
                            ActivityLogger.log_action(loan["username"], "RETURN_APPROVED", f"Admin confirmed return of {loan['quantity']}x '{item['item_name']}'.")
                    else:
                        conn.execute("UPDATE loans SET status = 'BORROWED' WHERE loan_id = ?", (lid,))
                        ActivityLogger.log_action(loan["username"], "RETURN_REJECTED", f"Admin declined return request for Loan #{lid}.")
            conn.commit()
            return True, f"Return request(s) {'approved' if approve else 'rejected'}."
        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def export_to_csv(username):
        try:
            conn = get_connection()
            try:
                rows = conn.execute("""
                    SELECT item_id, item_name, category, quantity, unit_price, status
                    FROM hardware ORDER BY item_id
                """).fetchall()
            finally:
                conn.close()

            csv_path = os.path.abspath("inventory_report.csv")
            with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Equipment Name", "Category", "Quantity", "Unit Price", "Status"])
                for r in rows:
                    writer.writerow([r["item_id"], r["item_name"], r["category"], r["quantity"], r["unit_price"], r["status"]])

            logging.info("Inventory report generated by %s", username)
            ActivityLogger.log_action(username, "EXPORT_CSV", "Exported hardware inventory report to CSV.")
            return True, "Export successful."
        except Exception as e:
            return False, str(e)


# ==========================================================
# CLI RUNNER
# ==========================================================

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
    print("Run 'python app.py' to launch the Flask web application.")