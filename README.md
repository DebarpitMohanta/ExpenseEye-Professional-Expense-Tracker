## 📌 Overview
ExpenseEye is a lightweight, professional-grade expense tracking web application built **without using any frameworks** like Flask or Django.  
The goal is to demonstrate strong backend fundamentals (WSGI, routing, hashing, sessions) and clean frontend development using only **HTML, CSS, SQL, and raw Python**.

The system allows users to securely register, log in, add expenses, view detailed reports, and export data — all through a polished and responsive interface.

---

## 🚀 Features
- **User Authentication**
  - Register & login with salted SHA256 password hashing  
  - Secure cookie-based session management  

- **Expense Management**
  - Add, view, and categorize expenses  
  - Category-wise analytics  
  - Clean responsive UI  

- **CSV Export**
  - Download all expenses in CSV format  

- **Auto Database Setup**
  - Automatically creates `expenseeye.db` from `database.sql`  
  - No sqlite3 installation required  

- **No Frameworks Used**
  - Custom WSGI routing  
  - Secure SQL queries  
  - Pure Python backend logic  

---

## 🛠️ Tech Stack
**Frontend:**  
- HTML5  
- CSS3 (fully responsive)  

**Backend:**  
- Python (WSGI – no frameworks)  
- SQLite (SQL database)  

**Other:**  
- SHA256 password hashing  
- Vanilla browser-based UI  

---

## 📂 Project Structure
