# Web Application Project

This project is a web application that includes a login page for normal users, with different views for root and administrators. It utilizes an SQLite database for user logins instead of CSV files.

## Project Structure

```
web-app
├── src
│   ├── app.py
│   ├── auth
│   │   ├── __init__.py
│   │   ├── login.py
│   │   └── models.py
│   ├── views
│   │   ├── __init__.py
│   │   ├── user_view.py
│   │   ├── admin_view.py
│   │   └── root_view.py
│   ├── templates
│   │   ├── login.html
│   │   ├── user_dashboard.html
│   │   ├── admin_dashboard.html
│   │   └── root_dashboard.html
│   └── database
│       ├── __init__.py
│       └── db.sqlite3
├── requirements.txt
└── README.md
```

## Setup Instructions

1. **Clone the Repository**
   Clone this repository to your local machine using:
   ```
   git clone <repository-url>
   ```

2. **Navigate to the Project Directory**
   Change to the project directory:
   ```
   cd web-app
   ```

3. **Install Dependencies**
   Install the required Python packages listed in `requirements.txt`:
   ```
   pip install -r requirements.txt
   ```

4. **Run the Application**
   Start the web application by running:
   ```
   python src/app.py
   ```

5. **Access the Application**
   Open your web browser and go to `http://localhost:5000` to access the login page.

## Usage Guidelines

- Users can log in using their credentials. Based on their role (normal user, administrator, or root), they will be redirected to the appropriate dashboard.
- The application uses an SQLite database to store user information securely.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.