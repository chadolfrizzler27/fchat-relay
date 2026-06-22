# FChat Relay Setup Instructions

This is the backend server relay for the FChat E2E Encrypted Chat client. It stores encrypted message payloads in an SQLite database and handles user authentication statelessly using SHA-256 hashes.

## Requirements
* PHP 8.0 or higher
* SQLite 3 module (`pdo_sqlite` extension enabled in `php.ini`)
* Writable directory permissions on the backend folder so PHP can create the database file
* Apache or Nginx web server

## Installation and Configuration

1. **Upload Files**: Copy the contents of the `backend` folder to your web server (e.g. inside `public_html/backend` or a dedicated subdomain).
2. **Configure Folder Permissions**: Make sure the directory hosting the files is writable by the web server user (e.g. `www-data` or `apache`):
   ```bash
   chmod 775 /path/to/backend
   chown -R www-data:www-data /path/to/backend
   ```
3. **Run Initial Setup**: Access `setup_relay.php` via your browser (e.g., `https://yourdomain.com/backend/setup_relay.php`). This script will automatically verify requirements and build the SQLite database (`chat_relay.sqlite`) with appropriate tables and indexes.
4. **Access Control**: The `.htaccess` file blocks direct browser downloads of the SQLite database. Ensure `AllowOverride All` is set in your Apache configuration for this directory to enable `.htaccess` protection.
5. **Secure the Admin Console**: Open `admin.php` and change the hardcoded password constant at the top of the file:
   ```php
   define('ADMIN_PASSWORD', 'your_super_secure_random_admin_password');
   ```

## Repository Link
For the official relay distribution, updates, and community documentation, visit:
[https://github.com/chadolfrizzler27/fchat-relay](https://github.com/chadolfrizzler27/fchat-relay)
