<?php
/**
 * FChat Relay Setup Script
 * Verifies system requirements and initializes the SQLite database.
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

$errors = [];
$success = false;

// 1. Check PHP Version
if (version_compare(PHP_VERSION, '8.0.0', '<')) {
    $errors[] = 'PHP version must be 8.0.0 or higher. Current version: ' . PHP_VERSION;
}

// 2. Check for pdo_sqlite
if (!extension_loaded('pdo_sqlite')) {
    $errors[] = 'The pdo_sqlite extension is not enabled in PHP.';
}

// 3. Check if directory is writable
$dir = __DIR__;
if (!is_writable($dir)) {
    $errors[] = 'The backend directory is not writable. Please change permissions so PHP can create the database file (e.g., chmod 777 or chown to webserver user).';
}

$db_file = $dir . DIRECTORY_SEPARATOR . 'chat_relay.sqlite';

if (empty($errors)) {
    try {
        $db = new PDO('sqlite:' . $db_file);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Create users table with aux_hash for duress authentication
        $db->exec("CREATE TABLE IF NOT EXISTS users (
            user_hash TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            aux_hash TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        // Upgrade older schema if users table exists but has no aux_hash
        try {
            $db->exec("ALTER TABLE users ADD COLUMN aux_hash TEXT DEFAULT NULL");
        } catch (PDOException $e) {
            // Column already exists, safe to ignore
        }

        // Create messages table
        $db->exec("CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id_hash TEXT NOT NULL,
            sender_id_hash TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        // Create blocked table for admin controls
        $db->exec("CREATE TABLE IF NOT EXISTS blocked (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_hash TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL, -- 'user' or 'room'
            reason TEXT,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        // Create indexes
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id_hash)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_blocked_target ON blocked(target_hash)");

        $success = true;
    } catch (PDOException $e) {
        $errors[] = 'Database initialization failed: ' . $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FChat Relay Setup</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            background-color: #1e293b;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%;
            border: 1px solid #334155;
        }
        h1 {
            font-size: 24px;
            margin-top: 0;
            margin-bottom: 24px;
            text-align: center;
            font-weight: 700;
            background: linear-gradient(135deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .status-card {
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            font-weight: 500;
        }
        .status-success {
            background-color: rgba(16, 185, 129, 0.15);
            border: 1px solid #10b981;
            color: #34d399;
        }
        .status-error {
            background-color: rgba(239, 68, 68, 0.15);
            border: 1px solid #ef4444;
            color: #f87171;
        }
        .details {
            font-size: 14px;
            line-height: 1.6;
            color: #94a3b8;
        }
        .details ul {
            margin: 10px 0 0 0;
            padding-left: 20px;
        }
        .details li {
            margin-bottom: 6px;
        }
        .footer {
            text-align: center;
            margin-top: 24px;
            font-size: 12px;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>FChat Relay Setup</h1>

        <?php if ($success): ?>
            <div class="status-card status-success">
                ✓ Setup completed successfully!
            </div>
            <div class="details">
                <p>The SQLite database <strong>chat_relay.sqlite</strong> has been created/verified and tables are ready.</p>
                <p>You can now proceed to use the FChat client and direct the API endpoint to this folder.</p>
            </div>
        <?php else: ?>
            <div class="status-card status-error">
                ✗ Setup failed!
            </div>
            <div class="details">
                <p>Please fix the following environment issues and refresh this page:</p>
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <div class="footer">
            FChat Decentralized Encryption Relay • PHP <?php echo htmlspecialchars(PHP_VERSION); ?>
        </div>
    </div>
</body>
</html>
