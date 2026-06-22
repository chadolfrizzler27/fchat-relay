<?php
/**
 * FChat Admin Panel
 * Allows blocking user hashes and room IDs, which also purges related database entries.
 * Features CSRF protection for all administrative actions.
 */

session_start();

// Configure admin password here.
define('ADMIN_PASSWORD', 'supersecureadminpassword123');

$db_file = __DIR__ . DIRECTORY_SEPARATOR . 'chat_relay.sqlite';

// Generate CSRF token if not present
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle Logout
if (isset($_GET['logout'])) {
    unset($_SESSION['admin_logged_in']);
    session_destroy();
    header("Location: admin.php");
    exit();
}

// Handle Login POST
$login_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_password'])) {
    // Note: No CSRF validation on login because session is initialized/cleared
    if ($_POST['login_password'] === ADMIN_PASSWORD) {
        $_SESSION['admin_logged_in'] = true;
        // Regenerate CSRF token on login for session security
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header("Location: admin.php");
        exit();
    } else {
        $login_error = 'Incorrect admin password.';
    }
}

// Authenticate session
$is_logged_in = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;

// DB connection
$db = null;
if ($is_logged_in) {
    if (!file_exists($db_file)) {
        die("Database not initialized. Please run setup_relay.php first.");
    }
    try {
        $db = new PDO('sqlite:' . $db_file);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e) {
        die("Connection to database failed: " . $e->getMessage());
    }

    // Handle Adding a Block
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'block') {
        // Validate CSRF token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            die("CSRF validation failed.");
        }

        $target_input = trim($_POST['target'] ?? '');
        $type = $_POST['type'] ?? 'user';
        $reason = trim($_POST['reason'] ?? '');

        if (!empty($target_input)) {
            $target_hash = $target_input;
            if ($type === 'room_raw') {
                // Hash raw Room ID to SHA-256 hex
                $target_hash = hash('sha256', $target_input);
                $type = 'room';
            }

            try {
                // Insert into blocked table
                $stmt = $db->prepare("INSERT OR REPLACE INTO blocked (target_hash, type, reason) VALUES (:target_hash, :type, :reason)");
                $stmt->execute([
                    ':target_hash' => $target_hash,
                    ':type' => $type,
                    ':reason' => $reason
                ]);

                // PURGE DATA ASSOCIATED WITH THE BLOCK
                if ($type === 'user') {
                    // 1. Delete user from users table
                    $stmt = $db->prepare("DELETE FROM users WHERE user_hash = :user_hash");
                    $stmt->execute([':user_hash' => $target_hash]);

                    // 2. Delete messages sent by this user (sender_id_hash is the SHA-256 of user_hash)
                    $sender_id_hash = hash('sha256', $target_hash);
                    $stmt = $db->prepare("DELETE FROM messages WHERE sender_id_hash = :sender_id_hash");
                    $stmt->execute([':sender_id_hash' => $sender_id_hash]);
                } elseif ($type === 'room') {
                    // Delete all messages in the room
                    $stmt = $db->prepare("DELETE FROM messages WHERE room_id_hash = :room_id_hash");
                    $stmt->execute([':room_id_hash' => $target_hash]);
                }

                $_SESSION['flash_message'] = "Target successfully blocked and related data purged.";
            } catch (PDOException $e) {
                $_SESSION['flash_error'] = "Failed to block: " . $e->getMessage();
            }
        } else {
            $_SESSION['flash_error'] = "Target value cannot be empty.";
        }
        header("Location: admin.php");
        exit();
    }

    // Handle Unblocking
    if (isset($_GET['unblock_id'])) {
        // Validate CSRF token
        if (!isset($_GET['csrf_token']) || $_GET['csrf_token'] !== $_SESSION['csrf_token']) {
            die("CSRF validation failed.");
        }

        $unblock_id = (int)$_GET['unblock_id'];
        try {
            $stmt = $db->prepare("DELETE FROM blocked WHERE id = :id");
            $stmt->execute([':id' => $unblock_id]);
            $_SESSION['flash_message'] = "Target unblocked successfully.";
        } catch (PDOException $e) {
            $_SESSION['flash_error'] = "Failed to unblock: " . $e->getMessage();
        }
        header("Location: admin.php");
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FChat Admin Console</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 40px auto;
            background-color: #1e293b;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            border: 1px solid #334155;
        }
        h1, h2 {
            margin-top: 0;
            font-weight: 700;
        }
        h1 {
            font-size: 28px;
            background: linear-gradient(135deg, #f43f5e, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: inline-block;
        }
        .header-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #334155;
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        .btn {
            display: inline-block;
            background-color: #38bdf8;
            color: #0f172a;
            border: none;
            padding: 10px 18px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: opacity 0.2s;
        }
        .btn:hover {
            opacity: 0.9;
        }
        .btn-danger {
            background-color: #ef4444;
            color: #ffffff;
        }
        .btn-secondary {
            background-color: #475569;
            color: #f8fafc;
        }
        .form-group {
            margin-bottom: 16px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            font-size: 14px;
            color: #94a3b8;
        }
        input[type="text"], input[type="password"], select, textarea {
            width: 100%;
            padding: 10px;
            border-radius: 6px;
            border: 1px solid #475569;
            background-color: #0f172a;
            color: #f8fafc;
            box-sizing: border-box;
            font-size: 14px;
        }
        input:focus, select:focus, textarea:focus {
            outline: 2px solid #38bdf8;
        }
        .alert {
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .alert-success {
            background-color: rgba(16, 185, 129, 0.15);
            border: 1px solid #10b981;
            color: #34d399;
        }
        .alert-danger {
            background-color: rgba(239, 68, 68, 0.15);
            border: 1px solid #ef4444;
            color: #f87171;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 14px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #334155;
        }
        th {
            background-color: #0f172a;
            color: #94a3b8;
            font-weight: 600;
        }
        tr:hover {
            background-color: #2b3a53;
        }
        .login-box {
            max-width: 400px;
            margin: 100px auto;
            background-color: #1e293b;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            border: 1px solid #334155;
            text-align: center;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-user {
            background-color: #3b82f6;
            color: #ffffff;
        }
        .badge-room {
            background-color: #a855f7;
            color: #ffffff;
        }
    </style>
</head>
<body>

<?php if (!$is_logged_in): ?>
    <div class="login-box">
        <h1 style="margin-bottom: 24px;">FChat Admin Access</h1>
        <?php if ($login_error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($login_error); ?></div>
        <?php endif; ?>
        <form method="POST" action="admin.php">
            <div class="form-group" style="text-align: left;">
                <label for="login_password">Admin Password</label>
                <input type="password" id="login_password" name="login_password" required>
            </div>
            <button type="submit" class="btn btn-danger" style="width: 100%; margin-top: 12px;">Authenticate</button>
        </form>
    </div>
<?php else: ?>
    <div class="container">
        <div class="header-bar">
            <div>
                <h1>FChat Admin Console</h1>
                <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 14px;">Moderate relays, block abuses, and purge database assets</p>
            </div>
            <a href="admin.php?logout=1" class="btn btn-secondary">Logout</a>
        </div>

        <?php
        if (isset($_SESSION['flash_message'])) {
            echo '<div class="alert alert-success">' . htmlspecialchars($_SESSION['flash_message']) . '</div>';
            unset($_SESSION['flash_message']);
        }
        if (isset($_SESSION['flash_error'])) {
            echo '<div class="alert alert-danger">' . htmlspecialchars($_SESSION['flash_error']) . '</div>';
            unset($_SESSION['flash_error']);
        }
        ?>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 32px; margin-bottom: 40px;">
            <div>
                <h2>Create Block & Purge</h2>
                <p style="color: #94a3b8; font-size: 13px; margin-top: -8px; margin-bottom: 20px;">
                    Blocking a target immediately deletes its database representation and all related messages from storage.
                </p>
                <form method="POST" action="admin.php">
                    <input type="hidden" name="action" value="block">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    
                    <div class="form-group">
                        <label for="type">Block Type</label>
                        <select id="type" name="type">
                            <option value="user">User Hash (Full account revocation)</option>
                            <option value="room_raw">Room ID (Raw name - will be SHA-256 hashed)</option>
                            <option value="room">Room ID Hash (Raw SHA-256 hex string)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="target">Target Value (Hash or Raw Name)</label>
                        <input type="text" id="target" name="target" placeholder="e.g. 5d41402abc4b2a76b9719d911017c592" required>
                    </div>
                    <div class="form-group">
                        <label for="reason">Reason for Block</label>
                        <textarea id="reason" name="reason" rows="3" placeholder="Explain the reason for policing or removing this entity..."></textarea>
                    </div>
                    <button type="submit" class="btn btn-danger">Apply Block & Delete Data</button>
                </form>
            </div>

            <div>
                <h2>Relay Status</h2>
                <div style="background-color: #0f172a; border-radius: 8px; padding: 20px; border: 1px solid #334155;">
                    <?php
                    // Fetch server counts
                    try {
                        $users_count = $db->query("SELECT COUNT(*) FROM users")->fetchColumn();
                        $messages_count = $db->query("SELECT COUNT(*) FROM messages")->fetchColumn();
                        $blocks_count = $db->query("SELECT COUNT(*) FROM blocked")->fetchColumn();
                    } catch (PDOException $e) {
                        $users_count = $messages_count = $blocks_count = 'Error';
                    }
                    ?>
                    <table style="margin-top: 0; width: 100%;">
                        <tr>
                            <td style="color: #94a3b8; border: none; padding-left: 0;">Registered Accounts</td>
                            <td style="text-align: right; font-weight: 700; border: none; padding-right: 0;"><?php echo htmlspecialchars($users_count); ?></td>
                        </tr>
                        <tr>
                            <td style="color: #94a3b8; padding-left: 0;">Relayed Messages (Active)</td>
                            <td style="text-align: right; font-weight: 700; padding-right: 0;"><?php echo htmlspecialchars($messages_count); ?></td>
                        </tr>
                        <tr>
                            <td style="color: #94a3b8; padding-left: 0;">Active Block Rules</td>
                            <td style="text-align: right; font-weight: 700; padding-right: 0;"><?php echo htmlspecialchars($blocks_count); ?></td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <h2>Active Block List</h2>
        <div style="overflow-x: auto; background-color: #0f172a; border-radius: 8px; border: 1px solid #334155;">
            <?php
            try {
                $stmt = $db->query("SELECT * FROM blocked ORDER BY blocked_at DESC");
                $blocks = $stmt->fetchAll(PDO::FETCH_ASSOC);
            } catch (PDOException $e) {
                $blocks = [];
            }
            ?>
            <?php if (empty($blocks)): ?>
                <p style="padding: 20px; text-align: center; color: #64748b; margin: 0;">No active blocks on this relay.</p>
            <?php else: ?>
                <table style="margin: 0;">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Blocked Target Hash</th>
                            <th>Reason</th>
                            <th>Blocked At</th>
                            <th style="text-align: right;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($blocks as $block): ?>
                            <tr>
                                <td>
                                    <span class="badge badge-<?php echo htmlspecialchars($block['type']); ?>">
                                        <?php echo htmlspecialchars($block['type']); ?>
                                    </span>
                                </td>
                                <td style="font-family: monospace; font-size: 12px; color: #cbd5e1; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                                    <?php echo htmlspecialchars($block['target_hash']); ?>
                                </td>
                                <td><?php echo htmlspecialchars($block['reason'] ?: 'None provided'); ?></td>
                                <td style="color: #94a3b8; font-size: 12px;"><?php echo htmlspecialchars($block['blocked_at']); ?></td>
                                <td style="text-align: right;">
                                    <a href="admin.php?unblock_id=<?php echo $block['id']; ?>&csrf_token=<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>" class="btn btn-secondary" style="padding: 4px 8px; font-size: 12px;">Unblock</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

</body>
</html>
