<?php
/**
 * FChat Relay Cleanup Cron Job
 * Deletes messages older than 7 days and vacuums the database.
 * Supports running via CLI or via HTTP with a secret key.
 */

$db_file = __DIR__ . DIRECTORY_SEPARATOR . 'chat_relay.sqlite';

// Determine execution environment
$is_cli = (php_sapi_name() === 'cli');

if (!$is_cli) {
    // Web execution - check authorization secret key
    header("Content-Type: application/json");
    $secret = $_GET['secret'] ?? '';
    if ($secret !== 'supersecretcronkey123') {
        http_response_code(403);
        echo json_encode([
            'status' => 'error',
            'message' => '403 Forbidden - Invalid or missing secret query parameter.'
        ]);
        exit();
    }
}

if (!file_exists($db_file)) {
    $msg = 'Relay database does not exist. No cleanup required.';
    if ($is_cli) {
        echo $msg . PHP_EOL;
    } else {
        echo json_encode(['status' => 'info', 'message' => $msg]);
    }
    exit();
}

try {
    $db = new PDO('sqlite:' . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Delete messages older than 7 days
    // SQLite datetime functions: datetime('now', '-7 days')
    $stmt = $db->prepare("DELETE FROM messages WHERE created_at < datetime('now', '-7 days')");
    $stmt->execute();
    $deleted_count = $stmt->rowCount();

    // Optimize database file size
    $db->exec("VACUUM");

    $success_message = "Cleaned up $deleted_count old messages and optimized the database successfully.";

    if ($is_cli) {
        echo "[SUCCESS] " . $success_message . PHP_EOL;
    } else {
        echo json_encode([
            'status' => 'success',
            'message' => $success_message,
            'deleted_messages' => $deleted_count
        ]);
    }

} catch (PDOException $e) {
    $error_message = 'Database cleanup failed: ' . $e->getMessage();
    if ($is_cli) {
        echo "[ERROR] " . $error_message . PHP_EOL;
        exit(1);
    } else {
        http_response_code(500);
        echo json_encode([
            'status' => 'error',
            'message' => $error_message
        ]);
    }
}
