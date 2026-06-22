<?php
/**
 * FChat Relay API
 * Handles user registration, login, sending encrypted messages, fetching new encrypted messages,
 * CAPTCHA puzzles, and E2E delivery acknowledgments.
 */

// Enable CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Content-Type: application/json");

// Handle OPTIONS preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$db_file = __DIR__ . DIRECTORY_SEPARATOR . 'chat_relay.sqlite';
$captcha_salt = "fchat_relay_captcha_secure_salt_789";

// Verify database exists
if (!file_exists($db_file)) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Relay database not initialized. Please run setup_relay.php first.'
    ]);
    exit();
}

try {
    $db = new PDO('sqlite:' . $db_file);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Failed to connect to the database: ' . $e->getMessage()
    ]);
    exit();
}

// Parse request body and query parameters
$input = json_decode(file_get_contents('php://input'), true) ?? [];
$params = array_merge($_GET, $_POST, $input);

$action = $params['action'] ?? null;
$user_hash = $params['user_hash'] ?? null;
$password_hash = $params['password_hash'] ?? null;

if (!$action) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Action parameter is required.'
    ]);
    exit();
}

/**
 * Validates whether user credentials are correct (checks standard password or aux duress password).
 */
function authenticate($db, $user_hash, $password_hash) {
    if (!$user_hash || !$password_hash) {
        return false;
    }
    try {
        $stmt = $db->prepare("SELECT password_hash, aux_hash FROM users WHERE user_hash = :user_hash");
        $stmt->execute([':user_hash' => $user_hash]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) {
            // Check both standard password hash and duress (aux) password hash
            if ($user['password_hash'] === $password_hash) {
                return true;
            }
            if ($user['aux_hash'] !== null && $user['aux_hash'] === $password_hash) {
                return true;
            }
        }
    } catch (PDOException $e) {
        return false;
    }
    return false;
}

/**
 * Checks if a user hash is blocked.
 */
function is_user_blocked($db, $user_hash) {
    if (!$user_hash) return false;
    try {
        $stmt = $db->prepare("SELECT 1 FROM blocked WHERE target_hash = :user_hash AND type = 'user'");
        $stmt->execute([':user_hash' => $user_hash]);
        return (bool)$stmt->fetch();
    } catch (PDOException $e) {
        return false;
    }
}

/**
 * Checks if a room hash is blocked.
 */
function is_room_blocked($db, $room_id_hash) {
    if (!$room_id_hash) return false;
    try {
        $stmt = $db->prepare("SELECT 1 FROM blocked WHERE target_hash = :room_id_hash AND type = 'room'");
        $stmt->execute([':room_id_hash' => $room_id_hash]);
        return (bool)$stmt->fetch();
    } catch (PDOException $e) {
        return false;
    }
}

switch ($action) {
    case 'captcha':
        // Generate a stateless mathematical puzzle
        $num1 = rand(1, 15);
        $num2 = rand(1, 10);
        $op = rand(0, 1) ? '+' : '-';
        $question = "What is $num1 $op $num2?";
        $answer = ($op === '+') ? ($num1 + $num2) : ($num1 - $num2);

        // Compute captcha token (SHA-256 with salt)
        $token = hash('sha256', $answer . $captcha_salt);

        echo json_encode([
            'status' => 'success',
            'question' => $question,
            'token' => $token
        ]);
        break;

    case 'register':
        $aux_hash = $params['aux_hash'] ?? null;
        $captcha_answer = isset($params['captcha_answer']) ? trim($params['captcha_answer']) : '';
        $captcha_token = $params['captcha_token'] ?? '';

        if (!$user_hash || !$password_hash) {
            http_response_code(400);
            echo json_encode([
                'status' => 'error',
                'message' => 'user_hash and password_hash are required.'
            ]);
            break;
        }

        // Verify CAPTCHA
        if (hash('sha256', $captcha_answer . $captcha_salt) !== $captcha_token) {
            http_response_code(400);
            echo json_encode([
                'status' => 'error',
                'message' => 'CAPTCHA validation failed. Please try again.'
            ]);
            break;
        }

        // Check if user is blocked
        if (is_user_blocked($db, $user_hash)) {
            http_response_code(403);
            echo json_encode([
                'status' => 'error',
                'message' => 'This user hash is blocked on this relay.'
            ]);
            break;
        }

        // Check if user already exists
        $stmt = $db->prepare("SELECT 1 FROM users WHERE user_hash = :user_hash");
        $stmt->execute([':user_hash' => $user_hash]);
        if ($stmt->fetch()) {
            http_response_code(409); // Conflict
            echo json_encode([
                'status' => 'error',
                'message' => 'User already registered.'
            ]);
            break;
        }

        // Insert new user
        try {
            $stmt = $db->prepare("INSERT INTO users (user_hash, password_hash, aux_hash) VALUES (:user_hash, :password_hash, :aux_hash)");
            $stmt->execute([
                ':user_hash' => $user_hash,
                ':password_hash' => $password_hash,
                ':aux_hash' => $aux_hash
            ]);
            echo json_encode([
                'status' => 'success',
                'message' => 'Registration successful.'
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode([
                'status' => 'error',
                'message' => 'Failed to register user: ' . $e->getMessage()
            ]);
        }
        break;

    case 'login':
        if (is_user_blocked($db, $user_hash)) {
            http_response_code(403);
            echo json_encode([
                'status' => 'error',
                'message' => 'This user hash is blocked on this relay.'
            ]);
            break;
        }

        if (authenticate($db, $user_hash, $password_hash)) {
            echo json_encode([
                'status' => 'success',
                'message' => 'Login successful.'
            ]);
        } else {
            http_response_code(401);
            echo json_encode([
                'status' => 'error',
                'message' => 'Invalid credentials.'
            ]);
        }
        break;

    case 'send':
        if (!authenticate($db, $user_hash, $password_hash)) {
            http_response_code(401);
            echo json_encode([
                'status' => 'error',
                'message' => 'Authentication failed.'
            ]);
            break;
        }

        if (is_user_blocked($db, $user_hash)) {
            http_response_code(403);
            echo json_encode([
                'status' => 'error',
                'message' => 'This user hash is blocked on this relay.'
            ]);
            break;
        }

        $room_id = $params['room_id'] ?? null;
        $content = $params['content'] ?? null;

        if (!$room_id || $content === null) {
            http_response_code(400);
            echo json_encode([
                'status' => 'error',
                'message' => 'room_id and content are required.'
            ]);
            break;
        }

        $room_id_hash = hash('sha256', $room_id);

        if (is_room_blocked($db, $room_id_hash)) {
            http_response_code(403);
            echo json_encode([
                'status' => 'error',
                'message' => 'This chat room is blocked on this relay.'
            ]);
            break;
        }

        $sender_id_hash = hash('sha256', $user_hash);

        try {
            $stmt = $db->prepare("INSERT INTO messages (room_id_hash, sender_id_hash, encrypted_content) VALUES (:room_id_hash, :sender_id_hash, :encrypted_content)");
            $stmt->execute([
                ':room_id_hash' => $room_id_hash,
                ':sender_id_hash' => $sender_id_hash,
                ':encrypted_content' => $content
            ]);
            echo json_encode([
                'status' => 'success',
                'message' => 'Message relayed successfully.'
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode([
                'status' => 'error',
                'message' => 'Failed to store message: ' . $e->getMessage()
            ]);
        }
        break;

    case 'fetch':
        if (!authenticate($db, $user_hash, $password_hash)) {
            http_response_code(401);
            echo json_encode([
                'status' => 'error',
                'message' => 'Authentication failed.'
            ]);
            break;
        }

        if (is_user_blocked($db, $user_hash)) {
            http_response_code(403);
            echo json_encode([
                'status' => 'error',
                'message' => 'This user hash is blocked on this relay.'
            ]);
            break;
        }

        $room_id = $params['room_id'] ?? null;
        $since = $params['since'] ?? '1970-01-01 00:00:00';

        if (!$room_id) {
            http_response_code(400);
            echo json_encode([
                'status' => 'error',
                'message' => 'room_id is required.'
            ]);
            break;
        }

        $room_id_hash = hash('sha256', $room_id);

        if (is_room_blocked($db, $room_id_hash)) {
            http_response_code(403);
            echo json_encode([
                'status' => 'error',
                'message' => 'This chat room is blocked on this relay.'
            ]);
            break;
        }

        try {
            $stmt = $db->prepare("SELECT id, sender_id_hash, encrypted_content, created_at FROM messages WHERE room_id_hash = :room_id_hash AND created_at > :since ORDER BY created_at ASC");
            $stmt->execute([
                ':room_id_hash' => $room_id_hash,
                ':since' => $since
            ]);
            $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo json_encode([
                'status' => 'success',
                'data' => $messages
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode([
                'status' => 'error',
                'message' => 'Failed to retrieve messages: ' . $e->getMessage()
            ]);
        }
        break;

    case 'acknowledge':
        // Enforces client-initiated zero retention on fetched payloads
        if (!authenticate($db, $user_hash, $password_hash)) {
            http_response_code(401);
            echo json_encode([
                'status' => 'error',
                'message' => 'Authentication failed.'
            ]);
            break;
        }

        $message_ids = $params['message_ids'] ?? [];

        if (empty($message_ids) || !is_array($message_ids)) {
            echo json_encode([
                'status' => 'success',
                'message' => 'No messages to acknowledge.'
            ]);
            break;
        }

        try {
            // Delete acknowledged messages
            $placeholders = implode(',', array_fill(0, count($message_ids), '?'));
            $stmt = $db->prepare("DELETE FROM messages WHERE id IN ($placeholders)");
            $stmt->execute(array_map('intval', $message_ids));

            echo json_encode([
                'status' => 'success',
                'message' => 'Acknowledged messages successfully purged from relay database.'
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode([
                'status' => 'error',
                'message' => 'Failed to drop acknowledged messages: ' . $e->getMessage()
            ]);
        }
        break;

    default:
        http_response_code(400);
        echo json_encode([
            'status' => 'error',
            'message' => 'Unknown action: ' . $action
        ]);
        break;
}
