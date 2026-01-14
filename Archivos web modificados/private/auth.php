<?php
require_once dirname(__FILE__) . '/conf.php';

if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit('Forbidden');
}

$cookieParams = session_get_cookie_params();
$secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => $cookieParams['path'],
        'domain' => $cookieParams['domain'],
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

$login_ok = false;
$error = '';
$userId = null;

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_SECONDS = 300;
const SESSION_TIMEOUT = 900;

function fetchUserByUsername($db, $username) {
    $stmt = $db->prepare('SELECT userId, username, password FROM users WHERE username = :username');
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $result = $stmt->execute();
    if ($result === false) {
        return null;
    }

    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row ?: null;
}

function verifyPasswordValue($password, $storedHash) {
    $info = password_get_info($storedHash);
    if (!empty($info['algo'])) {
        return password_verify($password, $storedHash);
    }

    return hash_equals($storedHash, $password);
}

function upgradePasswordIfNeeded($db, $userId, $password, $storedHash) {
    $info = password_get_info($storedHash);
    if (!empty($info['algo'])) {
        return;
    }

    $newHash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare('UPDATE users SET password = :password WHERE userId = :userId');
    $stmt->bindValue(':password', $newHash, SQLITE3_TEXT);
    $stmt->bindValue(':userId', $userId, SQLITE3_INTEGER);
    $stmt->execute();
}

function destroySession() {
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }

    session_destroy();
}

function isLoginLockedOut() {
    $attempts = $_SESSION['login_attempts'] ?? 0;
    if ($attempts < MAX_LOGIN_ATTEMPTS) {
        return false;
    }

    $lastAttempt = $_SESSION['login_last_attempt'] ?? 0;
    return (time() - $lastAttempt) < LOCKOUT_SECONDS;
}

function recordFailedLogin() {
    $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;
    $_SESSION['login_last_attempt'] = time();
}

function resetLoginAttempts() {
    unset($_SESSION['login_attempts'], $_SESSION['login_last_attempt']);
}

$sessionExpired = false;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
    destroySession();
    $sessionExpired = true;
}

# On logout
if (isset($_POST['Logout'])) {
    destroySession();
    header("Location: index.php");
    exit;
}

# Check user and password
if (isset($_SESSION['userId'])) {
    $login_ok = true;
    $userId = $_SESSION['userId'];
} elseif (isset($_POST['username']) && isset($_POST['password'])) {
    if (isLoginLockedOut()) {
        $login_ok = false;
        $error = 'Too many login attempts. Try again later.';
    } else {
        $username = trim($_POST['username']);
        $password = $_POST['password'];

        if ($username === '' || $password === '') {
            $login_ok = false;
            $error = 'Username and password are required.';
        } else {
            $row = fetchUserByUsername($db, $username);
            if ($row && verifyPasswordValue($password, $row['password'])) {
                session_regenerate_id(true);
                $_SESSION['userId'] = $row['userId'];
                $_SESSION['user'] = $row['username'];
                $userId = $row['userId'];
                upgradePasswordIfNeeded($db, $row['userId'], $password, $row['password']);
                resetLoginAttempts();
                $login_ok = true;
                $error = '';
            } else {
                recordFailedLogin();
                $login_ok = false;
                $error = 'Invalid user or password.';
            }
        }
    }
} else {
    $login_ok = false;
    $error = 'This page requires you to be logged in.';
}

if ($login_ok === true) {
    $_SESSION['last_activity'] = time();
}

if ($sessionExpired) {
    $login_ok = false;
    $error = 'Session expired. Please log in again.';
}

if ($login_ok == false) {
?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Practica RA3 - Authentication page</title>
    </head>
    <body>
    <header class="auth">
        <h1>Authentication page</h1>
    </header>
    <section class="auth">
        <div class="message">
            <?php if ($error !== '') { echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); } ?>
        </div>
        <section>
            <div>
                <h2>Login</h2>
                <form action="#" method="post">
                    <label>User</label>
                    <input type="text" name="username"><br>
                    <label>Password</label>
                    <input type="password" name="password"><br>
                    <input type="submit" value="Login">
                </form>
            </div>

            <div>
                <h2>Logout</h2>
                <form action="#" method="post">
                    <input type="submit" name="Logout" value="Logout">
                </form>
            </div>
        </section>
    </section>
    <footer>
        <h4>Puesta en produccion segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
    <?php
    exit(0);
}

?>
