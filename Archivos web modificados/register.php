<?php
require_once dirname(__FILE__) . '/private/conf.php';
# Require logged users
require dirname(__FILE__) . '/private/auth.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$errors = [];
$username = '';

// Registration is disabled by default. Add allowed usernames or set to true.
$registrationEnabled = false;
$allowedUsers = [];
$currentUser = $_SESSION['user'] ?? '';
$registrationLocked = !$registrationEnabled && !in_array($currentUser, $allowedUsers, true);

if ($registrationLocked) {
    http_response_code(403);
    $errors[] = 'Registration is disabled for this account.';
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
}
$csrfToken = $_SESSION['csrf_token'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$registrationLocked) {
    $postedToken = $_POST['csrf_token'] ?? '';
    if (!hash_equals($csrfToken, $postedToken)) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($username === '' || $password === '') {
            $errors[] = 'Username and password are required.';
        }
        if ($username !== '' && (strlen($username) < 3 || strlen($username) > 32)) {
            $errors[] = 'Username must be between 3 and 32 characters.';
        }
        if ($username !== '' && !preg_match('/^[A-Za-z0-9_]+$/', $username)) {
            $errors[] = 'Username must be alphanumeric.';
        }
        if ($password !== '' && strlen($password) < 8) {
            $errors[] = 'Password must be at least 8 characters.';
        }

        if (empty($errors)) {
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $db->prepare('INSERT INTO users (username, password) VALUES (:username, :password)');
            $stmt->bindValue(':username', $username, SQLITE3_TEXT);
            $stmt->bindValue(':password', $passwordHash, SQLITE3_TEXT);
            $result = $stmt->execute();

            if ($result === false) {
                $errors[] = 'User already exists or invalid data.';
            } else {
                header("Location: list_players.php");
                exit;
            }
        }
    }
}
?>
<!doctype html>
<html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Practica RA3 - Players list</title>
    </head>
    <body>
        <header>
            <h1>Register</h1>
        </header>
        <main class="player">
            <?php if (!empty($errors)) { ?>
                <div class="message">
                    <?php
                    $escapedErrors = array_map(function ($error) {
                        return htmlspecialchars($error, ENT_QUOTES, 'UTF-8');
                    }, $errors);
                    echo implode("<br>", $escapedErrors);
                    ?>
                </div>
            <?php } ?>
            <?php if (!$registrationLocked) { ?>
                <form action="#" method="post">
                    <label>Username:</label>
                    <input type="text" name="username" value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
                    <label>Password:</label>
                    <input type="password" name="password">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="submit" value="Send">
                </form>
            <?php } ?>
            <form action="#" method="post" class="menu-form">
                <a href="list_players.php">Back to list</a>
                <input type="submit" name="Logout" value="Logout" class="logout">
            </form>
        </main>
        <footer class="listado">
            <img src="images/logo-iesra-cadiz-color-blanco.png">
            <h4>Puesta en produccion segura</h4>
            < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
        </footer>
    </body>
</html>
