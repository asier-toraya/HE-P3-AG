<?php
session_start();

# On logout
if (isset($_POST['Logout'])) {
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }

    session_destroy();

    # Delete legacy cookies
    setcookie('user', FALSE);
    setcookie('password', FALSE);
    setcookie('userId', FALSE);
    unset($_COOKIE['user']);
    unset($_COOKIE['password']);
    unset($_COOKIE['userId']);

    header("Location: index.php");
    exit;
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
    <title>Practica RA3</title>
</head>
<body>
    <header>
        <h1>Developers Awards</h1>
    </header>
    <main>
        <h2><a href="insert_player.php"> Add a new player</a></h2>
        <h2><a href="list_players.php"> List of players</a></h2>
        <h2><a href="buscador.html"> Search a player</a></h2>

    </main>
    <form action="#" method="post" class="menu-form">
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
    <footer>
        <h4>Puesta en produccion segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
</body>
</html>
