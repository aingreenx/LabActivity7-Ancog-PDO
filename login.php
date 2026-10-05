<?php
declare(strict_types=1);
require 'db.php';

// Guests only
if (!empty($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$errors = [];
$email = '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!csrf_valid($_POST['csrf'] ?? null)) {
        http_response_code(419);
        exit('Invalid or expired form token.');
    }
    $email    = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    if ((int) ($_SESSION['login_attempts'] ?? 0) >= MAX_LOGIN_ATTEMPTS) {
        $errors['form'] = 'Too many failed attempts. Please close your browser and try again later.';
    } else {
        if ($email === '' || strlen($email) > 255 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors['email'] = 'A valid email is required.';
        }
        if ($password === '') {
            $errors['password'] = 'Password is required.';
        }

        if (!$errors) {
            $stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE email = :email LIMIT 1');
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch();

            if ($user !== false && password_verify($password, $user['password_hash'])) {
                unset($_SESSION['login_attempts']);
                session_regenerate_id(true); // prevent session fixation
                $_SESSION['user_id'] = (int) $user['id'];
                header('Location: index.php');
                exit;
            }
            $_SESSION['login_attempts'] = (int) ($_SESSION['login_attempts'] ?? 0) + 1;
            $errors['form'] = 'Invalid email or password.'; // generic on purpose
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log in | <?= e(APP_NAME) ?></title>
<link rel="stylesheet" href="styles.css">
</head>
<body>
<header class="nav"><a class="brand" href="index.php"><?= e(APP_NAME) ?></a></header>
<main>
<div class="card">
    <h2>Log in</h2>
    <?php if (isset($errors['form'])): ?><p class="error"><?= e($errors['form']) ?></p><?php endif; ?>
    <form method="post" action="login.php">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">

        <label for="email">Email</label>
        <input id="email" type="email" name="email" required maxlength="255" value="<?= e($email) ?>">
        <?php if (isset($errors['email'])): ?><p class="error"><?= e($errors['email']) ?></p><?php endif; ?>

        <label for="password">Password</label>
        <input id="password" type="password" name="password" required autocomplete="current-password">
        <?php if (isset($errors['password'])): ?><p class="error"><?= e($errors['password']) ?></p><?php endif; ?>

        <button type="submit">Log in</button>
    </form>
    <p>No account yet? <a href="register.php">Register</a></p>
</div>
</main>
</body>
</html>
