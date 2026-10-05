<?php
declare(strict_types=1);
require 'db.php';

// Guests only
if (!empty($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$errors = [];
$name = '';
$email = '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!csrf_valid($_POST['csrf'] ?? null)) {
        http_response_code(419);
        exit('Invalid or expired form token.');
    }
    $name     = trim((string) ($_POST['name'] ?? ''));
    $email    = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $confirm  = (string) ($_POST['confirm'] ?? '');

    if (mb_strlen($name) < 2 || mb_strlen($name) > 50) {
        $errors['name'] = 'Name must be 2-50 characters.';
    }
    if ($email === '' || strlen($email) > 255 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        $errors['email'] = 'A valid email (max 255 characters) is required.';
    }
    if (strlen($password) < 8 || strlen($password) > 72) {
        $errors['password'] = 'Password must be 8-72 characters.';
    } elseif (!hash_equals($password, $confirm)) {
        $errors['confirm'] = 'Passwords do not match.';
    }

    if (!$errors) {
        $stmt = $pdo->prepare('SELECT 1 FROM users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $email]);
        if ($stmt->fetchColumn() !== false) {
            $errors['email'] = 'That email is already registered.';
        }
    }

    if (!$errors) {
        try {
            $stmt = $pdo->prepare('INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :hash)');
            $stmt->execute([':name' => $name, ':email' => $email, ':hash' => password_hash($password, PASSWORD_DEFAULT)]);
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int) $pdo->lastInsertId();
            header('Location: index.php');
            exit;
        } catch (PDOException $ex) {
            if ($ex->getCode() !== '23000') { // duplicate email race condition
                throw $ex;
            }
            $errors['email'] = 'That email is already registered.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Register | <?= e(APP_NAME) ?></title>
<link rel="stylesheet" href="styles.css">
</head>
<body>
<header class="nav"><a class="brand" href="index.php"><?= e(APP_NAME) ?></a></header>
<main>
<div class="card">
    <h2>Create an account</h2>
    <form method="post" action="register.php" id="register-form">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">

        <label for="name">Name</label>
        <input id="name" name="name" required minlength="2" maxlength="50" value="<?= e($name) ?>">
        <?php if (isset($errors['name'])): ?><p class="error"><?= e($errors['name']) ?></p><?php endif; ?>

        <label for="email">Email</label>
        <input id="email" type="email" name="email" required maxlength="255" value="<?= e($email) ?>">
        <?php if (isset($errors['email'])): ?><p class="error"><?= e($errors['email']) ?></p><?php endif; ?>

        <label for="password">Password (min 8 characters)</label>
        <input id="password" type="password" name="password" required minlength="8" maxlength="72" autocomplete="new-password">
        <?php if (isset($errors['password'])): ?><p class="error"><?= e($errors['password']) ?></p><?php endif; ?>

        <label for="confirm">Confirm password</label>
        <input id="confirm" type="password" name="confirm" required minlength="8" maxlength="72" autocomplete="new-password">
        <?php if (isset($errors['confirm'])): ?><p class="error"><?= e($errors['confirm']) ?></p><?php endif; ?>

        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="login.php">Log in</a></p>
</div>
</main>
<script>
document.getElementById('register-form').addEventListener('submit', function (ev) {
    if (this.password.value !== this.confirm.value) {
        ev.preventDefault();
        alert('Passwords do not match.');
    }
});
</script>
</body>
</html>
