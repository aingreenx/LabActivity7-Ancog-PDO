<?php
declare(strict_types=1);
require 'db.php';

const TITLE_MAX = 150;
const POST_MAX = 5000;
const COMMENT_MAX = 1000;

/** Properly destroy the session: empty array, expire cookie, destroy storage. */
function logout_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly' => $p['httponly'],
            'samesite' => $p['samesite'] ?: 'Lax',
        ]);
    }
    session_destroy();
}

function positive_int(mixed $value): int
{
    $n = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    return $n === false ? 0 : $n;
}

function text_error(string $label, string $value, int $min, int $max): ?string
{
    $len = mb_strlen($value);
    return ($len < $min || $len > $max) ? "$label must be $min-$max characters." : null;
}

// ---- Authenticated page: redirect guests ----
if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}
$userId = (int) $_SESSION['user_id'];

$stmt = $pdo->prepare('SELECT id, name FROM users WHERE id = :id LIMIT 1');
$stmt->execute([':id' => $userId]);
$currentUser = $stmt->fetch();
if ($currentUser === false) { // account no longer exists
    logout_session();
    header('Location: login.php');
    exit;
}

$errors = [];          // keyed by form, e.g. 'add_post', 'edit_post_5', 'add_comment_5', 'edit_comment_9'
$old = [];             // re-fill values after a failed validation
$editPostId = positive_int($_GET['edit_post'] ?? 0);
$editCommentId = positive_int($_GET['edit_comment'] ?? 0);

// ---- Unified controller: all POST actions ----
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!csrf_valid($_POST['csrf'] ?? null)) {
        http_response_code(419);
        exit('Invalid or expired form token.');
    }

    $action    = (string) ($_POST['action'] ?? '');
    $title     = trim((string) ($_POST['title'] ?? ''));
    $content   = trim((string) ($_POST['content'] ?? ''));
    $postId    = positive_int($_POST['post_id'] ?? 0);
    $commentId = positive_int($_POST['comment_id'] ?? 0);

    switch ($action) {
        case 'logout':
            logout_session();
            header('Location: login.php');
            exit;

        case 'add_post':
            $old['add_post'] = ['title' => $title, 'content' => $content];
            if ($m = text_error('Title', $title, 1, TITLE_MAX)) { $errors['add_post']['title'] = $m; }
            if ($m = text_error('Content', $content, 1, POST_MAX)) { $errors['add_post']['content'] = $m; }
            if (!$errors) {
                $stmt = $pdo->prepare('INSERT INTO posts (user_id, title, content) VALUES (:u, :t, :c)');
                $stmt->execute([':u' => $userId, ':t' => $title, ':c' => $content]);
                header('Location: index.php');
                exit;
            }
            break;

        case 'edit_post':
            $key = 'edit_post_' . $postId;
            $old[$key] = ['title' => $title, 'content' => $content];
            if ($postId === 0) { http_response_code(400); exit('Bad request.'); }
            if ($m = text_error('Title', $title, 1, TITLE_MAX)) { $errors[$key]['title'] = $m; }
            if ($m = text_error('Content', $content, 1, POST_MAX)) { $errors[$key]['content'] = $m; }
            if (!$errors) {
                // Owner-only; updated_at is only stamped when the text really changed.
                $stmt = $pdo->prepare(
                    'UPDATE posts SET title = :t, content = :c, updated_at = CURRENT_TIMESTAMP
                      WHERE id = :id AND user_id = :u
                        AND (BINARY title <> BINARY :t2 OR BINARY content <> BINARY :c2)'
                );
                $stmt->execute([':t' => $title, ':c' => $content, ':id' => $postId, ':u' => $userId,
                                ':t2' => $title, ':c2' => $content]);
                header('Location: index.php#post-' . $postId);
                exit;
            }
            $editPostId = $postId;
            break;

        case 'delete_post':
            if ($postId === 0) { http_response_code(400); exit('Bad request.'); }
            // Owner-only delete (comments are removed via ON DELETE CASCADE)
            $stmt = $pdo->prepare('DELETE FROM posts WHERE id = :id AND user_id = :u');
            $stmt->execute([':id' => $postId, ':u' => $userId]);
            header('Location: index.php');
            exit;

        case 'add_comment':
            $key = 'add_comment_' . $postId;
            $old[$key] = ['content' => $content];
            $stmt = $pdo->prepare('SELECT 1 FROM posts WHERE id = :id LIMIT 1');
            $stmt->execute([':id' => $postId]);
            if ($postId === 0 || $stmt->fetchColumn() === false) { http_response_code(404); exit('Post not found.'); }
            if ($m = text_error('Comment', $content, 1, COMMENT_MAX)) { $errors[$key]['content'] = $m; }
            if (!$errors) {
                $stmt = $pdo->prepare('INSERT INTO comments (post_id, user_id, content) VALUES (:p, :u, :c)');
                $stmt->execute([':p' => $postId, ':u' => $userId, ':c' => $content]);
                header('Location: index.php#post-' . $postId);
                exit;
            }
            break;

        case 'edit_comment':
            $key = 'edit_comment_' . $commentId;
            $old[$key] = ['content' => $content];
            if ($commentId === 0) { http_response_code(400); exit('Bad request.'); }
            if ($m = text_error('Comment', $content, 1, COMMENT_MAX)) { $errors[$key]['content'] = $m; }
            if (!$errors) {
                $stmt = $pdo->prepare(
                    'UPDATE comments SET content = :c, updated_at = CURRENT_TIMESTAMP
                      WHERE id = :id AND user_id = :u AND BINARY content <> BINARY :c2'
                );
                $stmt->execute([':c' => $content, ':id' => $commentId, ':u' => $userId, ':c2' => $content]);
                header('Location: index.php');
                exit;
            }
            $editCommentId = $commentId;
            break;

        case 'delete_comment':
            if ($commentId === 0) { http_response_code(400); exit('Bad request.'); }
            $stmt = $pdo->prepare('DELETE FROM comments WHERE id = :id AND user_id = :u');
            $stmt->execute([':id' => $commentId, ':u' => $userId]);
            header('Location: index.php');
            exit;

        default:
            http_response_code(400);
            exit('Unknown action.');
    }
}

// ---- Load the feed: newest first, comments in a single IN query (no N+1) ----
$feed = $pdo->query(
    'SELECT p.id, p.user_id, p.title, p.content, p.created_at, p.updated_at, u.name AS author
       FROM posts p JOIN users u ON u.id = p.user_id
      ORDER BY p.created_at DESC, p.id DESC'
)->fetchAll();

$commentsByPost = [];
if ($feed) {
    $ids = array_map(static fn(array $p): int => (int) $p['id'], $feed);
    $stmt = $pdo->prepare(
        'SELECT c.id, c.post_id, c.user_id, c.content, c.created_at, c.updated_at, u.name AS author
           FROM comments c JOIN users u ON u.id = c.user_id
          WHERE c.post_id IN (' . implode(',', array_fill(0, count($ids), '?')) . ')
          ORDER BY c.created_at ASC, c.id ASC'
    );
    $stmt->execute($ids);
    foreach ($stmt->fetchAll() as $row) {
        $commentsByPost[(int) $row['post_id']][] = $row;
    }
}
$csrf = csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>News Feed | <?= e(APP_NAME) ?></title>
<link rel="stylesheet" href="styles.css">
</head>
<body>
<header class="nav">
    <a class="brand" href="index.php"><?= e(APP_NAME) ?></a>
    <form method="post" action="index.php" class="inline">
        <span>Hi, <?= e($currentUser['name']) ?></span>
        <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
        <input type="hidden" name="action" value="logout">
        <button type="submit" class="link">Log out</button>
    </form>
</header>
<main>

<div class="card">
    <h2>New post</h2>
    <form method="post" action="index.php">
        <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
        <input type="hidden" name="action" value="add_post">
        <label for="title">Title</label>
        <input id="title" name="title" required maxlength="<?= TITLE_MAX ?>" value="<?= e($old['add_post']['title'] ?? '') ?>">
        <?php if (isset($errors['add_post']['title'])): ?><p class="error"><?= e($errors['add_post']['title']) ?></p><?php endif; ?>
        <label for="content">What's on your mind?</label>
        <textarea id="content" name="content" rows="4" required maxlength="<?= POST_MAX ?>"><?= e($old['add_post']['content'] ?? '') ?></textarea>
        <?php if (isset($errors['add_post']['content'])): ?><p class="error"><?= e($errors['add_post']['content']) ?></p><?php endif; ?>
        <button type="submit">Publish</button>
    </form>
</div>

<?php if (!$feed): ?><p>No posts yet. Be the first!</p><?php endif; ?>

<?php foreach ($feed as $post):
    $pid = (int) $post['id'];
    $ownsPost = (int) $post['user_id'] === $userId;
    $editKey = 'edit_post_' . $pid;
?>
<article class="card" id="post-<?= $pid ?>">
<?php if ($ownsPost && $editPostId === $pid): ?>
    <form method="post" action="index.php#post-<?= $pid ?>">
        <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
        <input type="hidden" name="action" value="edit_post">
        <input type="hidden" name="post_id" value="<?= $pid ?>">
        <label for="et-<?= $pid ?>">Title</label>
        <input id="et-<?= $pid ?>" name="title" required maxlength="<?= TITLE_MAX ?>" value="<?= e($old[$editKey]['title'] ?? $post['title']) ?>">
        <?php if (isset($errors[$editKey]['title'])): ?><p class="error"><?= e($errors[$editKey]['title']) ?></p><?php endif; ?>
        <label for="ec-<?= $pid ?>">Content</label>
        <textarea id="ec-<?= $pid ?>" name="content" rows="5" required maxlength="<?= POST_MAX ?>"><?= e($old[$editKey]['content'] ?? $post['content']) ?></textarea>
        <?php if (isset($errors[$editKey]['content'])): ?><p class="error"><?= e($errors[$editKey]['content']) ?></p><?php endif; ?>
        <button type="submit">Save changes</button> <a href="index.php#post-<?= $pid ?>">Cancel</a>
    </form>
<?php else: ?>
    <h3><?= e($post['title']) ?>
        <?php if ($post['updated_at'] !== null): ?><span class="tag" title="Edited <?= e($post['updated_at']) ?>">(Edited)</span><?php endif; ?>
    </h3>
    <p class="meta">by <?= e($post['author']) ?> &middot; <?= e($post['created_at']) ?>
        <?php if ($ownsPost): ?>
            &middot; <a href="index.php?edit_post=<?= $pid ?>#post-<?= $pid ?>">Edit</a>
            <form method="post" action="index.php" class="inline" onsubmit="return confirm('Delete this post and all its comments?');">
                <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
                <input type="hidden" name="action" value="delete_post">
                <input type="hidden" name="post_id" value="<?= $pid ?>">
                <button type="submit" class="link danger">Delete</button>
            </form>
        <?php endif; ?>
    </p>
    <p class="content"><?= e($post['content']) ?></p>
<?php endif; ?>

    <h4>Comments</h4>
    <?php foreach ($commentsByPost[$pid] ?? [] as $c):
        $cid = (int) $c['id'];
        $ownsComment = (int) $c['user_id'] === $userId;
        $cKey = 'edit_comment_' . $cid;
    ?>
    <div class="comment">
    <?php if ($ownsComment && $editCommentId === $cid): ?>
        <form method="post" action="index.php#post-<?= $pid ?>">
            <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
            <input type="hidden" name="action" value="edit_comment">
            <input type="hidden" name="comment_id" value="<?= $cid ?>">
            <textarea name="content" rows="2" required maxlength="<?= COMMENT_MAX ?>" aria-label="Edit comment"><?= e($old[$cKey]['content'] ?? $c['content']) ?></textarea>
            <?php if (isset($errors[$cKey]['content'])): ?><p class="error"><?= e($errors[$cKey]['content']) ?></p><?php endif; ?>
            <button type="submit">Save</button> <a href="index.php#post-<?= $pid ?>">Cancel</a>
        </form>
    <?php else: ?>
        <span class="meta"><strong><?= e($c['author']) ?></strong> &middot; <?= e($c['created_at']) ?>
            <?php if ($c['updated_at'] !== null): ?><span class="tag" title="Edited <?= e($c['updated_at']) ?>">(Edited)</span><?php endif; ?>
            <?php if ($ownsComment): ?>
                &middot; <a href="index.php?edit_comment=<?= $cid ?>#post-<?= $pid ?>">Edit</a>
                <form method="post" action="index.php#post-<?= $pid ?>" class="inline" onsubmit="return confirm('Delete this comment?');">
                    <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
                    <input type="hidden" name="action" value="delete_comment">
                    <input type="hidden" name="comment_id" value="<?= $cid ?>">
                    <button type="submit" class="link danger">Delete</button>
                </form>
            <?php endif; ?>
        </span>
        <div class="content"><?= e($c['content']) ?></div>
    <?php endif; ?>
    </div>
    <?php endforeach; ?>

    <?php $aKey = 'add_comment_' . $pid; ?>
    <form method="post" action="index.php#post-<?= $pid ?>">
        <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
        <input type="hidden" name="action" value="add_comment">
        <input type="hidden" name="post_id" value="<?= $pid ?>">
        <label for="c-<?= $pid ?>" class="meta">Add a comment</label>
        <textarea id="c-<?= $pid ?>" name="content" rows="2" required maxlength="<?= COMMENT_MAX ?>"><?= e($old[$aKey]['content'] ?? '') ?></textarea>
        <?php if (isset($errors[$aKey]['content'])): ?><p class="error"><?= e($errors[$aKey]['content']) ?></p><?php endif; ?>
        <button type="submit">Comment</button>
    </form>
</article>
<?php endforeach; ?>

</main>
</body>
</html>
