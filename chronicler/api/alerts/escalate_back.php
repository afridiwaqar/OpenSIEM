<?php
// /var/www/chronicler/api/alerts/escalate.php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$db     = pdo();

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function current_user_id(): int {
    return (int)($_SESSION['user_id'] ?? $_SESSION['id'] ?? $_SESSION['uid'] ?? 0);
}

function get_alert(PDO $db, int $id): ?array {
    $s = $db->prepare(
        "SELECT a.*,
        l.username  AS assigned_username,
        l.email     AS assigned_email,
        l2.username AS acked_by_username
        FROM alerts a
        LEFT JOIN login l  ON l.user_id = a.assigned_to
        LEFT JOIN login l2 ON l2.user_id = a.acknowledged_by
        WHERE a.id = ?"
    );
    $s->execute([$id]);
    return $s->fetch(PDO::FETCH_ASSOC) ?: null;
}

function get_notes(PDO $db, int $alert_id): array {
    $s = $db->prepare(
        "SELECT n.id, n.note, n.created_at, l.username AS author
        FROM alert_notes n
        JOIN login l ON l.user_id = n.author_id
        WHERE n.alert_id = ?
        ORDER BY n.created_at ASC"
    );
    $s->execute([$alert_id]);
    return $s->fetchAll(PDO::FETCH_ASSOC);
}

function notify_analyst(PDO $db, int $alert_id, int $analyst_id,
                        string $case_name, string $severity): void {
                            try {
                                $db->prepare(
                                    "INSERT INTO ui_notifications
                                    (user_id, message, alert_id, created_at)
                                VALUES (?, ?, ?, now())"
                                )->execute([
                                    $analyst_id,
                                    "You have been assigned alert: {$case_name} [{$severity}]",
                                    $alert_id
                                ]);
                            } catch (Exception $e) { /* table may not exist yet */ }

                            $s = $db->prepare("SELECT email, username FROM login WHERE user_id = ?");
                            $s->execute([$analyst_id]);
                            $analyst = $s->fetch(PDO::FETCH_ASSOC);
                            if (!$analyst || empty($analyst['email'])) return;

                            $conf_file = '/etc/opensiem/opensiem.conf';
                            if (!file_exists($conf_file)) return;
                            $conf = parse_ini_file($conf_file, true);
                            if (empty($conf['email']['enabled']) || $conf['email']['enabled'] !== 'yes') return;

                            $smtp_server   = $conf['email']['smtp_server']    ?? '';
                            $smtp_port     = (int)($conf['email']['smtp_port'] ?? 587);
                            $sender        = $conf['email']['sender_email']   ?? '';
                            $password      = $conf['email']['sender_password'] ?? '';
                            $use_tls       = ($conf['email']['use_tls'] ?? 'yes') === 'yes';

                            if (!$smtp_server || !$sender) return;

                            $to      = $analyst['email'];
                            $subject = "OpenSIEM — Alert Assigned: {$case_name} [{$severity}]";
                            $body    = "Hello {$analyst['username']},\r\n\r\n"
                            . "You have been assigned a security alert in Chronicler.\r\n\r\n"
                            . "Alert ID   : {$alert_id}\r\n"
                            . "Case       : {$case_name}\r\n"
                            . "Severity   : " . strtoupper($severity) . "\r\n\r\n"
                            . "Please log in to Chronicler to investigate.\r\n\r\n"
                            . "— OpenSIEM";

                            try {
                                $payload = base64_encode(json_encode([
                                    'to'       => $to,
                                    'subject'  => $subject,
                                    'body'     => $body,
                                    'severity' => $severity,
                                ]));
                                $cmd = "python3 -c \"
                                import sys, json, base64, smtplib
                                from email.mime.text import MIMEText
                                p = json.loads(base64.b64decode('{$payload}'))
                                msg = MIMEText(p['body'])
                                msg['Subject'] = p['subject']
                                msg['From']    = '{$sender}'
                                msg['To']      = p['to']
                                try:
                                s = smtplib.SMTP('{$smtp_server}', {$smtp_port}, timeout=10)
                                " . ($use_tls ? "s.starttls()" : "") . "
                                " . ($password ? "s.login('{$sender}', '{$password}')" : "") . "
                                s.send_message(msg)
                                s.quit()
                                except Exception as e:
                                print('mail error:', e, file=sys.stderr)
                                \" 2>/dev/null &";
                                shell_exec($cmd);
                            } catch (Exception $e) { /* non-fatal */ }
                        }

                        try {
                            if ($method === 'GET') {
                                $action   = $_GET['action'] ?? 'detail';
                                $alert_id = (int)($_GET['alert_id'] ?? 0);

                                if ($action === 'detail') {
                                    if (!$alert_id) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'alert_id required']); exit; }
                                    $alert = get_alert($db, $alert_id);
                                    if (!$alert) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'Not found']); exit; }
                                    $notes = get_notes($db, $alert_id);
                                    echo json_encode(['ok'=>true, 'alert'=>$alert, 'notes'=>$notes]);

                                } elseif ($action === 'analysts') {
                                    // Fix: login table PK is user_id, aliased as id for UI compatibility
                                    $rows = $db->query(
                                        "SELECT user_id AS id, username, email FROM login
                                        WHERE is_active = true
                                        AND role IN ('analyst','admin')
                                    ORDER BY username"
                                    )->fetchAll(PDO::FETCH_ASSOC);
                                    echo json_encode(['ok'=>true, 'analysts'=>$rows]);

                                } elseif ($action === 'metrics') {
                                    $rows = $db->query(
                                        "SELECT
                                        l.username,
                                        COUNT(a.id)                                          AS total_assigned,
                                                       COUNT(a.first_ack_at)                                AS total_acked,
                                                       COUNT(CASE WHEN a.status='resolved' THEN 1 END)      AS total_resolved,
                                                       ROUND(AVG(
                                                           EXTRACT(EPOCH FROM (a.first_ack_at - a.assigned_at)) / 60
                                    )::numeric, 1)                                       AS avg_mtta_minutes,
                                    ROUND(AVG(
                                        CASE WHEN a.resolved_at IS NOT NULL
                                        THEN EXTRACT(EPOCH FROM (a.resolved_at - a.assigned_at)) / 60
                                        END
                                    )::numeric, 1)                                       AS avg_mttr_minutes
                                    FROM alerts a
                                    JOIN login l ON l.user_id = a.assigned_to
                                    WHERE a.assigned_to IS NOT NULL
                                    GROUP BY l.user_id, l.username
                                    ORDER BY total_assigned DESC"
                                    )->fetchAll(PDO::FETCH_ASSOC);
                                    echo json_encode(['ok'=>true, 'metrics'=>$rows]);

                                } else {
                                    http_response_code(400);
                                    echo json_encode(['ok'=>false,'error'=>"Unknown action: {$action}"]);
                                }

                            } elseif ($method === 'POST') {
                                require_perm('update');
                                $body     = json_decode(file_get_contents('php://input'), true) ?? [];
                                $action   = $body['action']   ?? '';
                                $alert_id = (int)($body['alert_id'] ?? 0);
                                if (!$alert_id) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'alert_id required']); exit; }

                                $alert = get_alert($db, $alert_id);
                                if (!$alert) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'Alert not found']); exit; }

                                if ($action === 'assign') {
                                    $analyst_id = (int)($body['analyst_id'] ?? 0);

                                    // Explicitly cast ?::integer so Postgres can resolve the parameter type
                                    $db->prepare(
                                        "UPDATE alerts
                                        SET assigned_to  = ?,
                                        assigned_at  = now(),
                                                 status       = CASE WHEN status = 'open' THEN 'investigating' ELSE status END,
                                                 escalated_at = CASE WHEN ?::integer IS NOT NULL AND assigned_to IS NULL THEN now() ELSE escalated_at END
                                                 WHERE id = ?"
                                    )->execute([$analyst_id ?: null, $analyst_id ?: null, $alert_id]);

                                    $me = current_user_id();

                                    if ($me === 0) {
                                        $stmt = $db->query("SELECT user_id FROM login WHERE role = 'admin' LIMIT 1");
                                        $me = (int)$stmt->fetchColumn() ?: 1;
                                    }

                                    if ($analyst_id) {
                                        $s = $db->prepare("SELECT username FROM login WHERE user_id = ?");
                                        $s->execute([$analyst_id]);
                                        $name = $s->fetchColumn() ?: 'Unknown';
                                        $db->prepare(
                                            "INSERT INTO alert_notes (alert_id, author_id, note) VALUES (?,?,?)"
                                        )->execute([$alert_id, $me, "Alert assigned to {$name}."]);

                                        $note_data  = json_decode($alert['admin_note'] ?? '{}', true);
                                        $case_name  = $note_data['case_name'] ?? "Alert #{$alert_id}";
                                        notify_analyst($db, $alert_id, $analyst_id, $case_name, $alert['severity']);
                                    } else {
                                        $db->prepare(
                                            "INSERT INTO alert_notes (alert_id, author_id, note) VALUES (?,?,?)"
                                        )->execute([$alert_id, $me, "Alert unassigned."]);
                                    }
                                    echo json_encode(['ok'=>true]);

                                } elseif ($action === 'status') {
                                    $new_status = $body['status'] ?? '';
                                    $allowed    = ['open','investigating','resolved','false_positive'];
                                    if (!in_array($new_status, $allowed)) {
                                        http_response_code(400);
                                        echo json_encode(['ok'=>false,'error'=>"Invalid status: {$new_status}"]);
                                        exit;
                                    }
                                    $me = current_user_id();

                                    $db->prepare(
                                        "UPDATE alerts SET
                                        status          = ?,
                                        is_active       = CASE WHEN ? IN ('resolved','false_positive') THEN false ELSE is_active END,
                                                 resolved_at     = CASE WHEN ? IN ('resolved','false_positive') AND resolved_at IS NULL THEN now() ELSE resolved_at END,
                                                 first_ack_at    = CASE WHEN ? = 'investigating' AND first_ack_at IS NULL THEN now() ELSE first_ack_at END,
                                                 acknowledged_by = CASE WHEN ? = 'investigating' AND acknowledged_by IS NULL THEN ? ELSE acknowledged_by END,
                                                 acknowledged_time = CASE WHEN ? = 'investigating' AND acknowledged_time IS NULL THEN now() ELSE acknowledged_time END
                                                 WHERE id = ?"
                                    )->execute([
                                        $new_status,
                                        $new_status, $new_status,
                                        $new_status, $new_status, $me,
                                        $new_status,
                                        $alert_id
                                    ]);

                                    $label_map = [
                                        'open'           => 'reopened',
                                        'investigating'  => 'marked as investigating',
                                        'resolved'       => 'marked as resolved',
                                        'false_positive' => 'marked as false positive',
                                    ];
                                    $db->prepare(
                                        "INSERT INTO alert_notes (alert_id, author_id, note) VALUES (?,?,?)"
                                    )->execute([$alert_id, $me, "Status changed to: " . ($label_map[$new_status] ?? $new_status) . "."]);

                                    echo json_encode(['ok'=>true]);

                                } elseif ($action === 'note') {
                                    $note = trim($body['note'] ?? '');
                                    if (!$note) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Note cannot be empty']); exit; }
                                    $me = current_user_id();
                                    $db->prepare(
                                        "INSERT INTO alert_notes (alert_id, author_id, note) VALUES (?,?,?)"
                                    )->execute([$alert_id, $me, $note]);
                                    $notes = get_notes($db, $alert_id);
                                    echo json_encode(['ok'=>true, 'notes'=>$notes]);

                                }
                                else {
                                    http_response_code(400);
                                    echo json_encode(['ok'=>false,'error'=>"Unknown action: {$action}"]);
                                }

                            } else {
                                http_response_code(405);
                                echo json_encode(['ok'=>false,'error'=>'Method not allowed']);
                            }

                        } catch (Exception $e) {
                            http_response_code(500);
                            echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);
                        }
