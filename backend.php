<?php
session_start();
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "users_db";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] == 'register') {
        $name = $_POST['name'];
        $email = $_POST['email'];
        $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
        $created_at = date('Y-m-d H:i:s');
        
        $stmt = $conn->prepare("INSERT INTO users (name, email, password, created_at) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $name, $email, $password, $created_at);
        if ($stmt->execute()) {
            echo json_encode(["message" => "User registered successfully"]);
        } else {
            echo json_encode(["message" => "Email already exists"]);
        }
        $stmt->close();
    }
    
    if ($_POST['action'] == 'login') {
        $email = $_POST['email'];
        $password = $_POST['password'];
        
        $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                echo json_encode(["message" => "Login successful"]);
            } else {
                echo json_encode(["message" => "Invalid credentials"]);
            }
        } else {
            echo json_encode(["message" => "User not found"]);
        }
        $stmt->close();
    }
}

function deleteExpiredUsers($conn) {
    $expiry_time = date('Y-m-d H:i:s', strtotime('-3 days'));
    $stmt = $conn->prepare("DELETE FROM users WHERE created_at < ?");
    $stmt->bind_param("s", $expiry_time);
    $stmt->execute();
    $stmt->close();
}

deleteExpiredUsers($conn);
$conn->close();
?>
