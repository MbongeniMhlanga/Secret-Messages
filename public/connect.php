<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "secret_messages";

$connect = new mysqli($servername, $username, $password, $dbname);

if ($connect->connect_error) {
    die("Connection failed: " . $connect->connect_error);
}

$message = $_POST['message']; // encrypted
$sql = "INSERT INTO messages (encrypted_message) VALUES ('$message')";

if ($connect->query($sql) === TRUE) {
    echo json_encode(['status' => 'success']);
} else {
    echo json_encode(['status' => 'error']);
}

$connect->close();
?>
