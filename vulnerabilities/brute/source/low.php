<?php
if( isset( $_POST[ 'Login' ] ) ) {
    // Validar que los campos existan y no estén vacíos
    if (empty($_POST['username']) || empty($_POST['password'])) {
        $html .= "<pre><br />Please enter username and password.</pre>";
    } else {
        // Sanitizar y validar entrada
        $user = trim($_POST['username']);
        $pass = trim($_POST['password']);
        
        // Validar longitud
        if (strlen($user) > 50 || strlen($pass) > 100) {
            $html .= "<pre><br />Invalid input length.</pre>";
        } else {
            // Hash de la contraseña
            $pass = md5($pass);
            
            // SOLUCIÓN: Usar prepared statements para prevenir SQL Injection
            $query = "SELECT * FROM users WHERE user = ? AND password = ?";
            
            // Preparar la consulta
            if ($stmt = mysqli_prepare($GLOBALS["mysqli_ston"], $query)) {
                
                // Vincular los parámetros
                mysqli_stmt_bind_param($stmt, "ss", $user, $pass);
                
                // Ejecutar la consulta
                mysqli_stmt_execute($stmt);
                
                // Obtener el resultado
                $result = mysqli_stmt_get_result($stmt);
                
                if ($result && mysqli_num_rows($result) == 1) {
                    // Get users details
                    $row = mysqli_fetch_assoc($result);
                    $avatar = $row["avatar"];
                    
                    // Login successful - Escapar salida para prevenir XSS
                    $html .= "<p>Welcome to the password protected area " . htmlspecialchars($user, ENT_QUOTES, 'UTF-8') . "</p>";
                    $html .= "<img src=\"" . htmlspecialchars($avatar, ENT_QUOTES, 'UTF-8') . "\" />";
                } else {
                    // Login failed
                    $html .= "<pre><br />Username and/or password incorrect.</pre>";
                }
                
                // Cerrar el statement
                mysqli_stmt_close($stmt);
                
            } else {
                // Error al preparar la consulta
                $html .= "<pre><br />Database error occurred.</pre>";
            }
            
            // Cerrar conexión
            mysqli_close($GLOBALS["mysqli_ston"]);
        }
    }
}
?>
