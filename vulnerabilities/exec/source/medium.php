<?php
if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = trim($_REQUEST[ 'ip' ]);
	
	// Validar que sea una IP o hostname válido
	$target = filter_var($target, FILTER_VALIDATE_IP);
	
	if ($target === false) {
		// Si no es una IP válida, intentar validar como hostname
		$target = trim($_REQUEST[ 'ip' ]);
		// Permitir solo caracteres válidos para hostname (letras, números, guiones, puntos)
		if (!preg_match('/^[a-zA-Z0-9.-]+$/', $target)) {
			$html .= "<pre>Error: Invalid IP address or hostname format</pre>";
			return;
		}
		// Validar longitud máxima
		if (strlen($target) > 253) {
			$html .= "<pre>Error: Hostname too long</pre>";
			return;
		}
	}
	
	// Escapar el argumento para shell
	$target = escapeshellarg($target);
	
	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		$cmd = shell_exec( 'ping ' . $target );
	}
	else {
		// *nix
		$cmd = shell_exec( 'ping -c 4 ' . $target );
	}
	
	// Escapar la salida para prevenir XSS
	$html .= "<pre>" . htmlspecialchars($cmd, ENT_QUOTES, 'UTF-8') . "</pre>";
}
?>
