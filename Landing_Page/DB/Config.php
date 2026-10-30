<?php
// DB/Config.php
class ConexionBD {
    private $host = "127.0.0.1";
    private $nombre_db = "onlineashes";
    private $usuario = "root";
    private $contrasena = "";
    public $conn;

    public function obtenerConexion() {
        $this->conn = null;
        try {
            $this->conn = new PDO(
                "mysql:host=" . $this->host . ";dbname=" . $this->nombre_db . ";charset=utf8mb4",
                $this->usuario,
                $this->contrasena
            );
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->conn->exec("SET NAMES utf8mb4");
        } catch (PDOException $exception) {
            // No hagas echo HTML aquí: rompe el JSON del front
            error_log("Error de conexión BD: " . $exception->getMessage());
            $this->conn = null;
        }
        return $this->conn;
    }
}
?>