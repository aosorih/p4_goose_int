import struct
import sys
import time
from typing import List, Tuple

try:
    import nnpy
except ImportError:
    print("Error: La biblioteca 'nnpy' no está instalada.")
    print("Por favor, instálela usando: pip install nnpy")
    sys.exit(1)

try:
    # Ajustamos la importación para pasar IP y puerto
    from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
except ImportError:
    print("Error: La biblioteca 'p4utils' no está instalada o no se encuentra.")
    print("Por favor, asegúrese de que p4utils esté instalado y en su PYTHONPATH.")
    sys.exit(1)

# --- Constantes ---
REMOTE_SWITCH_IP = "192.168.122.78"
THRIFT_PORT = 9090
P4_PROGRAM_NAME = "goosemit"
DIGEST_ID = 1 # ID del digest definido en el código P4

# --- Funciones Auxiliares ---

def mac_to_str(mac_bytes: bytes) -> str:
    """Convierte bytes de MAC a formato string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)

def unpack_goose_digest(msg: bytes, num_samples: int) -> List[Tuple[str, str, int, int, int, int]]:
    """
    Desempaqueta los datos del digest 'goosemit'.

    Args:
        msg: El mensaje de digest crudo recibido.
        num_samples: El número de muestras de digest en el mensaje.

    Returns:
        Una lista de tuplas, donde cada tupla contiene
        (src_addr, dst_addr, appid).
    """
    digest_data = []
    # El índice inicial es 32 (tamaño del encabezado de Nanomsg)
    current_index = 32

    # Formato del struct: 6 bytes (src_addr) + 6 bytes (dst_addr) + 1 byte (in_port) + 2 bytes (appid) + 1 byte (stnum) + 1 byte (sqnum)
    # > significa big-endian, 6s es una cadena de 6 bytes, B es unsigned char (1 byte), H es unsigned short (2 bytes)
    digest_format = ">6s6sBHBB"
    digest_size = struct.calcsize(digest_format)

    for _ in range(num_samples):
        if current_index + digest_size > len(msg):
            print("Error: Mensaje de digest incompleto.")
            break

        # Desempaqueta una muestra de digest
        src_bytes, dst_bytes, in_port, appid, stnum, sqnum  = struct.unpack(
            digest_format, msg[current_index : current_index + digest_size]
        )

        # Convierte las direcciones MAC a formato string
        src_addr = mac_to_str(src_bytes)
        dst_addr = mac_to_str(dst_bytes)

        digest_data.append((src_addr, dst_addr, in_port, appid, stnum, sqnum))
        current_index += digest_size

    return digest_data

# --- Clase del Controlador ---

class GooseDigestController:
    """
    Controlador para conectarse a un switch BMv2 remoto y recibir digests 'goosemit'.
    """

    def __init__(self, thrift_ip: str, thrift_port: int = THRIFT_PORT):
        """
        Inicializa el controlador y establece la conexión.

        Args:
            thrift_ip: La dirección IP del switch BMv2 remoto.
            thrift_port: El puerto Thrift del switch BMv2.
        """
        self.thrift_ip = thrift_ip
        self.thrift_port = thrift_port
        self.controller = None
        self.nn_socket = None
        self._connect()

    def _connect(self):
        """Establece la conexión Thrift y Nanomsg al switch remoto."""
        try:
            print(f"🔌 Conectando al switch BMv2 remoto {self.thrift_ip}:{self.thrift_port} vía Thrift...")
            # Pasamos la IP y el puerto a SimpleSwitchThriftAPI
            self.controller = SimpleSwitchThriftAPI(thrift_port=self.thrift_port, thrift_ip=self.thrift_ip)
            print("✅ Conexión Thrift establecida.")

            # Obtiene la dirección del socket de notificaciones (Nanomsg)
            notifications_socket_addr = self.controller.client.bm_mgmt_get_info().notifications_socket
            print(f"📡 Socket de notificaciones reportado por el switch: {notifications_socket_addr}")

            # --- AJUSTE PARA CONEXIÓN REMOTA NANOMSG ---
            # Si el switch reporta una dirección IPC, no funcionará remotamente.
            if notifications_socket_addr.startswith("ipc://"):
                print("❌ Error: El switch está configurado para notificaciones IPC.")
                print("❌ Para conexión remota, BMv2 debe iniciarse con una dirección TCP,")
                print("❌   ej: --notifications-addr tcp://0.0.0.0:22222")
                sys.exit(1)

            # Si el switch reporta '0.0.0.0' o '127.0.0.1', lo reemplazamos con la IP remota.
            if notifications_socket_addr.startswith("tcp://0.0.0.0"):
                notifications_socket_addr = notifications_socket_addr.replace("0.0.0.0", self.thrift_ip)
                print(f"🔧 Ajustando dirección Nanomsg a: {notifications_socket_addr}")
            elif notifications_socket_addr.startswith("tcp://127.0.0.1"):
                 notifications_socket_addr = notifications_socket_addr.replace("127.0.0.1", self.thrift_ip)
                 print(f"🔧 Ajustando dirección Nanomsg a: {notifications_socket_addr}")
            # --- FIN AJUSTE ---

            # Configura el socket Nanomsg para recibir digests
            self.nn_socket = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
            print(f"📡 Conectando al socket Nanomsg en: {notifications_socket_addr}")
            self.nn_socket.connect(notifications_socket_addr)
            # Se suscribe a todos los mensajes (b'')
            self.nn_socket.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, b'')
            print("✅ Socket Nanomsg configurado y escuchando.")

        except nnpy.NNError as nne:
            print(f"❌ Error de Nanomsg al conectar a {notifications_socket_addr}: {nne}")
            print("❌ Verifique que el switch BMv2 esté corriendo y que la dirección")
            print("❌   y puerto de notificaciones (--notifications-addr) sean correctos")
            print("❌   y accesibles desde esta máquina (revise firewalls).")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error durante la conexión: {e}")
            print(f"❌ Verifique que el switch BMv2 esté corriendo en {self.thrift_ip}:{self.thrift_port}")
            print("❌   y que el puerto Thrift sea accesible (revise firewalls).")
            sys.exit(1)


    def handle_digest_message(self, msg: bytes):
        """
        Procesa un mensaje de digest recibido vía Nanomsg.
        """
        try:
            # Desempaqueta el encabezado del mensaje de Nanomsg
            topic, device_id, ctx_id, list_id, buffer_id, num_samples = struct.unpack(
                "<iQiiQi", msg[:32]
            )

            print(f"\n--- 📩 Digest Recibido (ID: {list_id}, Muestras: {num_samples}) ---")

            # Desempaqueta los datos específicos del digest
            digest_list = unpack_goose_digest(msg, num_samples)

            # Procesa cada muestra del digest
            for src_addr, dst_addr, in_port, appid, stnum, sqnum in digest_list:
                print(f"  Fuente MAC: {src_addr}")
                print(f"  Destino MAC: {dst_addr}")
                print(f"  Ingress Port: {in_port}")
                print(f"  GOOSE AppID: {appid}")
                print(f"  GOOSE stnum: {stnum}")
                print(f"  GOOSE sqnum: {sqnum}")
                print("  ---")

            # Envía el acknowledgment (ACK) al switch para liberar el buffer
            print(f"📬 Enviando ACK (Buffer ID: {buffer_id})...")
            self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)
            print("✅ ACK enviado.")

        except struct.error as se:
            print(f"⚠️ Error al desempaquetar el mensaje de digest: {se}")
        except Exception as e:
            print(f"❌ Error inesperado al manejar el digest: {e}")


    def run(self):
        """
        Inicia el bucle principal para escuchar mensajes de digest.
        """
        print(f"\n🚀 Iniciando escucha de digests para '{P4_PROGRAM_NAME}' en {self.thrift_ip}...")
        print("Presione Ctrl+C para detener.")
        try:
            while True:
                # Bloquea hasta que se reciba un mensaje
                received_msg = self.nn_socket.recv()
                self.handle_digest_message(received_msg)
                time.sleep(0.01) # Pequeña pausa

        except KeyboardInterrupt:
            print("\n🛑 Deteniendo el controlador...")
        finally:
            if self.nn_socket:
                self.nn_socket.close()
            print("👋 Controlador detenido.")

# --- Punto de Entrada Principal ---

if __name__ == "__main__":
    # Crea la instancia del controlador pasando la IP remota
    controller = GooseDigestController(thrift_ip=REMOTE_SWITCH_IP, thrift_port=THRIFT_PORT)
    controller.run()