from scapy.all import *
import argparse
import struct
from datetime import datetime

def parse_telemetry(payload, offset=0):
    """Parsea telemetría desde un offset específico (48+48+32 bits = 16 bytes)"""
    try:
        # Calcular posición final (offset + 13 bytes)
        start = offset
        end = offset + 16
        
        if len(payload) < end:
            return None

        # Extraer los 13 bytes relevantes
        telemetry_data = payload[start:end]

        # Dividir los bytes
        ingress_bytes = telemetry_data[:6]      # Primeros 6 bytes (48 bits)
        egress_bytes = telemetry_data[6:12]     # Siguientes 6 bytes (48 bits)
        flow_id_bytes = telemetry_data[12:16]       # Últimos 4 byte (32 bits)

        # Convertir a enteros (big-endian)
        ingress_time = int.from_bytes(ingress_bytes, byteorder='big')
        egress_time = int.from_bytes(egress_bytes, byteorder='big')
        flow_id = int.from_bytes(flow_id_bytes, byteorder='big')

        return {
            'ingress_time': ingress_time,
            'egress_time': egress_time,
            'flow_id': flow_id,
            'ingress_hex': ingress_bytes.hex(),
            'egress_hex': egress_bytes.hex(),
            'raw_bytes': telemetry_data.hex()  # Para depuración
        }
    except Exception as e:
        print(f"Error parsing telemetry: {e}")
        return None

def packet_handler(pkt, offset=0):
    """Procesa paquetes con offset personalizado"""
    if Ether in pkt:
        eth = pkt[Ether]
        payload = bytes(eth.payload)
        
        print(f"\n[+] Paquete capturado (EtherType: 0x{eth.type:04x}):")
        print(f"    MAC Origen: {eth.src}, Destino: {eth.dst}")
        print(f"    Payload completo ({len(payload)} bytes): {payload.hex()}")
        
        telemetry = parse_telemetry(payload, offset)
        if telemetry:
            print("\n[!] Telemetría detectada:")
            latencia = telemetry['egress_time'] - telemetry['ingress_time']
            print(f"    Ingreso (hex): {telemetry['ingress_hex']} -> Dec: {telemetry['ingress_time']}")
            print(f"    Salida  (hex): {telemetry['egress_hex']} -> Dec: {telemetry['egress_time']}")
            print(f"    Latencia microseg: {latencia}")
            print(f"    Flow ID  Dec: {telemetry['flow_id']}")
            print(f"    Bytes crudos: {telemetry['raw_bytes']}")
        else:
            print("    No se detectó estructura de telemetría")

def main():
    parser = argparse.ArgumentParser(description='Sniffer avanzado para telemetría')
    parser.add_argument('-i', '--interface', required=True, help='Interfaz de red')
    parser.add_argument('-o', '--offset', type=int, default=0,
                       help='Offset en bytes donde empieza la telemetría')
    
    args = parser.parse_args()
    
    print(f"\n[+] Iniciando captura en {args.interface} con offset={args.offset}")
    print("[!] Los datos de telemetría deben estar en 16 bytes contiguos")
    
    sniff(
        iface=args.interface,
        prn=lambda x: packet_handler(x, args.offset),
        store=0
    )

if __name__ == "__main__":
    main()