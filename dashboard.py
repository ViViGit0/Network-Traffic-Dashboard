import streamlit as st
import pandas as pd
import plotly.express as px
import threading
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
import logging

# Configurazione del logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Classe per catturare e analizzare pacchetti di rete in tempo reale."""

    def __init__(self):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()

    def get_protocol_name(self, protocol_num: int) -> str:
        """Converti il numero di protocollo nel nome corrispondente."""
        return self.protocol_map.get(protocol_num, f"Other({protocol_num})")

    def process_packet(self, packet) -> None:
        """Elabora un pacchetto e raccoglie informazioni chiave."""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        "timestamp": datetime.now(),
                        "source": packet[IP].src,
                        "destination": packet[IP].dst,
                        "protocol": self.get_protocol_name(packet[IP].proto),
                        "size": len(packet),
                        "time_relative": (datetime.now() - self.start_time).total_seconds(),
                    }

                    if TCP in packet:
                        packet_info.update({"src_port": packet[TCP].sport, "dst_port": packet[TCP].dport, "tcp_flags": packet[TCP].flags})
                    elif UDP in packet:
                        packet_info.update({"src_port": packet[UDP].sport, "dst_port": packet[UDP].dport})

                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    # Mantieni solo gli ultimi 10.000 pacchetti per evitare problemi di memoria
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)
        except Exception as e:
            logger.error(f"Errore nell'elaborazione del pacchetto: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        """Restituisce i dati in formato DataFrame."""
        with self.lock:
            return pd.DataFrame(self.packet_data)

def create_visualizations(df: pd.DataFrame):
    """Genera visualizzazioni per l'analisi del traffico di rete."""
    if not df.empty:
        # Distribuzione dei protocolli
        protocol_counts = df["protocol"].value_counts()
        fig_protocol = px.pie(values=protocol_counts.values, names=protocol_counts.index, title="Distribuzione dei protocolli")
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Timeline dei pacchetti
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df_grouped = df.groupby(df["timestamp"].dt.floor("S")).size()
        fig_timeline = px.line(x=df_grouped.index, y=df_grouped.values, title="Pacchetti per secondo")
        st.plotly_chart(fig_timeline, use_container_width=True)

        # IP di origine più frequenti
        top_sources = df["source"].value_counts().head(10)
        fig_sources = px.bar(x=top_sources.index, y=top_sources.values, title="Top IP sorgenti")
        st.plotly_chart(fig_sources, use_container_width=True)

def start_packet_capture() -> PacketProcessor:
    """Avvia la cattura dei pacchetti in un thread separato."""
    processor = PacketProcessor()

    def capture_packets():
        logger.info("Inizio cattura pacchetti...")
        sniff(prn=processor.process_packet, store=False)

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return processor

def main():
    """Funzione principale per eseguire il dashboard di analisi del traffico di rete."""
    st.set_page_config(page_title="Analisi del traffico di rete", layout="wide")
    st.title("Monitoraggio del traffico di rete in tempo reale")

    # Inizializza il processore di pacchetti nella sessione
    if "processor" not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()

    # Layout della dashboard
    col1, col2 = st.columns(2)

    # Recupera i dati attuali
    df = st.session_state.processor.get_dataframe()

    # Mostra i valori principali
    with col1:
        st.metric("Pacchetti Totali", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Durata cattura", f"{duration:.2f}s")

    # Genera le visualizzazioni
    create_visualizations(df)

    # Mostra gli ultimi pacchetti catturati
    st.subheader("Pacchetti Recenti")
    if not df.empty:
        st.dataframe(df.tail(10)[["timestamp", "source", "destination", "protocol", "size"]], use_container_width=True)

    # Pulsante di aggiornamento manuale
    if st.button("Aggiorna Dati"):
        st.rerun()

    # Auto-refresh ogni 2 secondi
    time.sleep(2)
    st.rerun()

if __name__ == "__main__":
    main()
