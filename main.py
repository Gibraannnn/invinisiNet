import stegano
import vpn_client
import evasion

if __name__ == "__main__":
    stegano.hide_data("assets/cover.png", "Stego encoded by InvisiNet")
    stegano.reveal_data("assets/stego_image.png")
    vpn_client.start_vpn("myvpn.ovpn")
    evasion.detect_sniffing()
