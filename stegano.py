from PIL import Image
import os

def hide_data(image_path, message, output_path="assets/stego_image.png"):
    try:
        img = Image.open(image_path)
        encoded = img.copy()
        width, height = img.size
        message += chr(0)  # End marker
        data_idx = 0

        for row in range(height):
            for col in range(width):
                if data_idx >= len(message):
                    break
                r, g, b = img.getpixel((col, row))
                encoded.putpixel((col, row), (r, g, ord(message[data_idx])))
                data_idx += 1

        # Pastikan folder tujuan ada
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        encoded.save(output_path)
        print(f"[+] Data disembunyikan ke dalam {output_path}")
        return output_path

    except Exception as e:
        print(f"[!] Gagal menyisipkan data: {e}")
        return None

def reveal_data(stego_path):
    try:
        img = Image.open(stego_path)
        message = ""

        for row in range(img.size[1]):
            for col in range(img.size[0]):
                _, _, b = img.getpixel((col, row))
                if b == 0:
                    return message
                message += chr(b)

        return message  # fallback
    except Exception as e:
        print(f"[!] Gagal mengambil pesan: {e}")
        return "[!] Error membaca pesan"
