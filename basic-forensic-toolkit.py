import os
import numpy as np
import pyshark
import hashlib
from PIL import Image, ImageChops
from PIL.ExifTags import TAGS
import subprocess
import shutil
import base64
import binascii
import zipfile

def man():
    print("\n--- Manual ---")
    print("This toolkit provides basic forensic utilities:")
    print("1. EXIF data viewer: Extracts metadata from images.")
    print("2. Stego detector: Detects steganography in images via LSB, EOF, etc.")
    print("3. PCAP parser: Displays summary of packets in .pcap files.")
    print("4. File hash checker: Outputs MD5, SHA1, and SHA256 of a file.")
    print("5. Strings extractor: Extracts ASCII strings from binary files.")
    print("6. PDF metadata viewer: Shows author, creation date, etc.")
    print("7. File type checker: Identifies file type via magic numbers.")
    print("8. Image ELA: Highlights image tampering through error-level analysis.\n")
    print("9. Disk usage: Shows total, used, and free disk space.")
    print("10. Base64 decoder: Decodes Base64 encoded strings.")
    print("11. Hex viewer: Displays raw hexadecimal content of a file.")
    print("12. Image format converter: Converts images to different formats.")
    print("13. ZIP extractor: Extracts contents of ZIP archives.\n")

def exif(file_path):
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()

        if exif_data is None:
            print("No EXIF metadata found.")
            return

        print(f"\nEXIF data for: {file_path}")
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            print(f"{tag:25}: {value}")
    except Exception as e:
        print(f"Error: {e}")

def detectStego(file_path):
    # Detect EOF
    with open(file_path, 'rb') as f:
        data = f.read()
        eof_index = data.find(b'\xff\xd9')  # JPEG end marker
        if eof_index != -1 and eof_index + 2 < len(data):
            print("[!] Extra data found after EOF marker – possible hidden payload.")

    # Check LSBs
    image = Image.open(file_path)
    if image.mode != 'RGB':
        image = image.convert('RGB')
    pixels = np.array(image)
    lsb_values = pixels & 1
    randomness = np.std(lsb_values)

    print(f"[i] LSB randomness (std deviation): {randomness:.4f}")
    if randomness > 0.4:
        print("[!] High randomness in LSBs – possible steganography.")
    else:
        print("[i] LSBs appear uniform – likely clean.")

    # File signatures
    signatures = {
        b'\x50\x4B\x03\x04': 'ZIP archive',
        b'\x52\x61\x72\x21': 'RAR archive',
        b'\x89\x50\x4E\x47': 'PNG image',
        b'\x25\x50\x44\x46': 'PDF file'
    }
    for sig, desc in signatures.items():
        if sig in data:
            print(f"[!] Detected embedded file signature: {desc}")

def pcapParser(file_path):
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return
    try:
        cap = pyshark.FileCapture(file_path, only_summaries=True)
        print(f"\n--- All packets from {file_path} ---\n")
        for i, packet in enumerate(cap, 1):
            print(f"[{i}] {packet}")
        cap.close()
    except Exception as e:
        print(f"[!] Error while processing PCAP file: {e}")

def fileHash(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            print(f"MD5     : {hashlib.md5(data).hexdigest()}")
            print(f"SHA1    : {hashlib.sha1(data).hexdigest()}")
            print(f"SHA256  : {hashlib.sha256(data).hexdigest()}")
    except Exception as e:
        print(f"[!] Error: {e}")

def extractStrings(file_path):
    try:
        print(f"\n--- Strings in {file_path} ---\n")
        with open(file_path, 'rb') as f:
            data = f.read()
        strings = ''.join([chr(b) if 32 <= b <= 126 else '\n' for b in data])
        lines = [line for line in strings.split('\n') if len(line) >= 4]
        for line in lines:
            print(line)
    except Exception as e:
        print(f"[!] Error: {e}")

def pdfMeta(file_path):
    try:
        import PyPDF2
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            info = reader.metadata
            print(f"\n--- PDF Metadata for {file_path} ---\n")
            for key, value in info.items():
                print(f"{key}: {value}")
    except Exception as e:
        print(f"[!] Error reading PDF metadata: {e}")

def magicBytes(file_path):
    try:
        with open(file_path, 'rb') as f:
            sig = f.read(4)
        known = {
            b'\x89PNG': 'PNG Image',
            b'\xff\xd8\xff\xe0': 'JPEG Image',
            b'\x25PDF': 'PDF File',
            b'\x50\x4B\x03\x04': 'ZIP Archive',
            b'\x7FELF': 'ELF Executable',
            b'\x52\x61\x72\x21': 'RAR Archive',
        }
        print("\n[+] Magic Bytes Detection:")
        print(f"Signature: {sig}")
        print("Detected as:", known.get(sig, "Unknown file type"))
    except Exception as e:
        print(f"[!] Error: {e}")

def errorLevelAnalysis(file_path):
    try:
        im = Image.open(file_path).convert('RGB')
        im.save('temp_ela.jpg', 'JPEG', quality=90)
        ela_im = Image.open('temp_ela.jpg')
        diff = ImageChops.difference(im, ela_im)
        diff = diff.convert("L")
        diff.save("ela_output.png")
        print("[+] ELA image saved as 'ela_output.png'.")
    except Exception as e:
        print(f"[!] Error performing ELA: {e}")

def diskUsage():
    print("\n--- Disk Usage ---")
    total, used, free = shutil.disk_usage("/")
    print(f"Total: {total // (2**30)} GiB")
    print(f"Used : {used // (2**30)} GiB")
    print(f"Free : {free // (2**30)} GiB")

def base64Decode():
    data = input("Enter Base64 encoded string: ").strip()
    try:
        decoded = base64.b64decode(data)
        print("\nDecoded Output:")
        print(decoded.decode('utf-8', errors='ignore'))
    except Exception as e:
        print(f"[!] Error decoding base64: {e}")

def hexViewer(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        print("\n--- Hex Dump ---\n")
        print(binascii.hexlify(content).decode())
    except Exception as e:
        print(f"[!] Error: {e}")

def convertImageFormat(file_path):
    try:
        img = Image.open(file_path)
        out_format = input("Enter output format (e.g., PNG, BMP, TIFF): ").upper().strip()
        new_name = f"converted_output.{out_format.lower()}"
        img.save(new_name, format=out_format)
        print(f"[+] Image saved as {new_name}")
    except Exception as e:
        print(f"[!] Error: {e}")

def extractZip(file_path):
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall("extracted_zip")
            print("[+] Files extracted to 'extracted_zip/' directory.")
    except Exception as e:
        print(f"[!] Error extracting ZIP file: {e}")


def main():
    while True:
        print("\n-------------------- Basic Forensics Toolkit ------------------")
        print("1. Manual")
        print("2. EXIF data viewer")
        print("3. Detect Stego")
        print("4. PCAP parser")
        print("5. File Hashing")
        print("6. Extract Strings from file")
        print("7. View PDF Metadata")
        print("8. Detect File Type (Magic Bytes)")
        print("9. Image Error Level Analysis")
        print("10. Disk Usage")
        print("11. Base64 Decode")
        print("12. Hex Viewer")
        print("13. Convert Image Format")
        print("14. Extract ZIP File")
        print("15. Exit")

        try:
            option = int(input("Choose an option: ").strip())
        except ValueError:
            print("Invalid input.")
            continue

        if option == 1:
            man()
        elif option == 2:
            file_path = input("Enter image file path: ").strip()
            if os.path.exists(file_path):
                exif(file_path)
            else:
                print("File does not exist.")
        elif option == 3:
            file_path = input("Enter image file path: ").strip()
            if os.path.exists(file_path):
                detectStego(file_path)
            else:
                print("File does not exist.")
        elif option == 4:
            file_path = input("Enter PCAP file path: ").strip()
            pcapParser(file_path)
        elif option == 5:
            file_path = input("Enter file path: ").strip()
            if os.path.exists(file_path):
                fileHash(file_path)
            else:
                print("File does not exist.")
        elif option == 6:
            file_path = input("Enter file path: ").strip()
            if os.path.exists(file_path):
                extractStrings(file_path)
            else:
                print("File does not exist.")
        elif option == 7:
            file_path = input("Enter PDF file path: ").strip()
            if os.path.exists(file_path):
                pdfMeta(file_path)
            else:
                print("File does not exist.")
        elif option == 8:
            file_path = input("Enter file path: ").strip()
            if os.path.exists(file_path):
                magicBytes(file_path)
            else:
                print("File does not exist.")
        elif option == 9:
            file_path = input("Enter image file path: ").strip()
            if os.path.exists(file_path):
                errorLevelAnalysis(file_path)
            else:
                print("File does not exist.")
        elif option == 10:
            diskUsage()
        elif option == 11:
            base64Decode()
        elif option == 12:
            file_path = input("Enter file path: ").strip()
            if os.path.exists(file_path):
                hexViewer(file_path)
            else:
                print("File does not exist.")
        elif option == 13:
            file_path = input("Enter image file path: ").strip()
            if os.path.exists(file_path):
                convertImageFormat(file_path)
            else:
                print("File does not exist.")
        elif option == 14:
            file_path = input("Enter ZIP file path: ").strip()
            if os.path.exists(file_path):
                extractZip(file_path)
            else:
                print("File does not exist.")
        elif option == 15:
            print("Exiting...")
            break
        else:
            print("Invalid option. Choose between 1-15.")

main()