# NetSlicer

NetSlicer adalah alat pemantau jaringan dan keamanan dengan antarmuka GUI yang dibuat menggunakan Python.

## Overview

NetSlicer provides a user-friendly interface for scanning local networks, identifying connected devices, and managing network interactions. It supports features such as ARP spoofing, OS detection, and real-time monitoring of network devices.

## Prerequisites / Persyaratan Sistem

Sebelum menginstall NetSlicer, pastikan Anda telah menginstall:

1. **Npcap**
   - Download [Npcap 1.75](https://npcap.com/dist/npcap-1.75.exe)
   - Install dengan opsi default
   - Restart komputer setelah instalasi

2. **Visual C++ Redistributable**
   - Download [VC_redist.x64.exe](https://aka.ms/vs/17/release/vc_redist.x64.exe)
   - Install dengan opsi default
   - Tidak perlu restart

4. **Python Requirements**
   - Python 3.8 atau lebih tinggi
   - Sistem operasi yang didukung:
     - Windows


## Instalasi

1. Install prerequisites di atas
2. Install NetSlicer:
```bash
pip install netslicer
```

## Usage

```bash
netslicer
```

## Pengembangan

1. Clone repositori:
```bash
git clone https://github.com/MrRahman20/netslicer.git
cd netslicer
```

2. Buat virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Troubleshooting

Jika mengalami masalah:

1. **"Scapy failed to start capture"**
   - Pastikan Npcap sudah terinstall
   - Coba restart komputer

2. **"VCRUNTIME140.dll is missing"**
   - Install Visual C++ Redistributable

## Lisensi

Proyek ini dilisensikan di bawah Lisensi MIT - lihat file [LICENSE](LICENSE) untuk detail.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Author

- Muhammad Ruhiyatna Rahman
- Instagram: [@rahman.zip](https://www.instagram.com/rahman.zip)
