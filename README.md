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

3. **Python Requirements**
   - Python 3.8 atau lebih tinggi
   - Sistem operasi yang didukung:
     - Windows

Install dependencies:
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
