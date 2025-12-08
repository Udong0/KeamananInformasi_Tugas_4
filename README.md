# KeamananInformasi_Tugas_4
Anggota Kelompok:
M Rafli Abdillah (5025231028)
Ahmad Muqorrobin (5025231254)
-------------------------------
Alur Program di Tugas 4:
1. Host dan Client akan menyiapkan pasangan kunci RSA (Public dan Private) sebagai identitas digital masing-masing. [start_server] dan [start_client]
2. Bertukar public keys ketika host dan client saling tersambung. [start_server] dan [start_client]
3. Client generate acak 8 byte Key dan 8 byte IV. [start_client]
4. Signing dengan Client melakukan `(message^privatekey) mod n` pada key yang tadi di generate yang akan menghasilkan signature. [start_client]
5. Encryption, Client mengenkripsi kunci tadi dengan Public Key Host sehingga hanya bisa dibuka oleh Host. [start_client]
6. Client mengirim Encrypted Key dan Signature dalam 1 paket.
7. Host menerima dan mendekripsi paket yang diterima menggunakan Private Key Host. [start_server]
8. Signature Verification, Host mengecek apakah key yang diterima cocok dengan signature yang dikirim dengan `(signature^publickeyclient) mod n` menggunakan Public Key Client. [start_server]
9. Chatting session, Host dan Client akhirnya bisa melakukan chatting dengan kunci DES dimana proses enkripsi/dekripsi chat berjalan seperti sebelumnya. [chat_loop]
