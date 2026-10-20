# PROPOSAL PROYEK AKHIR

## SISTEM DETEKSI DAN MITIGASI DDoS MENGGUNAKAN MACHINE LEARNING BERBASIS eBPF/XDP

**Ihsanta Zaki Sanjaya**
NRP 322600058

**Dosen Pembimbing**
- Maretha Ruswiansari, S.ST, MT — NIP 19900322 201903 2 014
- Reni Soelistijorini, B.Eng., MT — NIP 19710428 199903 2 002

Program Studi Sarjana Terapan Teknik Komputer
Departemen Teknik Informatika dan Komputer
Politeknik Elektronika Negeri Surabaya
2026

---

## DAFTAR SINGKATAN

| Singkatan | Kepanjangan |
|---|---|
| ADR | Attack Detection Rate |
| ARP | Address Resolution Protocol |
| CIDR | Classless Inter-Domain Routing |
| CPU | Central Processing Unit |
| DDoS | Distributed Denial of Service |
| DNS | Domain Name System |
| DoS | Denial of Service |
| DT | Decision Tree |
| eBPF | extended Berkeley Packet Filter |
| FPR | False Positive Rate |
| ICMP | Internet Control Message Protocol |
| IDS | Intrusion Detection System |
| IPS | Intrusion Prevention System |
| JIT | Just-In-Time (compiler) |
| KNN | K-Nearest Neighbor |
| LAN | Local Area Network |
| ML | Machine Learning |
| MLP | Multi-Layer Perceptron |
| NIC | Network Interface Card |
| NIPS | Network Intrusion Prevention System |
| PCAP | Packet Capture |
| RF | Random Forest |
| RSS | Receive Side Scaling |
| RTT | Round Trip Time |
| SIEM | Security Information and Event Management |
| SYN | Synchronize |
| TCP | Transmission Control Protocol |
| TNR | True Negative Rate |
| TTL | Time To Live |
| TTM | Time-to-Mitigation |
| UDP | User Datagram Protocol |
| WAN | Wide Area Network |
| XDP | eXpress Data Path |

---

# BAB 1 PENDAHULUAN

## 1.1 Latar Belakang

Distributed Denial of Service (DDoS) adalah serangan terdistribusi yang membanjiri sistem atau jaringan target dengan trafik dalam jumlah besar sehingga layanan tidak dapat diakses oleh pengguna yang sah [1], [2]. Skala ancaman ini masif sepanjang tahun 2025, yang tergambar dari deteksi 7,1 miliar aktivitas botnet dari laporan Fortinet [3]. Cloudflare juga mencatat 34,4 juta serangan DDoS network-layer sepanjang tahun 2025, dengan Indonesia sebagai sumber serangan DDoS terbesar di dunia sepanjang periode tersebut sebelum turun ke posisi tiga besar pada Q4 [4].

Serangan DDoS, khususnya ancaman volumetrik dan multi-vector, mampu menumbangkan sistem pertahanan konvensional [5]. Sistem berbasis user space seperti Snort dan Suricata mudah lumpuh akibat overhead komputasi tinggi dan buffer overflow [5]. Sementara itu, firewall kernel seperti iptables tetap memicu overhead Central Processing Unit (CPU) yang tinggi karena menyaring paket di fase akhir tumpukan jaringan (*late stack processing*), setelah tahap inisialisasi paket telanjur membebani sistem [6].

Untuk mengatasi celah tersebut, extended Berkeley Packet Filter (eBPF) dan eXpress Data Path (XDP) menawarkan arsitektur pemrosesan paket berperforma tinggi [5]. Teknologi eBPF memungkinkan eksekusi program pemfilteran langsung di dalam mesin virtual kernel secara aman. Secara spesifik, XDP mampu mencegat paket di tingkat driver jaringan pada titik paling awal, jauh sebelum paket memasuki network stack sistem operasi [6]. Pemotongan jalur ini menekan berbagai operasi kernel, sehingga menghasilkan latensi rendah dan throughput tinggi yang ideal untuk mengamankan lingkungan jaringan berkecepatan tinggi [5], [6].

Beberapa penelitian telah mengkaji penerapan eBPF untuk keamanan jaringan. Soldani dkk. mendemonstrasikan potensi eBPF dalam konteks jaringan 5G dan 6G [7], sementara Remya dkk. mengembangkan sistem deteksi semantik menggunakan eBPF dengan Random Forest (RF) sebagai post-filter [8]. Hadi dkk. juga memperkenalkan iKern untuk deteksi dan pencegahan intrusi tingkat kernel [5]. Namun, penelitian tersebut belum mencakup inferensi Machine Learning (ML) end-to-end in-kernel.

Di sisi lain, deteksi DDoS berbasis ML dalam literatur secara konsisten mencatatkan akurasi di atas 99% [9], [10]. Namun, kajian sistematis oleh Mittal dkk. dan Pattnaik dkk. mengkritik dominasi evaluasi secara offline yang performanya cenderung berfluktuasi di lingkungan produksi real-time [9], [10]. Integrasi ML langsung ke dalam data plane kernel berbasis eBPF mulai diadopsi sebagai solusi mitigasi berlatensi rendah. Pendekatan in-kernel execution ini terbukti berhasil mengeksekusi model ringan seperti Decision Tree (DT) berbasis reduksi fitur ANOVA F-test [11], hingga model Multi-Layer Perceptron (MLP) melalui konversi pustaka emlearn [12], maupun optimasi kuantisasi fixed-point pada perangkat keras komoditas [13].

Penelitian lain yang dilakukan oleh Erskine serta Gaol dkk. masih berjalan di user space menggunakan skrip Python yang memicu overhead tinggi [14], [15]. Keterbatasan tersebut menjadikan pendekatan eBPF/XDP dengan integrasi ML di tingkat kernel relevan sebagai solusi mitigasi dengan overhead dan latensi rendah.

Berdasarkan permasalahan dan celah penelitian yang telah diidentifikasi, proyek akhir ini bertujuan untuk merancang dan mengimplementasikan Sistem Deteksi dan Mitigasi DDoS Menggunakan ML Berbasis eBPF/XDP pada jaringan 10 Gigabit Ethernet (10GbE). Sistem yang diusulkan mengintegrasikan pemrosesan paket native XDP untuk cakupan lapisan Link Layer hingga Transport Layer, model supervised ML yang dijalankan pada kernel space dengan emlearn, serta mekanisme mitigasi bertingkat adaptif. Kinerja sistem kemudian dievaluasi secara komprehensif melalui perbandingan dengan Suricata, Snort 3, nftables, dan eBPF rule-based.

## 1.2 Permasalahan

Berdasarkan latar belakang di atas, permasalahan dalam proyek akhir ini adalah sebagai berikut:

1. Bagaimana merancang dan mengimplementasikan sistem deteksi dan mitigasi DDoS berbasis eBPF/XDP yang mampu memproses trafik secara inline pada Link Layer, Internet Layer, dan Transport Layer di jaringan 10GbE dengan latensi pemrosesan paket (*packet processing latency*) yang rendah?

2. Bagaimana memilih dan mengimplementasikan model ML yang dijalankan di dalam kernel menggunakan emlearn untuk mendeteksi berbagai jenis serangan DDoS pada Link Layer (ARP Flood), Internet Layer (ICMP Flood), dan Transport Layer (SYN Flood, UDP Flood, DNS Amplification) secara real-time dengan akurasi tinggi dan penggunaan sumber daya yang efisien?

3. Bagaimana efektivitas sistem yang diusulkan dibandingkan dengan solusi keamanan jaringan konvensional (Suricata, Snort 3, nftables, dan eBPF rule-based) dalam hal akurasi deteksi, latensi, utilisasi CPU, dan throughput maksimum dalam skenario serangan DDoS pada Link Layer, Internet Layer, dan Transport Layer?

## 1.3 Tujuan

Tujuan dari proyek akhir ini adalah sebagai berikut:

1. Merancang dan mengimplementasikan sistem deteksi dan mitigasi DDoS berbasis eBPF/XDP pada lingkungan bare metal yang terhubung melalui jaringan 10GbE, mencakup pemrosesan paket pada Link Layer (ARP Flood), Internet Layer (ICMP Flood), dan Transport Layer (SYN Flood, UDP Flood, DNS Amplification) dengan mekanisme mitigasi bertingkat (PASS, DROP, BLACKLIST, THROTTLE).
2. Mengembangkan dan membandingkan beberapa model supervised learning ML (DT, RF, MLP) menggunakan dataset CIC-DDoS2019, kemudian mengonversi setiap model ke kode C menggunakan emlearn untuk dieksekusi in-kernel pada program eBPF guna membandingkan performanya.
3. Mengevaluasi dan membandingkan performa sistem yang diusulkan secara bertahap pada lingkungan virtualisasi dan bare metal 10GbE menggunakan skenario serta metrik pengujian yang identik. Evaluasi dilakukan melalui perbandingan dengan Suricata, Snort 3, nftables, dan eBPF rule-based untuk memperoleh benchmark yang konsisten serta mengidentifikasi *breaking point* sistem pada throughput yang lebih tinggi.

## 1.4 Batasan Masalah

Batasan masalah pada proyek akhir ini adalah sebagai berikut:

1. Penelitian difokuskan pada deteksi dan mitigasi serangan DDoS menggunakan teknologi eBPF/XDP.
2. Jenis serangan DDoS dibatasi pada ARP Flood, ICMP Flood, SYN Flood, UDP Flood, dan DNS Amplification, dengan skenario pengujian menggunakan karakteristik alamat sumber yang sesuai dengan masing-masing jenis serangan.
3. Pembahasan difokuskan pada pemrosesan paket pada lapisan Link Layer, Internet Layer, dan Transport Layer, sehingga tidak mencakup serangan pada lapisan aplikasi.
4. Pengujian dibatasi pada lingkungan virtual dan bare metal untuk mengevaluasi kemampuan deteksi, mitigasi, dan performa sistem.

## 1.5 Manfaat

Manfaat dari proyek akhir ini adalah sebagai berikut:

1. **Bagi administrator dan praktisi jaringan**, proyek akhir ini diharapkan menghasilkan sistem Network Intrusion Prevention System (NIPS) berbasis eBPF/XDP yang mampu mendeteksi dan memitigasi serangan DDoS pada Link Layer hingga Transport Layer secara real-time pada jaringan 10GbE dengan overhead rendah. Hal ini memberikan opsi implementasi keamanan jaringan yang teruji dan lebih efisien dibandingkan dengan solusi keamanan jaringan konvensional.
2. **Bagi peneliti dan akademisi**, proyek akhir ini diharapkan memberikan kontribusi berupa kerangka implementasi ML in-kernel menggunakan eBPF dengan cakupan arsitektur TCP/IP. Penelitian ini juga menyajikan hasil evaluasi komparatif antar model ML dalam klasifikasi serangan DDoS multiclass, serta metodologi pengujian bertahap dari lingkungan virtual hingga bare metal 10GbE. Selain itu, panduan praktis mengenai *constraint* library emlearn agar lolos eBPF verifier turut disajikan sebagai referensi bagi penelitian lanjutan.

## 1.6 Sistematika Penulisan

Tahap ini menjelaskan sistematika penulisan laporan berdasarkan penelitian, pembuatan sistem, serta analisis yang telah dilakukan. Penjelasan tentang sistematika penulisan dalam buku proyek akhir meliputi:

| Bab | Judul | Deskripsi |
|---|---|---|
| Bab 1 | Pendahuluan | Berisi latar belakang, permasalahan, tujuan, batasan masalah, manfaat, dan sistematika penulisan proyek akhir. |
| Bab 2 | Kajian Pustaka | Berisi teori-teori penunjang dan tinjauan penelitian terkait yang menjadi dasar penelitian. |
| Bab 3 | Desain Sistem | Berisi rancangan arsitektur, komponen, dan skenario pengujian sistem yang akan dibangun. |
| Bab 4 | Eksperimen dan Analisis | Berisi hasil pengujian sistem beserta analisisnya. |
| Bab 5 | Penutup | Berisi kesimpulan dan saran untuk pengembangan penelitian selanjutnya. |

---

# BAB 2 KAJIAN PUSTAKA

Bab ini memaparkan landasan teoritis yang mendasari penelitian, mencakup deskripsi permasalahan, konsep-konsep dasar meliputi serangan DDoS, teknologi eBPF/XDP, ML, metrik evaluasi yang digunakan, serta tinjauan penelitian terkait.

## 2.1 Deskripsi Permasalahan

Kapasitas jaringan modern yang terus melonjak menuntut sistem mitigasi DDoS berkinerja tinggi. Pada jaringan 10GbE yang menjadi target proyek akhir ini, volume trafik masif memicu bottleneck pada infrastruktur dan sistem keamanan [6], [16]. Akibatnya, tantangan utama bukan lagi sekadar mengenali pola serangan, melainkan menjaga efisiensi sistem di bawah laju trafik ekstrem [6], [16].

Kompleksitas bertambah karena serangan DDoS mengeksploitasi berbagai lapisan protokol dengan karakteristik berbeda [10]. Serangan seperti ARP Flood, ICMP Flood, SYN Flood, UDP Flood, dan DNS Amplification, beroperasi pada Link Layer, Internet Layer, dan Transport Layer [10]. IPS user space konvensional seperti Snort dan Suricata mampu mendeteksi serangan dalam kondisi normal. Namun, pada trafik bervolume tinggi, arsitektur tersebut rentan mengalami *resource exhaustion* yang meningkatkan latensi dan membebani CPU [16], [17].

Guna mengatasi keterbatasan tersebut, diperlukan mekanisme penyaringan trafik sebelum paket menyentuh network stack sistem operasi. Teknologi eBPF/XDP mampu memindahkan pemrosesan paket ke level kernel (*in-kernel*), sehingga keputusan drop atau pass dapat diambil pada titik paling awal jalur penerimaan paket [8], [16]. Selain itu, model ML ringan terbukti dapat diintegrasikan langsung ke lingkungan eBPF tanpa mengorbankan kecepatan pemrosesan [11], [12]. Dengan demikian, proyek akhir ini berfokus pada perancangan sistem deteksi dan mitigasi DDoS berbasis eBPF/XDP yang mengintegrasikan inferensi ML secara in-kernel, untuk menangani trafik real-time pada jaringan 10GbE.

## 2.2 Teori Penunjang

### 2.2.1 Distributed Denial of Service (DDoS)

Distributed Denial of Service (DDoS) merupakan serangan siber yang melumpuhkan ketersediaan layanan dengan membanjiri target menggunakan trafik dari banyak sumber secara bersamaan. Berbeda dari Denial of Service (DoS), DDoS mengoordinasikan banyak perangkat secara terdistribusi sehingga infrastruktur jaringan yang kewalahan akan gagal merespons permintaan trafik normal [10].

Serangan DDoS diklasifikasikan berdasarkan lapisan protokol yang dieksploitasi serta jenis sumber daya target yang dihabiskan, seperti bandwidth (serangan volumetrik) atau kapasitas koneksi (serangan berbasis protokol) [10]. Proyek akhir ini berfokus pada lima jenis serangan berikut.

**a. ARP Flood (Link Layer)**

ARP Flood membanjiri jaringan lokal dengan paket Address Resolution Protocol (ARP) dalam jumlah besar untuk membebani perangkat target serta memicu kongesti [18]. Karena ARP beroperasi tanpa mekanisme enkripsi maupun autentikasi, setiap perangkat yang terhubung ke jaringan dapat mengirimkan paket ARP palsu dengan biaya komputasi rendah di sisi penyerang, sementara sifat broadcast ARP dalam satu segmen jaringan menyebabkan volume paket kecil pun tersebar ke seluruh host [18]. Setiap paket yang diterima memaksa perangkat memperbarui ARP table-nya, sehingga volume tinggi menyebabkan ARP table exhaustion dan menguras siklus CPU untuk parsing serta lookup [18]. Mitigasi konvensional seperti Dynamic ARP Inspection (DAI) pada managed switch dinilai kurang fleksibel karena sangat bergantung pada infrastruktur jaringan yang mahal [18].

Karena beroperasi dalam satu segmen jaringan lokal (*local broadcast domain*), dampak ARP flood terbatas pada perangkat di segmen yang sama dengan penyerang [18]. Paket ARP tidak diteruskan lintas segmen oleh router, sehingga router sebagai gateway menjadi target utama sekaligus titik kritis yang harus dilindungi [18]. Kegagalan router akibat serangan ini akan menghentikan penerusan lalu lintas data ke seluruh perangkat di bawahnya, sehingga mengganggu ketersediaan (*availability*) jaringan secara keseluruhan [18].

**b. ICMP Flood (Internet Layer)**

ICMP Flood membanjiri target dengan paket Internet Control Message Protocol (ICMP) untuk menguras bandwidth jaringan [10]. Rentetan paket ini memaksa target memproses trafik secara terus-menerus hingga buffer memori penuh dan pengguna sah tidak lagi dapat dilayani [2]. Mitigasi konvensional umumnya hanya mengandalkan pemblokiran pada edge firewall atau IDS/IPS tradisional [2].

**c. SYN Flood (Transport Layer)**

SYN Flood merupakan serangan berbasis protokol (*protocol/semantic attack*) yang mengeksploitasi kelemahan proses three-way handshake pada TCP [19], [20]. Penyerang membanjiri target dengan paket SYN secara terus-menerus tanpa pernah mengirimkan paket respons ACK untuk menyelesaikan koneksi [20]. Akibatnya, antrean koneksi server terisi penuh oleh *half-open connection* yang menguras sumber daya sistem, sehingga pengguna sah tidak dapat lagi dilayani [19].

**d. UDP Flood (Transport Layer)**

UDP Flood mengirimkan paket User Datagram Protocol (UDP) dalam jumlah besar untuk membanjiri kapasitas serta sumber daya jaringan target [8]. Karena UDP bersifat *connectionless*, target terpaksa memproses setiap trafik acak yang masuk hingga bandwidth jaringan terkuras habis. Beban komputasi yang ekstrem dan terus-menerus ini pada akhirnya menyebabkan server mengalami kolaps [10].

**e. DNS Amplification (Transport Layer)**

DNS Amplification memanfaatkan kerentanan *open DNS resolvers* untuk melipatgandakan volume trafik target [10]. Dalam skema ini, penyerang menggunakan botnet untuk mengirim kueri kecil (seperti tipe ANY) dengan memalsukan (*spoofing*) alamat IP korban, yang kemudian dibalas oleh server DNS dengan ukuran respons jauh lebih besar hingga secara efektif menguras habis kapasitas bandwidth target [21]. Pada proyek akhir ini, deteksi DNS Amplification difokuskan pada pola volumetrik dan rasio ukuran paket di Transport Layer, tanpa melakukan inspeksi payload DNS.

### 2.2.2 extended Berkeley Packet Filter (eBPF)

**a. Arsitektur eBPF**

Arsitektur eBPF terbagi atas user space dan kernel space seperti yang ditunjukkan Gambar 2.1. Program eBPF ditulis dalam restricted C, dikompilasi menggunakan LLVM/Clang menjadi bytecode, lalu dimuat ke kernel melalui system call `bpf()` menggunakan pustaka loader seperti libbpf [23], [24]. Bytecode yang dimuat harus melewati verifikasi terlebih dahulu sebelum dijalankan. eBPF verifier memeriksa keamanan program secara statis, mencakup validasi akses memori, deteksi potensi crash, dan kepastian bahwa program selalu berjalan hingga selesai tanpa loop tak terbatas [24], [25]. Setelah lolos, JIT compiler menerjemahkan bytecode menjadi instruksi mesin spesifik sehingga program eBPF berjalan seefisien kode kernel native [24].

> **Gambar 2.1** Arsitektur Umum eBPF
> *Sumber: https://ebpf.io/what-is-ebpf/*

Program eBPF tidak memanggil fungsi kernel secara langsung karena akan mengikat program pada versi kernel tertentu. Kernel menyediakan helper functions sebagai API stabil untuk mengakses layanan kernel seperti pembacaan waktu sistem, akses BPF maps, dan manipulasi paket jaringan [23], [24]. Untuk kebutuhan logika yang lebih kompleks, eBPF mendukung tail call dan function call sehingga satu program dapat memanggil program atau fungsi eBPF lain secara modular [24], [26].

**b. BPF Maps**

BPF Maps merupakan struktur data key-value yang tersimpan di kernel dan tetap persisten meskipun program eBPF yang mengaksesnya telah selesai dieksekusi, sehingga memungkinkan pertukaran data antara program eBPF di kernel space dan aplikasi di user space [23], [24], [25]. Kernel Linux menyediakan beberapa tipe map sesuai kebutuhan, seperti Array untuk akses berbasis indeks, Hash Table untuk pencarian berbasis kunci, LRU untuk data yang otomatis tergusur saat penuh, dan Ring Buffer untuk mengirim data ke user space tanpa memblokir eksekusi kernel [24], [26]. Untuk mengatasi konflik penulisan saat satu antarmuka diproses oleh banyak core CPU melalui RSS, tersedia varian PERCPU_ARRAY dan PERCPU_HASH yang menyimpan salinan data terpisah per core [25], [26]. Pemilihan tipe map pada sistem ini dibahas lebih lanjut pada Subbab 3.2.2.

### 2.2.3 eXpress Data Path (XDP)

XDP merupakan mekanisme pemrosesan paket berperforma tinggi pada Linux yang memungkinkan program eBPF dijalankan langsung di driver jaringan, sebelum paket memasuki Linux networking stack [22], [23], [26].

**a. Jalur Pemrosesan XDP**

> **Gambar 2.2** XDP dalam Jalur Pemrosesan Paket Linux
> *Sumber: Gai (2020)*

Gambar 2.2 menunjukkan posisi XDP dalam jalur pemrosesan paket Linux. Ketika NIC menerima paket, program XDP dieksekusi segera setelah paket keluar dari receive queue di driver jaringan, sebelum paket dibungkus ke dalam struktur socket buffer (SKB) yang lebih mahal secara komputasi untuk dialokasikan [22], [26]. Kemampuan XDP mengambil keputusan sebelum tahap alokasi SKB ini memberikan keuntungan performa yang signifikan pada trafik berkecepatan tinggi, karena paket belum menyentuh struktur data yang lebih berat tersebut [22], [26]. Program XDP juga dapat membaca dan memodifikasi isi paket secara langsung sebelum diteruskan ke tahap berikutnya, menjadikannya pilihan utama untuk filtering, load balancing, dan mitigasi DDoS [22], [26].

**b. Mode XDP**

XDP menyediakan tiga mode operasi yang berbeda dalam hal lokasi eksekusi dan tingkat dukungan driver yang dibutuhkan, yaitu Generic, Native, dan Hardware Offload [26].

- **Generic XDP** tidak membutuhkan dukungan driver khusus karena program dieksekusi setelah SKB dialokasikan. Mode ini ditujukan untuk pengujian dan pengembangan, bukan untuk lingkungan produksi [26].
- **Native XDP** mengeksekusi program pada jalur penerimaan paling awal di dalam driver, sebelum SKB dialokasikan, sehingga memberikan latensi paling rendah di antara mode yang berjalan pada CPU host [26]. Mode ini membutuhkan dukungan eksplisit dari driver NIC. Driver ixgbe yang digunakan NIC Intel X540-T2 telah mendukung Native XDP sejak kernel versi 4.12 [26].
- **Hardware Offload** mengeksekusi program langsung pada hardware NIC sehingga memindahkan seluruh biaya pemrosesan dari CPU host. Mode ini hanya didukung oleh SmartNIC dengan prosesor khusus, dan saat penulisan ini hanya tersedia melalui driver nfp dari Netronome maupun arsitektur SmartNIC modern lainnya [26].

Pemilihan mode operasi XDP untuk sistem ini dibahas pada Subbab 3.2.2.

**c. XDP Actions**

Program XDP mengembalikan salah satu dari lima action code yang didefinisikan pada header `linux/bpf.h`, yaitu `XDP_ABORTED`, `XDP_DROP`, `XDP_PASS`, `XDP_TX`, dan `XDP_REDIRECT`. Kode ini menjadi instruksi bagi driver NIC mengenai cara memproses paket setelah eksekusi program XDP selesai [26].

`XDP_DROP` membuang paket langsung pada level driver tanpa alokasi resource tambahan, menjadikannya pilihan utama untuk mitigasi DDoS dan firewalling. `XDP_PASS` meneruskan paket ke networking stack Linux untuk diproses secara normal. `XDP_TX` mentransmisikan kembali paket keluar melalui NIC yang sama, umumnya digunakan pada skenario load balancing hairpin. `XDP_REDIRECT` mengalihkan paket ke NIC lain atau ke BPF cpumap untuk diproses core CPU lain. `XDP_ABORTED` menandakan kondisi exception pada program dan secara perilaku setara dengan `XDP_DROP`, namun memicu tracepoint `trace_xdp_exception` yang dapat dimonitor untuk mendeteksi malfungsi [26].

Pemilihan action code yang diterapkan pada setiap kondisi klasifikasi dalam sistem ini dibahas lebih lanjut pada Subbab 3.2.2.

### 2.2.4 Machine Learning

Machine learning (ML) memungkinkan sistem membangun model prediksi berbasis pola data historis untuk mengambil keputusan secara otomatis terhadap data baru, tanpa memerlukan aturan yang didefinisikan secara eksplisit oleh manusia [1]. Dalam konteks deteksi DDoS, ML umumnya digunakan untuk mengklasifikasikan trafik jaringan ke dalam kelas normal maupun satu atau beberapa jenis kelas serangan berdasarkan vektor fitur yang diekstraksi dari statistik trafik [1], [2]. Pendekatan ini banyak diadopsi karena metode deteksi berbasis aturan statis (*rule-based*) tidak selalu memadai dalam menghadapi pola serangan yang bervariasi maupun berlangsung singkat [1].

Berdasarkan ketersediaan label pada data pelatihan, ML terbagi menjadi supervised learning, unsupervised learning, dan semi-supervised learning [2]. Pembahasan pada subbab ini difokuskan pada supervised learning beserta tiga algoritma yang relevan dengan konteks in-kernel execution, yaitu DT, RF, dan MLP, yang masing-masing memiliki karakteristik struktur, kompleksitas komputasi, dan representasi numerik berbeda ketika dikonversi untuk berjalan pada lingkungan dengan sumber daya terbatas seperti eBPF [11], [12], [13].

**a. Supervised Learning**

Supervised learning merupakan metode pembelajaran ML yang menggunakan data berlabel sebagai acuan dalam proses pelatihan model [2]. Pada pendekatan ini, sistem dilatih menggunakan dataset untuk mengidentifikasi hubungan antara variabel masukan dan keluaran melalui penyesuaian parameter serta fungsi pemetaan [2]. Setelah proses pelatihan selesai, model dapat digunakan untuk melakukan prediksi terhadap data baru.

**b. Decision Tree**

Decision Tree (DT) merupakan algoritma klasifikasi supervised learning yang memetakan proses pengambilan keputusan ke dalam struktur pohon yang terdiri atas root node, internal node, dan leaf node [2], [27]. Setiap internal node membandingkan satu fitur terhadap threshold hingga mencapai leaf node yang menyimpan label kelas [11]. Struktur if-then hasil konversi DT relatif sejalan dengan representasi kode C dari emlearn, karena kompleksitas inferensinya hanya O(kedalaman pohon) [11]. Karena representasi ini murni berupa perbandingan nilai dan percabangan logis tanpa operasi floating-point, DT maupun RF pada umumnya dapat direpresentasikan langsung sebagai struktur if-else pada lingkungan in-kernel tanpa modifikasi tipe data [11], berbeda dengan model neural network seperti MLP yang memerlukan kuantisasi manual dari floating-point ke integer akibat larangan operasi floating-point pada eBPF verifier [13].

**c. Random Forest**

Random Forest (RF) merupakan metode ensemble learning yang membangun sekumpulan DT melalui bootstrap sampling dan mekanisme keacakan tambahan dalam pembentukan tiap pohon [21], dengan hasil klasifikasi akhir ditentukan melalui majority voting [1], [10]. Dibandingkan DT tunggal, RF lebih robust terhadap overfitting [10], [15], namun kompleksitas inferensinya meningkat menjadi O(n_estimators × max_depth) karena setiap pohon harus dievaluasi secara independen saat prediksi. Pada implementasi in-kernel, karakteristik ini berimplikasi langsung terhadap ukuran kode hasil konversi. Karena jumlah (n_estimators) dan kedalaman (max_depth) pohon berkorelasi linier dengan ukuran kode biner hasil konversi, kedua hyperparameter ini dibatasi secara eksplisit agar total instruksi tidak melampaui batas verifikasi eBPF. Batasan nilai yang digunakan dibahas pada Subbab 3.2.4.

**d. Multi-Layer Perceptron**

Multi-Layer Perceptron (MLP) merupakan metode klasifikasi artificial neural network yang tersusun atas input layer, satu atau lebih hidden layer, dan output layer, dengan proses feedforward mengalikan input dengan bobot dan melewatkannya melalui fungsi aktivasi pada setiap neuron [12], [13]. Struktur berlapis ini memungkinkan MLP menangkap hubungan non-linear antar fitur yang berpotensi memberikan performa lebih tinggi dibandingkan model berbasis pohon pada data yang kompleks [12].

Namun, eBPF verifier melarang operasi floating-point sehingga seluruh bobot dan aktivasi harus direpresentasikan dalam integer sebelum dieksekusi in-kernel. Hara dan Sasabe [35] menunjukkan bahwa kuantisasi int8 (NN-int8) menurunkan recall secara signifikan akibat presisi yang hilang pada proses quantize-dequantize berulang di tiap layer. Mengikuti pendekatan Zhang dkk. [13], keterbatasan tersebut diatasi menggunakan representasi fixed-point berbasis int32 dengan skema *enlargement factor* untuk menjaga akurasi sekaligus mencegah overflow komputasi. Skema ini menjadi acuan konversi MLP pada proyek akhir ini. Selain presisi numerik, ukuran arsitektur MLP (jumlah hidden layer dan neuron) membatasi jumlah operasi feedforward dan instruksi biner, sehingga pemilihan arsitektur harus menyeimbangkan akurasi dengan batas verifier eBPF. Rincian arsitektur dan kuantisasi ini dibahas pada Subbab 3.2.4.

**e. Inferensi**

Inferensi merupakan tahap ketika model ML yang telah dilatih digunakan untuk mengklasifikasikan data baru berdasarkan pola yang dipelajari, tanpa lagi memperbarui parameter model [20]. Secara umum, DT dan RF menentukan kelas berdasarkan hasil traversal pohon (leaf node untuk DT, majority voting antar pohon untuk RF), sedangkan MLP melalui operasi argmax terhadap nilai output layer [11], [12], [13]. Selain akurasi klasifikasi, efisiensi inference dalam hal latensi dan penggunaan instruksi BPF menjadi pertimbangan utama dalam pemilihan dan konfigurasi model, sebagaimana dibahas lebih lanjut pada Subbab 3.2.2 dan 3.2.4.

### 2.2.5 Emlearn

emlearn merupakan pustaka (library) Python bersifat open-source yang dirancang untuk mengonversi model ML yang telah dilatih menggunakan scikit-learn menjadi representasi kode C statis, sehingga model dapat dieksekusi pada lingkungan dengan sumber daya terbatas tanpa bergantung pada runtime Python maupun pustaka numerik seperti NumPy [12]. Karakteristik inilah yang menjadikan emlearn relevan digunakan pada proyek akhir ini sebagai jembatan antara proses pelatihan model di user space menggunakan scikit-learn dan proses inferensi yang dieksekusi secara in-kernel pada program eBPF/XDP, karena kode C yang dihasilkan bersifat self-contained, deterministik, dan tidak memiliki dependensi eksternal yang dapat melanggar batasan eBPF verifier.

**a. Konversi Model scikit-learn ke Kode C**

emlearn menyediakan fungsi `emlearn.convert()` yang mengonversi model scikit-learn terlatih menjadi file header (.h) berisi kode inferensi dalam bahasa C, dengan representasi berbeda sesuai jenis model: struktur if-else chain terhadap threshold integer untuk DT dan RF yang identik dengan proses traversal pohon aslinya, serta operasi matrix multiplication berbasis floating-point untuk MLP yang merepresentasikan feedforward antar layer, sebelum dikuantisasi manual ke int32 sebagaimana dibahas pada bagian selanjutnya [12]. Kode C hasil konversi kemudian di-include ke dalam source code program eBPF dan dikompilasi bersama menggunakan Clang/LLVM, sehingga seluruh parameter model tertanam sebagai konstanta statis tanpa memerlukan struktur data dinamis tambahan seperti BPF Maps [11].

**b. Constraint eBPF Verifier**

eBPF verifier menerapkan tiga batasan utama yang relevan dengan implementasi model ML. Operasi floating-point dilarang, unbounded loop dilarang, dan pointer arithmetic dibatasi ketat [22], [23], [25]. Ketiga batasan ini bertentangan dengan karakteristik default scikit-learn yang menggunakan float64 serta struktur loop pada inferensi RF dan MLP, sehingga model tidak dapat langsung dimuat ke program eBPF tanpa modifikasi [11].

Untuk DT dan RF, emlearn menangani ketiga batasan secara otomatis dengan mengonversi threshold ke integer dan meng-unroll traversal pohon menjadi kode if-else statis. Untuk MLP, mekanisme otomatis ini tidak berlaku. Pengujian pada emlearn versi 0.23.2 menunjukkan bobot dan bias tetap dihasilkan dalam floating-point, sehingga kuantisasi ke int32 dilakukan secara manual sebelum kode disertakan ke program eBPF, mengikuti pendekatan Zhang dkk. [13]. Ketiga model menghasilkan kode fixed-size yang dipastikan tidak melampaui batas 1 juta instruksi BPF sejak kernel 5.2 [28]. Batasan hyperparameter spesifik yang diterapkan pada proyek akhir ini untuk menjaga kepatuhan terhadap batas ini dibahas pada Subbab 3.2.4.

### 2.2.6 Pendekatan Window-Based

Selain pendekatan flow-based, beberapa penelitian mengusulkan pendekatan window-based, yaitu ekstraksi fitur dari sekumpulan paket dalam interval waktu tetap tanpa menunggu flow berakhir. Li dkk. [20] menunjukkan bahwa pendekatan ini dapat mengurangi overhead dan latensi deteksi dengan akurasi yang tetap terjaga, sedangkan Halladay dkk. [21] membuktikan efektivitas fitur berbasis waktu untuk klasifikasi multiclass berbagai jenis serangan DDoS. Proyek akhir ini mengadopsi pendekatan tersebut dengan `window_ns` sebagai parameter yang dapat dikonfigurasi.

### 2.2.7 Heavy Hitter

Heavy hitter merupakan aliran atau sumber trafik yang mendominasi volume lalu lintas jaringan pada suatu interval pengamatan. Liu dkk. [29] memanfaatkan Universal Sketch untuk mengidentifikasi heavy hitters secara line-rate dan mendukung konfigurasi mekanisme mitigasi secara dinamis tanpa memuat ulang program. Proyek akhir ini mengadaptasi prinsip tersebut melalui seleksi Top-N IP dengan volume trafik tertinggi pada setiap window sebagai kandidat inferensi ML, sementara parameter mitigasi dapat diubah melalui `system_config` tanpa reload program.

### 2.2.8 Dataset

Dataset utama yang digunakan adalah CIC-DDoS2019 dari Canadian Institute for Cybersecurity, yang menyediakan trafik normal serta berbagai jenis serangan DDoS dalam format PCAP dan CSV hasil ekstraksi CICFlowMeter [5], [15]. Karena fitur bawaan CICFlowMeter bersifat flow-based dan tidak sesuai dengan kebutuhan penelitian, ekstraksi fitur dilakukan secara mandiri dari data PCAP. Untuk melengkapi kelas serangan yang tidak tersedia pada CIC-DDoS2019, yaitu ARP Flood dan ICMP Flood, kedua jenis trafik tersebut dibangkitkan secara mandiri sehingga seluruh kelas klasifikasi dapat direpresentasikan. Detail proses ekstraksi fitur dan pembangkitan trafik dijelaskan pada Bab 3.

### 2.2.9 Metrik Evaluasi

Untuk mengukur kinerja model ML dan sistem yang dikembangkan, proyek akhir ini menggunakan metrik evaluasi yang mencakup aspek klasifikasi dan performa sistem. Proses deteksi dilakukan menggunakan pendekatan klasifikasi multiclass terhadap enam kelas, yaitu trafik normal, ARP Flood, ICMP Flood, SYN Flood, UDP Flood, dan DNS Amplification, dengan confusion matrix berukuran 6×6 yang kemudian direduksi menjadi representasi biner 2×2 melalui pendekatan one-vs-rest, yaitu menggabungkan seluruh kelas serangan menjadi satu kelompok "Attack" dan kelas normal sebagai "Normal", sehingga metrik berbasis perspektif biner seperti False Positive Rate (FPR), True Negative Rate (TNR), dan Attack Detection Rate (ADR) dapat dihitung secara konsisten [30].

**a. Confusion Matrix**

Confusion matrix merupakan salah satu metode evaluasi yang digunakan untuk menganalisis hasil klasifikasi dengan membandingkan label hasil prediksi dari model ML [14]. Matriks ini memberikan informasi mengenai jumlah data yang berhasil diklasifikasikan dengan benar maupun jumlah data yang mengalami kesalahan klasifikasi [9]. Pada proyek akhir ini, confusion matrix yang digunakan berukuran 6×6 sesuai dengan jumlah kelas yang diklasifikasikan. Setiap baris menunjukkan kelas aktual, sedangkan setiap kolom menunjukkan kelas hasil prediksi model, sehingga elemen diagonal matriks merepresentasikan prediksi yang benar untuk setiap kelas.

**Tabel 2.1** Confusion Matrix 6x6 Multiclass

| Actual \ Pred | Normal | ARP flood | ICMP flood | SYN flood | UDP flood | DNS amp. |
|---|---|---|---|---|---|---|
| Normal | C₁₁ | C₁₂ | C₁₃ | C₁₄ | C₁₅ | C₁₆ |
| ARP flood | C₂₁ | C₂₂ | C₂₃ | C₂₄ | C₂₅ | C₂₆ |
| ICMP flood | C₃₁ | C₃₂ | C₃₃ | C₃₄ | C₃₅ | C₃₆ |
| SYN flood | C₄₁ | C₄₂ | C₄₃ | C₄₄ | C₄₅ | C₄₆ |
| UDP flood | C₅₁ | C₅₂ | C₅₃ | C₅₄ | C₅₅ | C₅₆ |
| DNS amp. | C₆₁ | C₆₂ | C₆₃ | C₆₄ | C₆₅ | C₆₆ |

Cᵢᵢ pada diagonal merepresentasikan sampel kelas *i* yang diklasifikasikan dengan benar, sedangkan Cᵢⱼ dengan *i ≠ j* merepresentasikan sampel kelas *i* yang keliru diklasifikasikan sebagai kelas *j*. Dari confusion matrix 6×6 tersebut, parameter dasar evaluasi klasifikasi berupa True Positive (TP), True Negative (TN), False Positive (FP), dan False Negative (FN) diperoleh menggunakan pendekatan one-vs-rest. Untuk keperluan perhitungan metrik berbasis perspektif biner seperti FPR, TNR, dan ADR, seluruh lima kelas serangan digabungkan menjadi satu kelompok "Attack" sebagai kelas positif, sedangkan kelompok "Normal" menjadi kelas negatif, sehingga trafik serangan yang berhasil terdeteksi dikategorikan sebagai TP dan trafik normal yang berhasil dikenali dikategorikan sebagai TN [30]. Representasi confusion matrix biner yang digunakan dalam proyek akhir ini ditunjukkan pada Tabel 2.2.

**Tabel 2.2** Confusion Matrix Binary

| | Predicted Normal | Predicted Attack |
|---|---|---|
| **Actual Normal** | True Negative (TN) | False Positive (FP) |
| **Actual Attack** | False Negative (FN) | True Positive (TP) |

**b. Accuracy**

Accuracy merupakan metrik evaluasi yang mengukur rasio prediksi benar terhadap seluruh data pengujian, sehingga memberikan gambaran keseluruhan kemampuan model dalam mengklasifikasikan seluruh kelas trafik [13], [14].

Pada klasifikasi multiclass, prediksi yang benar direpresentasikan oleh elemen diagonal matriks (Cᵢᵢ) pada Tabel 2.1, yaitu C₁₁, C₂₂, C₃₃, C₄₄, C₅₅, dan C₆₆, sedangkan jumlah seluruh sampel pengujian diperoleh dari penjumlahan seluruh elemen confusion matrix. Perhitungan accuracy dinyatakan pada Persamaan 2.1.

$$Accuracy = \frac{\sum_{i=1}^{6} C_{ii}}{\sum_{i=1}^{6}\sum_{j=1}^{6} C_{ij}} \tag{2.1}$$

Dengan Σ Cᵢᵢ menyatakan jumlah seluruh elemen diagonal yang merepresentasikan prediksi benar untuk setiap kelas, sedangkan Σ Σ Cᵢⱼ menyatakan jumlah seluruh sampel pada confusion matrix.

**c. Precision**

Precision merupakan metrik yang mengukur proporsi prediksi positif yang benar-benar termasuk dalam kelas yang diprediksi, sehingga nilai precision yang tinggi mencerminkan kemampuan model dalam meminimalkan false alarm [14], [27]. Precision untuk kelas ke-i dihitung berdasarkan perbandingan antara jumlah TPᵢ dan total prediksi positif, dinyatakan pada Persamaan 2.2.

$$Precision_i = \frac{TP_i}{TP_i + FP_i} \tag{2.2}$$

Dengan TPᵢ menyatakan jumlah sampel kelas ke-i yang berhasil diprediksi dengan benar, sedangkan FPᵢ menyatakan jumlah sampel dari kelas lain yang keliru diprediksi sebagai kelas ke-i. Dalam proyek akhir ini, precision dihitung menggunakan macro-average, yaitu rata-rata nilai precision dari seluruh kelas dengan bobot yang sama [15].

**d. Recall**

Recall merupakan metrik yang mengukur proporsi sampel aktual suatu kelas yang berhasil dikenali dengan benar oleh model, sehingga nilai recall yang rendah mengindikasikan masih terdapat sampel yang keliru dikategorikan sebagai FN [14]. Recall untuk kelas ke-i dinyatakan pada Persamaan 2.3.

$$Recall_i = \frac{TP_i}{TP_i + FN_i} \tag{2.3}$$

Dengan TPᵢ menyatakan jumlah sampel kelas ke-i yang berhasil diprediksi dengan benar, sedangkan FNᵢ menyatakan jumlah sampel kelas ke-i yang keliru diprediksi sebagai kelas lain.

**e. F1 Score**

F1 Score merupakan harmonic mean dari precision dan recall, sehingga nilai F1 yang tinggi hanya dapat dicapai apabila keduanya tinggi secara bersamaan [31].

$$F1_i = \frac{2 \times Precision_i \times Recall_i}{Precision_i + Recall_i} \tag{2.4}$$

Dengan Precisionᵢ dan Recallᵢ masing-masing menyatakan nilai precision dan recall untuk kelas ke-i. Dalam proyek akhir ini, nilai precision, recall, dan F1 Score dilaporkan menggunakan macro-average, yaitu rata-rata dari nilai per kelas dengan bobot yang sama, agar performa model terevaluasi secara setara terhadap seluruh jenis serangan tanpa terpengaruh perbedaan jumlah sampel antar kelas [15].

**f. FPR**

False Positive Rate (FPR) mengukur proporsi trafik normal yang keliru diklasifikasikan sebagai serangan, sehingga nilai FPR yang tinggi mengindikasikan sistem sering menghasilkan false alarm yang dapat menurunkan kepercayaan terhadap hasil deteksi [5], [8]. Pada proyek akhir ini, FPR dihitung menggunakan confusion matrix biner pada Tabel 2.2, dinyatakan pada Persamaan 2.5.

$$FPR = \frac{FP}{FP + TN} \tag{2.5}$$

Dengan FP menyatakan jumlah trafik normal yang keliru diprediksi sebagai serangan, sedangkan TN menyatakan jumlah trafik normal yang berhasil diprediksi dengan benar.

**g. TNR**

True Negative Rate (TNR) mengukur proporsi trafik normal yang berhasil diklasifikasikan dengan benar, sehingga nilai TNR yang tinggi menunjukkan sistem tidak cenderung memblokir trafik sah [5], [8]. Secara matematis, TNR merupakan komplemen langsung dari FPR dan diturunkan dari Persamaan 2.5, dinyatakan pada Persamaan 2.6.

$$TNR = \frac{TN}{TN + FP} = 1 - FPR \tag{2.6}$$

Dengan TN menyatakan jumlah trafik normal yang berhasil diprediksi dengan benar, sedangkan FP menyatakan jumlah trafik normal yang keliru diprediksi sebagai serangan. Pada proyek akhir ini, TNR digunakan bersama FPR untuk menggambarkan secara lengkap kemampuan sistem dalam menangani trafik normal.

**h. ADR**

Attack Detection Rate (ADR) mengukur proporsi keseluruhan trafik serangan yang berhasil dideteksi sebagai serangan dari seluruh trafik serangan yang masuk [8]. Berbeda dengan recall yang dihitung per kelas secara terpisah, ADR menggabungkan seluruh kelas serangan menjadi satu kelompok tunggal "Attack". Setiap serangan yang diprediksi sebagai jenis serangan apa pun tetap dihitung sebagai True Positive (TP), selama tidak terdeteksi sebagai Normal. Hal ini konsisten dengan definisi TP biner (Tabel 2.2) yang hanya mensyaratkan trafik dikenali sebagai serangan, tanpa memedulikan ketepatan subklasifikasinya. Perhitungan ADR menggunakan confusion matrix biner pada Tabel 2.2 dan confusion matrix 6×6 pada Tabel 2.1, dinyatakan pada Persamaan 2.7.

$$ADR = \frac{TP}{TP + FN} = \frac{\sum_{i=2}^{6}\sum_{j=2}^{6} C_{ij}}{\sum_{i=2}^{6}\sum_{j=1}^{6} C_{ij}} \tag{2.7}$$

Dengan TP mencakup seluruh sampel serangan aktual (baris 2–6) yang diprediksi sebagai kelas serangan apa pun (kolom 2–6), tanpa memedulikan ketepatan jenisnya. Penyebut TP+FN menyatakan total populasi seluruh kelas serangan. Konsekuensinya, FN pada ADR hanya terjadi ketika trafik serangan keliru diprediksi sebagai Normal (Σ Cᵢ₁), bukan saat serangan salah diklasifikasikan ke jenis serangan lain.

**i. Throughput**

Throughput mengukur kemampuan sistem dalam memproses sejumlah paket atau data dalam satu satuan waktu, sehingga mencerminkan kapasitas sistem dalam menangani beban trafik sebelum terjadi penurunan kinerja [11], [13], [16]. Throughput dapat dinyatakan dalam dua bentuk, yaitu berbasis paket dan berbasis data, masing-masing dinyatakan pada Persamaan 2.8 dan 2.9.

$$Throughput_{packet} = \frac{TotalPackets}{Duration} \tag{2.8}$$

Dengan TotalPackets menyatakan jumlah paket yang berhasil diproses selama periode pengamatan dan Duration menyatakan lama waktu pengamatan. Nilai throughput berbasis paket dinyatakan dalam satuan packets per second (pps) atau million packets per second (Mpps).

$$Throughput_{data} = \frac{TotalData}{Duration} \tag{2.9}$$

Dengan TotalData menyatakan jumlah data yang berhasil diproses selama periode pengamatan. Nilai throughput berbasis data dinyatakan dalam satuan bps, Mbps, atau Gbps.

**j. Latensi Pemrosesan (Processing Latency)**

Latensi pemrosesan mengukur waktu yang dibutuhkan program XDP untuk menghasilkan keputusan terhadap satu paket [8], [27]. Nilai ini dihitung secara terpisah untuk Fast Path dan Slow Path karena kedua jalur memiliki kompleksitas komputasi yang berbeda. Pada Fast Path, latensi pemrosesan merepresentasikan waktu satu operasi lookup ke `mitigation_state`. Pada Slow Path, latensi pemrosesan merepresentasikan waktu pembaruan counter pada `ip_window_stats` dan `hll_registers`, tanpa menunggu hasil inferensi ML, karena inferensi dijalankan secara asinkron oleh BPF Timer di akhir window dan tidak menjadi bagian dari waktu pemrosesan per-paket. Perhitungan latensi pemrosesan dinyatakan pada Persamaan 2.10.

$$Processing\ Latency = t_{end} - t_{start} \tag{2.10}$$

Dengan t_start menyatakan waktu ketika paket mulai diproses oleh program eBPF/XDP, sedangkan t_end menyatakan waktu ketika program XDP mengembalikan action code untuk paket tersebut, tanpa mencakup waktu eksekusi BPF Timer yang berjalan secara independen dari jalur pemrosesan paket.

**k. Latensi Jaringan (Network Latency)**

Latensi jaringan merupakan total waktu tempuh paket dari pengirim hingga diterima penerima, yang tersusun atas empat komponen di setiap simpul yang dilalui: processing delay (pemrosesan header di node), queuing delay (waktu tunggu di buffer), transmission delay (waktu mendorong seluruh bit paket ke link), dan propagation delay (waktu rambat sinyal sepanjang media transmisi) [36]. Perhitungan latensi jaringan dinyatakan pada Persamaan 2.11.

$$Network\ Latency = t_{rx} - t_{tx} \tag{2.11}$$

Dengan t_rx menyatakan waktu paket mulai dikirim dan t_tx menyatakan waktu paket selesai diterima. Latensi jaringan bersifat independen terhadap latensi pemrosesan (poin j) karena XDP baru dieksekusi setelah paket tiba di antarmuka. Parameter ini tetap diuji terpisah karena memengaruhi laju kedatangan paket per `window_ns` yang menjadi input klasifikasi ML (Subbab 3.3.5).

**l. CPU Utilization**

CPU Utilization mengukur tingkat penggunaan sumber daya CPU selama sistem berjalan, sehingga menjadi indikator efisiensi implementasi pada lingkungan eBPF/XDP yang dirancang untuk memiliki overhead rendah [8], [13], [16]. Perhitungan CPU Utilization dinyatakan pada Persamaan 2.12.

$$CPU\ Utilization = \frac{CPUTimeUsed}{TotalCPUTime} \times 100\% \tag{2.12}$$

Dengan CPUTimeUsed menyatakan waktu penggunaan CPU oleh sistem selama periode pengamatan, sedangkan TotalCPUTime menyatakan total waktu CPU yang tersedia pada periode sama. Nilai CPU Utilization dinyatakan dalam satuan persen (%).

**m. Time-to-Mitigation**

Time-to-Mitigation (TTM) mengukur durasi antara paket pertama dari suatu alamat sumber serangan hingga aksi mitigasi pertama kali diterapkan terhadap alamat tersebut, selaras dengan konsep reaction time pada mitigasi DDoS berbasis data plane [29]. Perhitungan TTM dinyatakan pada Persamaan 2.13.

$$TTM = t_{mitigation} - t_{entry} \tag{2.13}$$

Dengan t_entry menyatakan waktu paket pertama dari `src_ip` serangan tercatat pada Slow Path, sedangkan t_mitigation menyatakan waktu `mitigation_state[src_ip]` pertama kali berubah menjadi THROTTLE, BLACKLIST, atau DROP. TTM dipengaruhi langsung oleh `window_ns`, karena mitigasi baru diterapkan setelah window pertama menghasilkan klasifikasi.

## 2.3 Penelitian Terkait

Penelitian terdahulu yang menggabungkan eBPF/XDP dengan ML untuk deteksi serangan jaringan dapat dikelompokkan berdasarkan lokasi inferensi, mulai dari user space hingga in-kernel penuh, sebagaimana dirangkum pada Tabel 2.3. Pengelompokan ini menjadi dasar tinjauan pada empat subbab berikut.

**a. Deteksi ML Berbasis User Space**

Ali [32] mengusulkan kerangka federated learning untuk IDS pada jaringan industrial, mencapai akurasi 99,98% dengan RF, namun tidak menyebutkan eksekusi in-kernel sama sekali. Ali dan Karam [27] membandingkan DT, RF, K-Nearest Neighbor (KNN), dan MLP untuk IPS real-time, dan menemukan bahwa KNN membutuhkan waktu deteksi hingga 800 ms yang tidak sesuai untuk skenario real-time, sementara MLP pada konfigurasinya hanya mencapai akurasi 64%. Erskine [14], Gaol dkk. [15], dan Toyin dkk. [17] masing-masing mengintegrasikan model ML dengan mekanisme mitigasi otomatis berbasis iptables atau Wazuh Security Information and Event Management (SIEM), tetapi ketiganya tetap bergantung pada pemrosesan paket di level user space, sehingga rentan terhadap resource exhaustion pada volume trafik tinggi sebagaimana telah dijelaskan pada Subbab 2.1.

**b. Pemrosesan Paket eBPF/XDP tanpa ML**

Athallah [6] mereplikasi firewall berbasis XDP dan menunjukkan penurunan waktu kernel dari 12,44% menjadi 4,84% dibandingkan iptables pada lingkungan cloud. Machnicki dkk. [16] mengembangkan Sapo-boi, NIDS berbasis pattern-matching Aho-Corasick yang mencatat packet loss 2,23% pada 10Gbps, jauh lebih rendah dibandingkan Suricata (9,61%) dan Snort (91,70%) pada kondisi 16.000 aturan. Soldani dkk. [7] membangun Sauron, platform observability eBPF untuk cloud-native telco yang independen protokol tanpa plugin tambahan, namun fokusnya murni pada pengumpulan data dan tidak menyertakan komponen klasifikasi apa pun. Ketiga penelitian ini membuktikan keunggulan throughput dan fleksibilitas eBPF/XDP dibandingkan solusi konvensional, tetapi tidak satu pun memiliki kemampuan klasifikasi yang adaptif terhadap pola serangan yang berubah.

**c. Integrasi eBPF dan ML secara Hybrid**

Farasat dkk. [31] pada SmartX Intelligent Sec mengakui secara eksplisit bahwa modul deteksi Bidirectional Long Short-Term Memory (BiLSTM) mereka beroperasi di level user space, meskipun blocking paket dilakukan melalui XDP. Remya dkk. [8] pada CODAX menempatkan RF sebagai post-filter setelah deteksi semantik berbasis tracepoint syscall. Hadi dkk. [5] pada iKern mengklaim algoritma deteksinya berjalan di dalam kernel dan melibatkan ML untuk mengklasifikasikan trafik yang tidak langsung terindikasi sebagai serangan volumetrik. Namun, paper tersebut tidak menyebutkan algoritma ML yang digunakan, dan arsitekturnya tidak konsisten apakah klasifikasi benar-benar dieksekusi di kernel space atau di proses user space yang membaca ring buffer PF_RING, ambiguitas yang membuat iKern sulit dijadikan pembanding langsung untuk klaim eksekusi in-kernel.

**d. Inferensi ML In-Kernel Penuh**

Zhang dkk. [13] menjalankan Neural Network terkuantisasi int32 melalui rangkaian tail calls eBPF dengan waktu inferensi 3.000–5.000 ns per flow, tetapi deteksi hanya dilakukan pada akhir flow, sehingga tidak menjangkau intrusi yang terjadi selama koneksi persisten. Gallego-Madrid dkk. [12] membuktikan MLP dapat berjalan in-kernel dengan penurunan waktu eksekusi 97%, namun pengujian terbatas pada skenario IoT 6LowPAN dengan throughput maksimum hanya 43–44 Mbps, jauh di bawah skala 10 Gigabit. Anand dkk. [11] mengeksekusi DT dan RF pada level socket filter dengan 10–15 fitur teratas hasil seleksi ANOVA F-test, namun secara eksplisit menyatakan representasi fixed-point tidak dapat diterapkan pada model non-linear seperti Neural Network dan XGBoost.

Pada pendekatan lain, Taguchi dkk. [33] mencapai throughput 224 Kpps per core menggunakan Autoencoder in-kernel, meski pendekatan unsupervised ini ditujukan untuk deteksi anomali biner, bukan klasifikasi multiclass terhadap jenis serangan spesifik. Einsfeldt dkk. [34] memecah algoritma genetik menjadi tahapan per paket melalui tail calls untuk ekstraksi fitur in-kernel, tetapi fokusnya terbatas pada reduksi dimensi fitur, bukan klasifikasi dan mitigasi serangan end-to-end.

Dari seluruh penelitian pada Tabel 2.3, belum ditemukan sistem yang menggabungkan keempat aspek berikut dalam satu arsitektur: cakupan deteksi Link Layer hingga Transport Layer, inferensi ML in-kernel penuh untuk klasifikasi multiclass, mitigasi bertingkat (throttle dan blacklist sementara), serta pengujian bare metal 10 Gigabit dengan solusi keamanan jaringan konvensional pada testbed yang sama.

Prinsip pembatasan analisis pada sumber trafik dominan sendiri bukan hal baru. Liu dkk. [29] menerapkan prinsip tersebut melalui heavy hitters berbasis sketch pada programmable switch untuk mengarahkan mitigasi volumetric DDoS dalam sistem Jaqen. Namun, kombinasi seleksi IP dominan ini dengan inferensi ML multiclass in-kernel penuh melalui BPF Timer belum dijumpai pada penelitian yang ditinjau, sebagai strategi menjaga waktu eksekusi tetap terkendali tanpa mengorbankan cakupan mitigasi. Efektivitasnya akan dievaluasi lebih lanjut pada Bab 4.

Berdasarkan celah tersebut, proyek akhir ini diposisikan untuk mengintegrasikan keempat aspek tersebut sekaligus mengevaluasi kinerja dan efektivitasnya secara menyeluruh.

**Tabel 2.3** Komparasi Penelitian Terkait

> *Catatan: tabel komparasi pada dokumen sumber berupa gambar/tabel kompleks yang tidak dapat diekstrak sebagai teks oleh proses konversi otomatis. Silakan merujuk ke halaman 26 dokumen PDF asli untuk melihat tabel ini secara lengkap.*

---

# BAB 3 DESAIN SISTEM

## 3.1 Deskripsi Solusi

Tinjauan pada Subbab 2.3 mengidentifikasi empat celah yang belum terpenuhi secara serentak oleh penelitian in-kernel sebelumnya, yaitu cakupan deteksi pada Link Layer hingga Transport Layer, inferensi ML in-kernel penuh untuk klasifikasi multiclass, mitigasi bertingkat, serta pengujian bare metal 10 Gigabit dengan pembanding IPS konvensional pada testbed yang sama [11], [12], [13]. Proyek akhir ini mengusulkan NIPS berbasis eBPF/XDP yang mengintegrasikan keempat aspek tersebut dalam satu arsitektur.

Sistem beroperasi sebagai inline middlebox yang memproses paket di level driver jaringan menggunakan XDP sebelum paket menyentuh Linux networking stack, sehingga keputusan mitigasi dapat diambil lebih awal dibandingkan IPS berbasis user space seperti Suricata dan Snort pada volume trafik tinggi [16]. Pemrosesan paket dibagi menjadi fast path (satu hash lookup untuk paket dengan state mitigasi yang sudah diketahui) dan slow path (pembaruan counter fitur per-paket, diikuti agregasi lintas-CPU dan inferensi ML in-kernel oleh BPF Timer di akhir tiap time window). Hasil klasifikasi diterjemahkan menjadi mitigasi bertingkat (PASS, THROTTLE, BLACKLIST, DROP), dengan rincian mekanisme dan mode operasi dibahas pada Subbab 3.2.2 dan 3.2.5.

Evaluasi dilakukan secara bertahap pada lingkungan virtual (Generic dan Native XDP) serta bare metal (NIC Intel X540-T2, Native XDP, pada koneksi 10GbE), dibandingkan terhadap Suricata, Snort 3, nftables, dan eBPF rule-based. Rincian topologi, skenario, dan sistem pembanding dibahas pada Subbab 3.2.7 dan 3.3.

## 3.2 Perancangan Sistem

### 3.2.1 Arsitektur Sistem

Sistem terdiri dari tiga node yang terhubung secara inline. Node 1 berperan sebagai traffic generator sekaligus attacker, Node 3 sebagai server target, dan Node 2 sebagai NIPS yang ditempatkan di antara keduanya sehingga seluruh trafik dari Node 1 ke Node 3 wajib melewati Node 2. Program XDP di-attach pada kedua antarmuka Node 2, baik yang menghadap Node 1 maupun Node 3, sehingga paket pada kedua arah trafik diproses pada level driver jaringan sebelum naik ke Linux networking stack. Detail topologi ketiga node ditunjukkan pada Gambar 3.4 dan Gambar 3.5 (Subbab 3.3.1).

> **Gambar 3.1** Arsitektur Sistem
> *(diagram alur pemrosesan paket dan struktur BPF maps Node 2 — lihat halaman 28 dokumen asli)*

Node 2 beroperasi sebagai router pada Internet Layer yang menghubungkan segmen jaringan Node 1 dan Node 3 pada subnet berbeda. Konsekuensinya, mitigasi terhadap ARP Flood (Link Layer) bertujuan melindungi ketersediaan Node 2 sebagai gateway. Langkah tersebut secara tidak langsung turut menjaga konektivitas Node 3 terhadap jaringan luar. Kondisi ini berbeda dengan keempat jenis serangan lain (Internet dan Transport Layer) yang diteruskan hingga ke Node 3 dan dimitigasi secara langsung di antarmuka yang menghadap Node 3.

Gambar 3.1 menunjukkan arsitektur internal Node 2, mencakup alur pemrosesan paket dan struktur BPF maps yang digunakan. Paket diproses melalui tiga tingkat berurutan. **Trusted Check** memeriksa `src_ip` terhadap whitelist `trusted_cidr` dan meneruskannya langsung bila cocok. **Fast Path** menangani paket yang state mitigasinya sudah tercatat melalui satu operasi lookup tanpa komputasi tambahan. **Slow Path** menangani paket dari sumber yang belum tercatat, memperbarui counter fitur untuk kebutuhan klasifikasi ML dan keputusan mitigasi. Pemisahan tingkat ini menjaga latensi Trusted Check dan Fast Path tetap konstan meski kompleksitas Slow Path lebih tinggi. Detail ketiga tingkat, struktur BPF maps, dan logika mitigasi bertingkat dibahas pada Subbab 3.2.2 dan 3.2.5.

Node 2 memisahkan control plane dari data plane. Seluruh keputusan inline (Trusted Check, Fast Path, Slow Path, klasifikasi ML) dijalankan di kernel space tanpa keterlibatan user space per-paket maupun per-window, sedangkan user space berperan sebagai control plane untuk konfigurasi dan monitoring sebagaimana dijelaskan pada Subbab 3.2.6. Parameter operasional diubah melalui BPF maps tanpa reload program, termasuk `op_mode` pada `system_config` yang menentukan mode operasi. Sistem menyediakan tiga mode, yaitu mode penuh (Fast Path dan ML aktif bersamaan), mode ML-only (Fast Path dinonaktifkan untuk isolasi pengukuran inferensi), dan mode Fast Path-only (ML dinonaktifkan, berfungsi sebagai baseline eBPF rule-based).

### 3.2.2 Perancangan eBPF/XDP

**a. Mode XDP dan Konfigurasi Driver**

Program XDP pada proyek akhir ini dijalankan dalam tiga konfigurasi untuk mengisolasi pengaruh mode eksekusi dan jenis hardware secara terpisah. Konfigurasi **VM-Generic** menjalankan Generic XDP pada virtual machine, menjadi baseline yang merepresentasikan kondisi umum infrastruktur virtualisasi tanpa dukungan native. Konfigurasi **VM-Native** menjalankan Native XDP pada virtual machine yang sama, memungkinkan pengukuran pengaruh mode eksekusi secara terisolasi karena hardware yang digunakan identik dengan konfigurasi VM-Generic. Konfigurasi **Bare metal-Native** menjalankan Native XDP pada NIC Intel X540-T2 di jaringan 10 Gigabit, memungkinkan pengukuran pengaruh hardware secara terisolasi karena mode eksekusi yang digunakan identik dengan konfigurasi VM-Native.

Dukungan Native XDP pada driver vmxnet3 dikonfirmasi tersedia pada kernel 6.8.0-107-generic dengan versi driver 1.7.0.0-k-NAPI melalui pengujian langsung menggunakan mode `xdpdrv`, yang memaksa pemuatan program pada mode native tanpa fallback ke generic. Dukungan ini relatif baru dan tidak tersedia secara luas pada kernel versi lebih lama, sehingga konfigurasi VM-Generic tetap relevan dipertahankan untuk merepresentasikan kondisi infrastruktur virtualisasi yang lebih umum digunakan.

**Tabel 3.1** Konfigurasi Mode Eksekusi XDP

| Parameter | VM-Generic | VM-Native | Bare metal-Native |
|---|---|---|---|
| Titik eksekusi | Setelah alokasi SKB | Sebelum alokasi SKB | Sebelum alokasi SKB |
| Driver | vmxnet3 | vmxnet3 | ixgbe (X540-T2) |
| Variabel terisolasi | Baseline | Mode eksekusi | Hardware |
| Tujuan | Representasi VM umum | Selisih Generic vs Native | Performa 10 Gbps |

**b. Desain BPF Maps**

Sistem menggunakan delapan BPF maps yang dipilih berdasarkan pola akses masing-masing komponen. Kedelapan map ini melayani dua jalur pemrosesan: **Jalur A** (Packet Path, per-paket), yang mencakup ketiga tingkat pemrosesan pada Subbab 3.2.1, dan **Jalur B** (Periodic Path, per-window) yang dijalankan oleh BPF Timer.

`trusted_cidr` menggunakan LPM_TRIE untuk pencarian berbasis prefix IP/CIDR. `mitigation_state` menggunakan LRU_HASH dengan `bpf_spin_lock` pada field `tokens` dan `last_refill_ns` untuk menjaga konsistensi saat token bucket THROTTLE didekremen dari banyak core secara bersamaan. Tipe per-CPU tidak dapat digunakan di sini karena akan menggandakan kuota secara proporsional dengan jumlah core [24], [25]. `ip_window_stats` menggunakan LRU_PERCPU_HASH dan `hll_registers` menggunakan PERCPU_ARRAY, keduanya agar penyimpanan counter dan register HyperLogLog bersifat per-core tanpa kontensi saat satu antarmuka diproses banyak core melalui RSS. `ip_window_stats` juga mendapat auto-eviction otomatis di bawah tekanan memori, berbeda dari PERCPU_HASH biasa yang hanya gagal saat insert ketika map penuh [26].

Dua map tambahan mendukung Jalur B. `top_ips` menggunakan ARRAY sebagai scratch space untuk daftar top-N IP paling aktif per window. Map ini sengaja dipisahkan dari stack frame BPF Timer karena batas MAX_BPF_STACK sebesar 512 byte akan membatasi N maksimal hanya pada puluhan entri apabila disimpan sebagai variabel lokal [25], [26]. `timer_ctrl` menggunakan ARRAY satu slot untuk struktur `bpf_timer`. `alert_events` menggunakan RINGBUF agar user space dapat membaca event secara reaktif lewat epoll. `system_config` menggunakan ARRAY karena hanya membutuhkan satu slot data global. Ukuran `max_entries` pada `mitigation_state` ditetapkan sebesar 8192, memberikan headroom sekitar 64 window penuh turnover sebelum eviction LRU menjadi faktor signifikan. Rincian kedelapan map ditunjukkan pada Tabel 3.2.

**Tabel 3.2** Konfigurasi BPF Maps

| Map | Tipe | Key / Value | Penulis | Pembaca |
|---|---|---|---|---|
| `trusted_cidr` | LPM_TRIE | prefix+addr / flag u8 | User | XDP Tkt. 1 |
| `mitigation_state` | LRU_HASH | src_ip / mit_entry + spin_lock | XDP, Timer, User | XDP Tkt. 2 |
| `ip_window_stats` | LRU_PERCPU_HASH | src_ip / 7 counter per-core | XDP Tkt. 3 | Timer |
| `hll_registers` | PERCPU_ARRAY | idx 0-255 / reg. HLL u8 | XDP Tkt. 3 | Timer |
| `top_ips` | ARRAY | slot 0-127 / src_ip + pkt_count | Timer | Timer |
| `timer_ctrl` | ARRAY | slot 0 / bpf_timer | Init program | Kernel |
| `system_config` | ARRAY | slot 0 / sys_config | User | XDP, Timer |
| `alert_events` | RINGBUF | - / alert_entry | Timer | User space (epoll) |

**c. Pemrosesan Paket dan Pemetaan Action Code**

Ketiga tingkat pada Subbab 3.2.1 bersifat berurutan dan tidak tumpang tindih. Setiap paket hanya melewati satu tingkat hingga mendapatkan keputusan akhir.

- **Tingkat 1 (Trusted Check)** memeriksa `src_ip` terhadap `trusted_cidr` dan meneruskan paket langsung via `XDP_PASS` tanpa menyentuh map lain. Pemeriksaan ini sengaja dijadikan gerbang pertama agar selalu menang atas entri lama pada `mitigation_state`, membuat sistem bersifat self-healing terhadap perubahan trusted list.
- **Tingkat 2 (Fast Path)** membaca aksi tersimpan pada `mitigation_state`. PASS diteruskan sebagai `XDP_PASS`, THROTTLE diperiksa ketersediaan tokennya dengan `bpf_spin_lock`, dan BLACKLIST dijatuhkan sebagai `XDP_DROP`. Entri yang `expire_ns`-nya telah terlampaui diperlakukan sebagai cache-miss dan dilanjutkan ke Tingkat 3.
- **Tingkat 3 (Slow Path)** menangani IP yang belum tercatat atau entrinya kedaluwarsa. Paket UDP port 53 yang melampaui `dns_max_bytes` langsung dikenai `XDP_DROP` tanpa pencatatan state karena `src_ip`-nya bersifat spoofed. Paket lainnya memperbarui tujuh counter pada `ip_window_stats` dan register HyperLogLog pada `hll_registers` sebelum diteruskan sebagai `XDP_PASS` hingga window berikutnya menghasilkan klasifikasi.

Keputusan klasifikasi dihasilkan sepenuhnya oleh Jalur B (BPF Timer) di akhir setiap `window_ns`. Timer mengiterasi `ip_window_stats` via `bpf_for_each_map_elem` untuk mengagregasi counter lintas-core per `src_ip` menggunakan bounded loop sejumlah core (bukan `bpf_loop`, karena jumlah core adalah konstanta kecil dengan batas atas yang pasti), mempertahankan daftar N = 128 IP paling aktif pada `top_ips`, lalu menjalankan inferensi ML via `bpf_loop` hanya terhadap N IP teratas tersebut dan menuliskan hasilnya ke `mitigation_state` sesuai Tabel 3.3. Nilai N = 128 didasarkan pada estimasi waktu eksekusi sekitar 13 hingga 38 mikrodetik (128 inferensi dikali 100-300 ns per inferensi), jauh di bawah durasi window default 1 detik, selaras dengan prinsip seleksi heavy hitters pada Subbab 2.2.7, dan akan divalidasi lebih lanjut menggunakan `bpftool` pada tahap implementasi. Logika eskalasi THROTTLE menjadi BLACKLIST dijelaskan pada Subbab 3.2.5. Detail langkah demi langkah tiap tahap pada Jalur B (Timer Aggregate, ML Inference, dan Update State) dijelaskan lebih lanjut pada Subbab 3.2.2d.

Sebagai jaring pengaman terhadap serangan yang terdistribusi ke banyak alamat sumber dengan volume rendah per IP, sistem menyediakan mekanisme fallback `flood_active`. Mekanisme ini aktif apabila estimasi Unique Source IP global melampaui `unique_ip_threshold` sementara volume trafik IP teratas pada `top_ips` berada di bawah `dominant_ip_min`, dan menerapkan blanket rate-limit per protokol/port pada Tingkat 3 sebagai pengganti sementara mitigasi per-IP. Cakupan implementasinya dinyatakan pada Subbab 1.4.

**Tabel 3.3** Action Code

| Kelas | Action Code |
|---|---|
| Normal | PASS |
| ARP/ICMP/SYN/UDP Flood | THROTTLE → BLACKLIST |
| DNS Amplification (Tingkat 3) | DROP |
| DNS Amplification (ML) | DROP |

**d. Detail Algoritma Jalur B**

Jalur B (Periodic Path) pada Gambar 3.1 terdiri atas tiga kotak yang dieksekusi berurutan oleh `bpf_timer` di akhir setiap `window_ns`, yaitu Timer Aggregate, ML Inference, dan Update State.

**▪ Timer Aggregate**

Kotak ini menggabungkan data yang tersebar di banyak core CPU akibat struktur per-CPU map yang dipakai untuk menghindari kontensi saat RSS mendistribusikan paket ke banyak core (lihat Subbab 3.2.2b), menjadi satu kesatuan statistik per alamat IP sumber.

```
Algoritma Timer Aggregate
Input  : Peta ip_window_stats dan hll_registers per-core, jumlah_core
Output : Estimasi unique_ip global dan daftar top_ips (128 entri)

1. Untuk setiap core CPU dari 0 sampai (jumlah_core − 1), lakukan:
      Untuk setiap entri src_ip pada ip_window_stats milik core tersebut,
      tambahkan packet_count, byte_count, arp_count, syn_count, udp_count,
      icmp_count, dan dns_count ke hasil_gabungan[src_ip]
2. Untuk setiap core CPU, gabungkan hll_registers milik core tersebut ke
   register HyperLogLog global dengan aturan ambil nilai maksimum per indeks
3. Hitung estimasi_unique_ip dari register HyperLogLog global
4. Urutkan hasil_gabungan berdasarkan packet_count secara menurun
5. Ambil 128 entri teratas sebagai top_ips
6. Tulis top_ips ke BPF map top_ips
```

Langkah 1 dan 2 menggunakan bounded loop sejumlah core CPU, bukan `bpf_loop`, karena jumlah core adalah konstanta kecil dengan batas atas pasti.

**▪ ML Inference**

Kotak ini dieksekusi setelah Timer Aggregate selesai, hanya terhadap 128 IP pada `top_ips` sesuai pembatasan heavy hitter yang telah dijelaskan pada Subbab 3.2.2c, bukan seluruh IP yang tercatat pada `ip_window_stats`.

```
Algoritma ML Inference
Input  : Daftar top_ips (128 entri), estimasi_unique_ip,
         system_config.active_model
Output : Pasangan (src_ip, kelas_prediksi) diteruskan ke Update State,
         serta alert_events untuk IP yang terklasifikasi sebagai serangan

1. Baca model_aktif dari system_config.active_model (DT, RF, atau MLP)
2. Untuk setiap entri ip pada top_ips, lakukan:
     a. Susun vektor_fitur dari packet rate, byte rate, arp_count,
        syn_count, udp_count, icmp_count, dns_count, average packet size,
        dan estimasi_unique_ip
     b. Jalankan inferensi model_aktif terhadap vektor_fitur, hasilkan
        kelas_prediksi
     c. Jika kelas_prediksi bukan Normal, tulis event (src_ip, kelas_prediksi,
        window_id, timestamp) ke alert_events
     d. Kirim pasangan (src_ip, kelas_prediksi) ke Update State
```

Langkah 2 menggunakan `bpf_loop`, berbeda dari Timer Aggregate, karena jumlah iterasinya tetap sebesar N = 128 sesuai desain pada Subbab 3.2.2c.

**▪ Update State**

Kotak terakhir menuliskan hasil klasifikasi ke `mitigation_state`, sekaligus menjalankan logika eskalasi bertingkat yang telah dijelaskan secara naratif pada Subbab 3.2.5.

```
Algoritma Update State
Input  : Pasangan (src_ip, kelas_prediksi) dari ML Inference,
         BPF map mitigation_state
Output : mitigation_state terbarui, timer untuk window berikutnya dimulai

1. Untuk setiap pasangan (src_ip, kelas_prediksi), lakukan:
     a. Baca entri mitigation_state[src_ip], buat entri baru jika belum ada
     b. Jika kelas_prediksi = Normal, tetapkan action = PASS,
        expire_ns = waktu sekarang + (3 × window_ns), dan
        consecutive_windows = 0
     c. Jika kelas_prediksi ≠ Normal:
          - Jika last_class = kelas_prediksi, tambahkan 1 ke
            consecutive_windows; jika tidak, tetapkan consecutive_windows = 1
            dan perbarui last_class
          - Jika kelas_prediksi = DNS Amplification, tetapkan action = DROP
          - Jika tidak dan consecutive_windows ≥ escalate_windows, tetapkan
            action = BLACKLIST dan expire_ns = waktu sekarang + blacklist_ns
          - Jika tidak, tetapkan action = THROTTLE, tokens = throttle_burst,
            dan expire_ns = waktu sekarang + window_ns
     d. Tulis entri ke mitigation_state[src_ip]
2. Mulai timer untuk window_ns berikutnya
```

Logika `consecutive_windows` pada langkah 1c mengimplementasikan mekanisme eskalasi THROTTLE ke BLACKLIST yang telah dijelaskan pada Subbab 3.2.5.

### 3.2.3 Perancangan Feature Extraction

Pemilihan kesembilan fitur ini didasarkan pada tiga kriteria yang diterapkan secara bersamaan.

- **Ekstraktabilitas in-kernel.** Seluruh fitur dapat dihitung secara inkremental per-paket di dalam program XDP tanpa memerlukan struktur data dinamis yang melanggar batasan eBPF verifier, yakni hanya menggunakan operasi integer sederhana pada counter di BPF maps.
- **Relevansi diskriminatif per kelas.** Setiap serangan yang menjadi fokus sistem memiliki setidaknya satu fitur yang secara teoritis dominan, yaitu ARP Count untuk ARP Flood, SYN Count untuk SYN Flood, ICMP Count untuk ICMP Flood, serta UDP Count dan DNS Count untuk UDP Flood dan DNS Amplification, sehingga vektor fitur memiliki struktur yang selaras dengan taksonomi kelas.
- **Kelengkapan cakupan lapisan.** Kombinasi fitur per-IP dan fitur global (Unique Source IP) memungkinkan sistem membedakan serangan flooding dari satu sumber versus serangan terdistribusi dari banyak sumber, yang merupakan karakteristik pembeda antara DoS dan DDoS.

Fitur Unique Source IP secara khusus ditambahkan sebagai sinyal global karena fitur ini tidak dapat diwakili oleh counter per-IP manapun. Sumber trafik yang bervariasi tinggi dalam satu window mengindikasikan serangan refleksi atau amplifikasi. Validitas pemilihan fitur ini dievaluasi lebih lanjut menggunakan feature importance dari model RF dan analisis korelasi Pearson pada tahap Feature Validation dalam pipeline persiapan dataset (Gambar 3.2).

**a. Pipeline Ekstraksi Fitur untuk Data Pelatihan**

Pipeline ekstraksi fitur offline dirancang menghasilkan dataset pelatihan dengan representasi fitur identik dengan vektor fitur in-kernel saat inferensi real-time, sebagaimana ditunjukkan pada Gambar 3.2 dan Tabel 3.4.

**Tabel 3.4** Rancangan Feature Extraction

| Type | Features |
|---|---|
| Per-IP | Packet Rate, Byte Rate, ARP Count, SYN Count, UDP Count, ICMP Count, DNS Count, Average Packet Size |
| Global | Unique Source IP |

Data bersumber dari PCAP CIC-DDoS2019 untuk kelas Normal, SYN Flood, UDP Flood, dan DNS Amplification, serta trafik ARP Flood dan ICMP Flood yang dibangkitkan langsung menggunakan fitur stateless packet crafting pada TRex, kemudian disimpan sebagai PCAP melalui mode simulasi TRex (`stl-sim`) sebelum diproses oleh pipeline yang sama. Pipeline membaca PCAP menggunakan `dpkt` dan menghitung kedelapan fitur per-IP per window berukuran tetap sesuai `window_ns`, sedangkan Unique Source IP diestimasi menggunakan HyperLogLog yang implementasinya identik dengan versi in-kernel. Label ditetapkan per window menggunakan majority label, dengan window bercampuran yang tidak memenuhi threshold mayoritas dibuang dari dataset.

Sebelum digunakan untuk pelatihan, window hasil ekstraksi melalui tahap preprocessing sebagaimana ditunjukkan pada Gambar 3.2. Window bernilai NaN atau infinite dibuang dari dataset. Label kelas dikodekan menjadi enam kategori sesuai Subbab 2.2.9. Nilai fitur tidak dinormalisasi dan tetap direpresentasikan sebagai integer mentah agar konsisten dengan representasi in-kernel yang tidak mendukung operasi floating-point.

**b. Agregasi Fitur In-Kernel untuk Inferensi Real-Time**

Kesembilan fitur diekstraksi sepenuhnya di kernel oleh XDP dan BPF Timer tanpa keterlibatan user space pada jalur inline. Setiap paket pada Slow Path memperbarui tujuh counter mentah per-IP pada `ip_window_stats` (`packet_count`, `byte_count`, `arp_count`, `syn_count`, `udp_count`, `icmp_count`, dan `dns_count`) serta `hll_registers` untuk estimasi Unique Source IP berbasis HyperLogLog per-core tanpa locking. Tiga fitur turunan, yaitu Packet Rate, Byte Rate, dan Average Packet Size, tidak disimpan sebagai counter tersendiri. Ketiganya dihitung dari `packet_count` dan `byte_count` pada tahap agregasi oleh BPF Timer, sehingga total sembilan fitur (delapan per-IP dan satu global) terbentuk saat penyusunan vektor fitur akhir.

Pada akhir setiap window, BPF Timer mengagregasi ketujuh counter `ip_window_stats` dan register `hll_registers` lintas-core untuk mendapatkan estimasi Unique Source IP global, kemudian menyusun vektor fitur dari kombinasi fitur per-IP (termasuk fitur turunan) dan hasil agregasi tersebut untuk IP dengan kontribusi tertinggi. Vektor fitur ini menjadi input inferensi ML sebagaimana dijelaskan pada Subbab 3.2.2c. Seluruh counter pada `ip_window_stats` direset setiap akhir window karena klasifikasi dilakukan murni berdasarkan statistik window yang sedang berjalan, tanpa mempertahankan state lintas-window selain yang sudah tersimpan pada `mitigation_state`. Konsistensi antara pipeline offline dan in-kernel dijamin selama `window_ns` yang dikonfigurasi pada kedua konteks identik.

**c. Window Size**

`window_ns` menentukan trade-off antara stabilitas fitur statistik dan latensi deteksi. Window pendek menghasilkan fitur yang noisy, sedangkan window panjang meningkatkan Time-to-Mitigation karena alamat sumber baru tetap diteruskan tanpa mitigasi hingga window pertama selesai diklasifikasi. Sebagai ilustrasi, pada 10 Gbps dengan ukuran paket minimum, window 1 detik memungkinkan sekitar 14,9 juta paket diteruskan sebelum keputusan klasifikasi pertama.

Proyek akhir ini mengevaluasi window 500 ms, 1 detik, dan 2 detik, dengan 1 detik sebagai nilai default karena serangan volumetrik seperti SYN Flood dan UDP Flood umumnya menghasilkan peningkatan counter signifikan bahkan dalam interval sub-detik. Nilai `window_ns` dapat diubah melalui `system_config` tanpa reload program, sehingga evaluasi sensitivitas dapat dilakukan tanpa modifikasi kode.

Window berdurasi menit lebih relevan untuk mendeteksi pola serangan low-rate atau lapisan aplikasi yang berkembang secara gradual. Pendekatan tersebut justru merugikan pada konteks volumetrik karena memperbesar Time-to-Mitigation (Subbab 2.2.9.m) tanpa memberi keuntungan stabilitas fitur yang signifikan. Kelima serangan yang menjadi fokus penelitian ini tergolong DDoS volumetrik dengan lonjakan rate mendadak, sehingga sudah dapat teridentifikasi dalam skala sub-detik hingga beberapa detik.

### 3.2.4 Perancangan Model Machine Learning

**a. Arsitektur dan Batasan Hyperparameter Model**

Ukuran dan kompleksitas ketiga model (DT, RF, MLP) dibatasi secara eksplisit agar total instruksi hasil konversi emlearn tidak melampaui batas verifikasi eBPF sebagaimana dijelaskan pada Subbab 2.2.5b. Pada DT, pembatasan `max_depth` membatasi pertumbuhan jumlah node hasil konversi. Pada RF, pembatasan `max_depth` dan `n_estimators` dilakukan secara bersamaan karena setiap pohon dikonversi secara independen menjadi kode statis, sehingga kompleksitas total meningkat proporsional terhadap keduanya. Pada MLP, arsitektur dibatasi maksimal 1 hidden layer dengan 16 neuron (9→16→6) atau 2 hidden layer dengan 8 neuron per layer (9→8→8→6) untuk mengendalikan operasi feedforward in-kernel. Dimensi input layer mengikuti ukuran vektor fitur (9 fitur, Subbab 3.2.3) dan output layer mengikuti jumlah kelas klasifikasi (6 kelas, Subbab 2.2.9). Kuantisasi bobot dan bias MLP menggunakan format fixed-point Q14 berbasis int32 (faktor skala 16.384) mengadopsi skema *enlargement factor* dari Zhang dkk. [13] (Subbab 2.2.4d) agar presisi tetap terjaga tanpa risiko integer overflow. Rincian batasan hyperparameter untuk ketiga model ditunjukkan pada Tabel 3.5.

**Tabel 3.5** Constraint Hyperparameter Model dan Karakteristik In-Kernel Verifier

| Model | Parameter | Constraint | Bytecode Inst. | Processed Inst. | Verifier Status | Justifikasi & Karakteristik |
|---|---|---|---|---|---|---|
| DT | max_depth | ≤ 10 (terpilih: 6) | 102 | 403 | PASS (O2/O3) | Membatasi kedalaman nested if-else chain. Sangat hemat instruksi dengan Recall 99.9975%. |
| RF | max_depth, n_estimators | max_depth ≤ 8, n_estimators ≤ 10 (terpilih: d8n3) | 204 | 5.152 | PASS (O2/O3) | Dibatasi bersama karena setiap tree dikonversi independen menjadi struktur pohon statis berbobot voting. |
| MLP | Hidden layers, Neuron/layer | ≤ 16 (1 layer) atau ≤ 8 (2 layer) (terpilih: 1×16) | 338 | 7.139 | PASS (O2/O3) | Operasi feedforward unrolled loop matrix-vector. Fixed-point Q14 menghasilkan FPR 0,0000% pada data uji. |
| MLP | Tipe data bobot | Int32 (Q14) | — | — | PASS | eBPF melarang floating-point; kuantisasi Q14 menjaga stabilitas numerik tanpa overflow. |

**b. Alur Pelatihan, Seleksi Model Dua Tahap, dan Deployment**

Perancangan model ML mengikuti alur pada Gambar 3.2 dan Gambar 3.3. Metodologi pelatihan dan seleksi model pada penelitian ini menerapkan pendekatan dua tahap (*two-stage constrained model selection*) dengan rincian sebagai berikut:

1. **Partisi Data Temporal 80/20 (Locked Test Partition)**: Dataset hasil preprocessing pada Subbab 3.2.3a dibagi berdasarkan urutan waktu kronologis `window_id` menjadi 80% partisi pelatihan dan validasi (train partition) serta 20% partisi pengujian akhir yang dikunci (locked test partition). Pembagian berbasis temporal ini dipilih untuk merefleksikan skenario operasional nyata di mana model dilatih dari jendela waktu historis dan dievaluasi pada jendela waktu mendatang yang belum pernah dilihat, sekaligus mencegah data leakage yang lazim terjadi pada random split.
2. **Grouped Temporal Cross-Validation (StratifiedGroupKFold 5-Fold)**: Pada partisi data latih 80%, validasi silang dilakukan menggunakan `StratifiedGroupKFold` 5-fold dengan pengelompokan berbasis blok temporal 60 detik. Seluruh window dalam satu blok waktu 60 detik dialokasikan ke fold yang sama agar dependensi temporal antar window berdekatan tidak bocor ke fold validasi.
3. **Eksplorasi Skenario Class Weighting**: Untuk mengatasi ketimpangan distribusi trafik antara Normal dan berbagai vektor serangan DDoS, evaluasi mencakup 7 variasi skenario pembobotan kelas: skenario `a` (`class_weight=None`), skenario `b-S1..S3` (`class_weight='balanced'` dipadukan dengan 3 variasi kuota downsampling serangan), dan skenario `c-S1..S3` (dictionary custom weight dipadukan dengan 3 variasi kuota downsampling serangan).
4. **Pipeline Seleksi 2-Tahap dengan Hard Constraint eBPF Verifier (`cv_selection_constrained`)**:
   - *Fase 1 (CV Sweep)*: Menjalankan pelatihan dan validasi silang pada seluruh ruang kombinasi hyperparameter (434 kandidat model yang mencakup variasi arsitektur pohon, kedalaman layer MLP, dan skenario pembobotan) untuk menghitung skor validasi berbasis **macro-average Recall**. Metrik ini diprioritaskan sebagai kriteria seleksi utama karena pada sistem NIPS, kegagalan deteksi (*missed detection*) berakibat jauh lebih destruktif menjenuhkan buffer jaringan dibanding *false alarm* [37], serta untuk mengevaluasi ketahanan deteksi seluruh kelas serangan pada dataset dengan ketimpangan kelas [38].
   - *Fase 2 (Kompilasi C & Verifikasi Kernel)*: Mengonversi seluruh model kandidat menjadi kode C statis (`.h`) menggunakan `emlearn` dan skrip konversi kuantisasi Q14. Masing-masing model dikompilasi ke objek eBPF via Clang/LLVM pada dua level optimasi (`-O2` dan `-O3`), lalu diuji terhadap Linux BPF Verifier menggunakan `bpftool`.
   - *Aturan Seleksi Final*: Kandidat model yang gagal verifikasi eBPF (*verifier FAIL* pada batas stack 512-byte atau batas 1 juta instruksi) langsung didiskualifikasi dari daftar seleksi. Dari kandidat yang lolos (*verifier PASS* di kedua flag optimasi), dipilih satu model dengan skor macro-average Recall CV tertinggi untuk setiap famili arsitektur (DT, RF, MLP).
   - *Evaluasi Terkunci (Locked Evaluation)*: Ketiga model terbaik yang terpilih kemudian dievaluasi pada 20% locked test partition untuk menetapkan performa final offline (Accuracy, Precision, Recall, F1 Score, FPR, TNR, ADR) serta diverifikasi Prediction Agreement Rate-nya guna memastikan kesetaraan 100% antara inferensi C in-kernel dan model Python scikit-learn.

Ketiga model yang lolos validasi dideploy ke dalam modul data plane eBPF, di mana model aktif dapat dipilih dan diganti secara dinamis melalui peta konfigurasi `system_config` tanpa perlu melakukan reload program XDP.

> **Gambar 3.2** Alur Persiapan Dataset · **Gambar 3.3** Alur Pelatihan dan Deployment ML

### 3.2.5 Perancangan Mekanisme Mitigasi

Mekanisme mitigasi dirancang secara bertingkat dan dieksekusi sepenuhnya inline oleh XDP, sementara kelas klasifikasi ditentukan oleh BPF Timer di akhir setiap window (Subbab 3.2.2c). Tiga aksi tersimpan pada `mitigation_state`. PASS diberi TTL 3×`window_ns` agar IP Normal tidak perlu berulang kali melalui Slow Path. THROTTLE diterapkan untuk ARP, ICMP, SYN, dan UDP Flood. BLACKLIST diterapkan apabila klasifikasi yang sama konsisten selama `escalate_windows` berturut-turut, berlaku selama `blacklist_ns`.

Perlakuan THROTTLE/BLACKLIST pada keempat serangan tersebut mengasumsikan `src_ip` tidak dipalsukan, sesuai batasan masalah pada Subbab 1.4, karena mekanisme per-IP bergantung pada alamat sumber sebagai identitas yang stabil. DNS Amplification diperlakukan berbeda karena mitigasinya berdasarkan rasio ukuran paket pada Slow Path, sebuah sinyal yang tetap valid terlepas dari `src_ip` asli atau palsu, sehingga bisa langsung di-DROP tanpa perlu mempercayai alamat sumbernya. Inilah alasan DNS Amplification dapat dimitigasi berbasis spoofing sementara keempat jenis serangan lain belum, karena keduanya memakai jenis sinyal deteksi yang berbeda secara fundamental. Mendeteksi spoofing untuk keempat jenis serangan lain berada di luar cakupan proyek akhir ini.

ML tetap berperan sebagai jaring pengaman bagi paket DNS Amplification yang lolos pre-filter namun terklasifikasi sebagai serangan pada akhir window, sehingga ML berfungsi sebagai konfirmator eskalasi mitigasi berbasis pola teragregasi, bukan pemicu tunggal per-paket. Seluruh parameter mitigasi dapat diubah melalui `system_config` tanpa reload program, dengan pemetaan kelas ke aksi ditunjukkan pada Tabel 3.3.

### 3.2.6 Perancangan Modul Userspace

Modul userspace terdiri dari tiga fungsi utama yang berjalan secara independen, tanpa terlibat dalam jalur keputusan inline sebagaimana dijelaskan pada Subbab 3.2.1.

- Pembacaan event dari `alert_events` ring buffer menggunakan epoll secara event-driven. Setiap event yang diterima dicatat sebagai log dan diteruskan ke pipeline monitoring tanpa memblokir eksekusi program XDP.
- Ekspor metrik ke Prometheus melalui `ebpf_exporter`, mencakup jumlah paket per aksi mitigasi, distribusi label klasifikasi ML, dan statistik throughput per window. Metrik ini divisualisasikan pada dashboard Grafana untuk keperluan monitoring real-time selama pengujian.

Konfigurasi parameter operasional dilakukan melalui `system_config`, mencakup threshold mitigasi, durasi blacklist, ukuran time window, threshold eskalasi, pemilihan model ML aktif, dan mode operasi sistem. Perubahan berlaku segera tanpa reload program atau kehilangan paket.

### 3.2.7 Perancangan Sistem Pembanding

Evaluasi komparatif dilakukan terhadap empat sistem pembanding pada topologi dan skenario identik. Suricata dan Snort 3 mewakili IPS konvensional berbasis user space. nftables mewakili firewall kernel tanpa ML menggunakan aturan statis threshold packet rate. eBPF rule-based mewakili eBPF tanpa inferensi ML menggunakan mode Fast Path-only sistem utama.

## 3.3 Skenario Pengujian

### 3.3.1 Topologi Pengujian

Pengujian dilakukan pada dua lingkungan secara bertahap. Lingkungan pertama menggunakan tiga virtual machine pada VMware Workstation dengan sistem operasi Ubuntu 26.04 LTS yang terhubung melalui virtual switch internal dan beroperasi menggunakan Generic XDP. Pada lingkungan yang sama, pengujian juga dilakukan menggunakan Native XDP melalui mode `xdpdrv` pada driver vmxnet3, sebagaimana dijelaskan pada Subbab 3.2.2a, sehingga diperoleh dua titik data untuk mengisolasi pengaruh mode eksekusi dari pengaruh hardware. Lingkungan ini digunakan untuk validasi fungsionalitas sistem, debugging, dan pengukuran baseline sebelum pengujian bare metal. Lingkungan kedua menggunakan tiga node yang terhubung langsung tanpa switch perantara. Node 1 (PC) berperan sebagai traffic generator sekaligus attacker, Node 2 (PC) sebagai NIPS dengan NIC Intel X540-T2 (ixgbe) yang beroperasi menggunakan Native XDP pada koneksi 10 Gigabit, sedangkan Node 3 (laptop) berperan sebagai server target.

Node 3 digunakan sebagai server target untuk merepresentasikan skenario deployment inline NIPS yang realistis. Keterbatasan NIC 1 Gbps pada Node 3 (laptop) tidak mempengaruhi validitas pengujian karena seluruh metrik performa diukur pada antarmuka Node 2, sedangkan pada skenario serangan trafik yang diteruskan setelah mitigasi berada di bawah kapasitas Node 3. Hanya pada skenario Normal Traffic seluruh trafik diteruskan (PASS), sehingga Node 3 digunakan untuk memverifikasi keberhasilan penerimaan trafik hingga batas kapasitas 1 Gbps sebagai validasi fungsional, bukan sebagai acuan pengukuran performa maksimum sistem.

> **Gambar 3.4** Topologi Pengujian Virtual
> **Gambar 3.5** Topologi Pengujian Bare metal

### 3.3.2 Skenario Trafik

Pengujian mencakup dua kategori skenario. Skenario serangan tunggal menguji masing-masing dari lima kelas serangan, yaitu ARP Flood, ICMP Flood, SYN Flood, UDP Flood, dan DNS Amplification. Seluruh trafik dibangkitkan menggunakan TRex. ARP Flood dan ICMP Flood dibangkitkan langsung melalui fitur stateless packet crafting TRex sesuai pipeline pada Subbab 3.2.3a, sedangkan SYN Flood, UDP Flood, dan DNS Amplification di-replay dari PCAP CIC-DDoS2019. Skenario serangan campuran menggabungkan dua atau lebih jenis serangan dengan proporsi trafik normal yang bervariasi untuk menguji kemampuan sistem menangani multi-vector attack dan mixed traffic. Pengujian ML dilakukan dengan menjalankan ketiga model (DT, RF, dan MLP) secara bergantian melalui `system_config` pada kondisi skenario yang identik. Hasil klasifikasi, latensi inferensi, dan performa sistem dibandingkan pada setiap skenario.

Setiap skenario dijalankan selama 5 menit dengan tiga kali repetisi. Durasi tersebut menghasilkan ribuan window pengukuran dalam setiap run, sedangkan repetisi digunakan untuk mendeteksi outlier akibat variasi kondisi hardware. Hasil dilaporkan sebagai rata-rata beserta standard deviation, dan repetisi tambahan dilakukan apabila standard deviation melebihi 5% dari nilai rata-rata metrik throughput.

**Tabel 3.6** Skenario Trafik Pengujian

| Skenario | Deskripsi |
|---|---|
| Normal Traffic | Trafik normal tanpa serangan (trafik HTTP menuju layanan pada Node 3, lihat Subbab 3.3.2a) |
| ARP Flood | Serangan ARP Flood |
| ICMP Flood | Serangan ICMP Flood |
| SYN Flood | Serangan TCP SYN Flood |
| UDP Flood | Serangan UDP Flood |
| DNS Amplification | Serangan DNS Amplification |
| Mixed Attack | Kombinasi beberapa jenis serangan |

Pengujian model ML dilakukan secara terpisah dari pengujian sistem keseluruhan. Evaluasi klasifikasi menggunakan data holdout 20% dari pipeline pada Subbab 3.2.3a untuk mengukur accuracy, precision, recall, F1 Score, FPR, TNR, dan ADR dari ketiga model secara offline sebelum deployment, dengan seluruh metrik dihitung menggunakan fungsi `sklearn.metrics`. Setelah deployment, ketiga model diuji secara bergantian melalui `system_config` pada skenario trafik yang sama (Tabel 3.6). Karena setiap skenario hanya berisi satu jenis serangan yang diketahui, label kelas aktual untuk tiap window sudah ditentukan oleh skenario yang sedang dijalankan. Hasil klasifikasi in-kernel pada tiap window, diperoleh dari parsing log `alert_events`, dibandingkan terhadap label tersebut untuk membentuk confusion matrix yang sama seperti evaluasi offline menggunakan `sklearn.metrics`, sehingga metrik pada Subbab 2.2.9 dapat dihitung ulang pada kondisi real-time. Selain akurasi, pengujian ini juga mengukur pengaruh pemilihan model terhadap latensi inferensi dan CPU utilization pada berbagai tingkat beban trafik.

Sebelum trafik hasil replay PCAP maupun hasil pembangkitan mandiri TRex diuji melawan mekanisme mitigasi pada Subbab 3.3.2, perlu dibuktikan terlebih dahulu bahwa trafik tersebut benar-benar memberi dampak nyata terhadap Node 3. Trafik ini telah dimodifikasi dari dataset asli, yaitu IP dan port diarahkan ulang ke topologi testbed, sehingga bukan lagi trafik asli 1:1 dari CIC-DDoS2019.

**a. Prasyarat Layanan di Node 3**

Agar validasi dapat dilakukan, Node 3 perlu menjalankan layanan nyata yang bisa "dikorbankan", bukan sekadar menjadi alamat IP tujuan pasif.

**Tabel 3.7** Kebutuhan Layanan

| Serangan | Kebutuhan Layanan | Justifikasi |
|---|---|---|
| ARP Flood | Tidak relevan bagi Node 3 (lihat Subbab 2.2.1a dan 3.2.1) | Dampak terukur di Node 2 sebagai router L3, bukan Node 3 |
| SYN Flood | Wajib, server HTTP mendengarkan di port target | Tanpa listener, paket SYN ke port tertutup dibalas RST oleh kernel sehingga half-open connection tidak pernah terbentuk |
| UDP Flood | Tidak wajib | Indikator validasi (Tabel 3.6b) diukur dari saturasi bandwidth link dan packet loss trafik sah paralel, bukan dari respons layanan, sehingga balasan default kernel berupa ICMP Port Unreachable tidak memengaruhi validitas pengukuran |
| ICMP Flood | Tidak perlu | Mekanisme default OS sudah membalas echo request |
| DNS Amplification | Tidak perlu, Node 3 berperan sebagai korban refleksi, bukan resolver | Dampak yang diukur adalah bandwidth Node 3 yang terkuras oleh respons besar |

Karena Node 3 sudah harus menjalankan server HTTP untuk validasi SYN Flood, layanan yang sama dipakai sebagai target skenario Normal Traffic (Tabel 3.6), sehingga trafik normal didefinisikan secara eksplisit sebagai trafik HTTP menuju layanan tersebut.

**b. Penyesuaian IP/Port Target**

Sebelum trafik SYN Flood, UDP Flood, dan DNS Amplification di-replay, IP dan port tujuan pada PCAP asli CIC-DDoS2019 diperiksa menggunakan `tshark`:

```
tshark -r <file>.pcap -q -z io,phs
tshark -r <file>.pcap -q -z endpoints,ip
tshark -r <file>.pcap -q -z conv,tcp
tshark -r <file>.pcap -q -z conv,udp
```

Hasil pemeriksaan ini mencatat IP tujuan asli, port tujuan dominan, dan karakteristik rate/ukuran paket sebagai referensi ambang "tergolong flood". IP tujuan kemudian ditulis ulang menjadi IP Node 3 sebenarnya menggunakan `packet_hook` pada `STLProfile.load_pcap()` milik TRex saat PCAP dimuat ke profil, sehingga seluruh proses penyesuaian dilakukan di dalam TRex tanpa PCAP perantara hasil edit manual. Port tujuan dominan hasil pemeriksaan menentukan port layanan yang perlu dijalankan di Node 3 (Tabel 3.6a). Untuk ARP Flood dan ICMP Flood yang dibangkitkan langsung menggunakan TRex, langkah ini tidak diperlukan karena target IP ditentukan langsung sesuai topologi testbed saat pembuatan paket.

**c. Metodologi Validasi**

Validasi dilakukan sebelum skenario pengujian mitigasi utama (Subbab 3.3.2), mengikuti pola go/no-go yang sudah dipakai proposal ini untuk validasi model ML (Gambar 3.3).

- Program XDP pada Node 2 dijalankan dalam mode Fast Path-only dengan seluruh `mitigation_state` di-bypass menjadi PASS, atau Node 2 sementara dilepas dari jalur dan Node 1↔Node 3 dihubungkan langsung, sehingga trafik serangan sampai ke Node 3 tanpa mitigasi apa pun.
- Setiap kelas serangan dijalankan secara terpisah selama durasi singkat, 30 detik cukup untuk validasi, tidak perlu 5 menit seperti pengujian utama.
- Dampak diukur di Node 3, atau di Node 2 khusus untuk ARP Flood, menggunakan kriteria pada Tabel 3.6b.

Serangan dinyatakan valid ("go") bila kriteria kuantitatif terpenuhi. Jika tidak, parameter pembangkitan trafik pada TRex (rate, jumlah sumber melalui `ip_gen`, dan sebagainya) disesuaikan dan diuji ulang sebelum lanjut ke pengujian mitigasi utama.

**Tabel 3.8** Validasi Serangan

| Serangan | Indikator | Alat Ukur |
|---|---|---|
| ARP Flood | Tabel ARP pada Node 2 penuh/thrashing, CPU Node 2 naik signifikan, latensi/packet loss trafik sah Node 1→Node 3 turut meningkat | `ip -s neigh`, `mpstat`, stream trafik sah paralel pada profil TRex yang sama dengan flow_stats |
| SYN Flood | Jumlah half-open connection mendekati/melampaui `net.ipv4.tcp_max_syn_backlog`, klien sah gagal handshake baru | `ss -n state syn-recv \| wc -l`, uji koneksi klien kontrol |
| UDP Flood | Bandwidth tautan Node 2↔Node 3 mendekati kapasitas; packet loss trafik sah paralel meningkat signifikan dari baseline | Stream trafik sah paralel pada profil TRex yang sama dengan flow_stats untuk mengukur packet loss dan bandwidth, `ifstat`/`ethtool -S` di Node 2 |
| ICMP Flood | Utilisasi CPU Node 3 meningkat signifikan, RTT trafik sah paralel meningkat | `mpstat`, stream ICMP trafik sah paralel pada profil TRex yang sama dengan flow_stats untuk mengukur RTT |
| DNS Amplification | Amplification factor terverifikasi jauh di atas 1, bandwidth Node 3 sisi penerima respons terkuras | Analisis ukuran paket via `tshark`, statistik bandwidth dari TRex |

Baris ARP Flood menjadi bukti kuantitatif wajib untuk mendukung klaim "proteksi tidak langsung" Node 2 sebagai router L3 (Subbab 2.2.1a dan 3.2.1).

### 3.3.3 Variasi Beban Trafik

Variasi beban ini bertujuan mengidentifikasi titik degradasi performa masing-masing sistem pada throughput yang meningkat. Setiap skenario diuji pada empat tingkat beban trafik sebagaimana ditunjukkan pada Tabel 3.9.

**Tabel 3.9** Variasi Beban Trafik

| Kategori | Throughput Target |
|---|---|
| Rendah | 100 Mbps |
| Sedang | 1 Gbps |
| Tinggi | 5 Gbps |
| Maksimum | 10 Gbps |

### 3.3.4 Sensitivitas Window Size

Sensitivitas ini diuji pada dua skenario representatif, yaitu SYN Flood (mewakili serangan single-source volumetrik) dan Mixed Attack (mewakili kondisi multi-vector), pada level beban Sedang (1 Gbps), menggunakan model ML dengan performa klasifikasi terbaik hasil evaluasi offline (Subbab 3.2.4). Ketiga nilai `window_ns` (500 ms, 1 detik, 2 detik) dibandingkan berdasarkan tiga aspek: (1) stabilitas metrik klasifikasi (accuracy, F1 Score) akibat variasi jumlah sampel per window, (2) Time-to-Mitigation rata-rata, dan (3) CPU utilization akibat frekuensi eksekusi BPF Timer. Hasil evaluasi ini menjadi dasar penetapan `window_ns` = 1 detik sebagai nilai default yang digunakan pada seluruh skenario pengujian utama (Tabel 3.6, 3.9) kecuali dinyatakan lain.

### 3.3.5 Sensitivitas Latensi Jaringan

Subbab ini menguji dimensi latensi jaringan (network latency) yang dijelaskan pada Subbab 2.2.9.k, sebagai pelengkap dari Subbab 3.3.4 yang menguji sensitivitas `window_ns`. Tujuan pengujian ini adalah membuktikan bahwa akurasi klasifikasi dan efektivitas mitigasi sistem tetap terjaga meskipun kondisi jaringan antara penyerang dan sistem tidak ideal.

Latensi jaringan disimulasikan menggunakan `tc netem` pada tautan Node 1 ↔ Node 2, sisi yang menghadap traffic generator, karena merepresentasikan kondisi paling realistis untuk trafik pengguna sah maupun penyerang yang datang dari jaringan luas dengan RTT bervariasi. Nilai delay dan jitter diperoleh dari pengukuran preliminary menggunakan RIPE Atlas, menganalisis RTT dari probe Indonesia menuju anchor di Singapura, Jepang, dan Jerman. Median RTT terukur adalah 20,17 ms, 97,76 ms, dan 175,72 ms secara berurutan; median dan Median Absolute Deviation (MAD) dipilih sebagai representasi delay dan jitter karena distribusi RTT pada ketiga lokasi terbukti skewed. Pengukuran dilakukan pada 19 Juli 2026.

```
tc qdisc add dev <interface> root netem delay 20ms 8ms distribution normal
tc qdisc add dev <interface> root netem delay 98ms 24ms distribution normal
tc qdisc add dev <interface> root netem delay 176ms 10ms distribution normal
```

**Tabel 3.10** Variasi Latensi Jaringan

| Kategori | Delay | Jitter | Representasi |
|---|---|---|---|
| Baseline | 0 ms | - | Kondisi LAN langsung |
| Rendah | 20 ms | ±8 ms | Regional ASEAN (Indonesia–Singapura) |
| Sedang | 98 ms | ±24 ms | Asia-Pasifik (Indonesia–Jepang) |
| Tinggi | 176 ms | ±10 ms | Lintas benua (Indonesia–Jerman) |

Pada setiap level, pengujian dilakukan pada dua skenario representatif yaitu SYN Flood dan Mixed Attack pada beban Sedang (1 Gbps). Tiga metrik diukur pada tiap level: performa deteksi klasifikasi (macro-average Recall, Accuracy, F1 Score), Time-to-Mitigation, serta throughput dan efektivitas mitigasi.

Latensi pemrosesan dan latensi jaringan bersifat independen. Latensi pemrosesan XDP tidak berubah akibat delay jaringan karena XDP beroperasi setelah paket sampai di antarmuka, tetapi latensi jaringan tetap memengaruhi pola statistik trafik yang menjadi input klasifikasi ML.

## 3.4 Parameter Pengujian

Parameter pengujian dibagi menjadi dua kelompok sesuai dengan dua aspek evaluasi sistem yang dirancang pada Subbab 3.2.

Parameter evaluasi model ML mencakup macro-average Recall (sebagai kriteria seleksi utama), Accuracy, Precision, F1 Score, FPR, TNR, dan ADR, yang seluruhnya dihitung berdasarkan confusion matrix sebagaimana didefinisikan pada Subbab 2.2.9. Parameter ini digunakan untuk mengukur kemampuan klasifikasi ketiga model, baik pada evaluasi offline menggunakan locked holdout test partition maupun pada pengujian in-kernel terhadap trafik real-time.

Parameter performa sistem mencakup Throughput, Latensi Pemrosesan, Latensi Jaringan, dan CPU Utilization sebagaimana didefinisikan pada Subbab 2.2.9. Parameter ini digunakan untuk mengevaluasi efisiensi implementasi sistem pada masing-masing tingkat beban trafik dan membandingkannya terhadap keempat sistem pembanding pada Subbab 3.2.7.

**Tabel 3.11** Parameter Pengujian

| Kelompok | Parameter |
|---|---|
| Evaluasi Model ML | macro-average Recall (Kriteria Utama), Accuracy, Precision, F1 Score, FPR, TNR, ADR |
| Performa Sistem | Throughput, Latensi Pemrosesan, Latensi Jaringan, CPU Utilization, Time-to-Mitigation |

## 3.5 Perencanaan Jadwal

Penelitian proyek akhir ini direncanakan dilaksanakan selama 14 bulan, dimulai pada bulan Juni 2026 sampai target terakhir bulan Juli 2027, dengan detail kegiatan seperti pada Tabel 3.12.

**Tabel 3.12** Perencanaan Jadwal

| No | Kegiatan | Bulan 6 | 7 | 8 | 9 | 10 | 11 | 12 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Studi Literatur | | | | | | | | | | | | | | |
| 2 | Perancangan Sistem | | | | | | | | | | | | | | |
| 3 | Pengujian dan Analisa | | | | | | | | | | | | | | |
| 4 | Pembuatan Laporan | | | | | | | | | | | | | | |
| 5 | Perencanaan Jadwal | | | | | | | | | | | | | | |

> *Catatan: sel-sel penanda durasi pelaksanaan (Gantt chart) pada tabel asli berupa blok visual/shading yang tidak dapat diekstrak sebagai teks. Silakan merujuk ke halaman 50 dokumen PDF asli untuk melihat rentang bulan pelaksanaan setiap kegiatan secara visual.*

---

# DAFTAR PUSTAKA

[1] Z. H. Sahosh, A. Faheem, M. B. Tuba, M. I. Ahmed, dan S. A. Tasnim, "A Comparative Review on DDoS Attack Detection Using Machine Learning Techniques," *Malaysian Journal of Science and Advanced Technology*, vol. 4, no. 2, hlm. 75-83, 2024.

[2] R. Nazir, A. A. Laghari, F. H. Dahri, Y. Shoulin, Z. M. Alhakeem, H. Hakim, dan Z. A. Mughal, "A review on machine learning techniques for network security," *Journal of Cyber Security Technology*, 2025.

[3] FortiGuard Labs, "2026 Global Threat Landscape Report," Fortinet, 2026. [Online]. Available: https://www.fortinet.com/resources/reports/threat-landscape-report. [Diakses pada Jun. 30, 2026].

[4] Cloudflare, "DDoS Threat Report for 2025 Q4," Cloudflare Radar, 2026. [Online]. Available: https://radar.cloudflare.com/reports/ddos-2025-q4. [Diakses pada Jun. 30, 2026].

[5] H. J. Hadi, M. Adnan, Y. Cao, F. B. Hussain, N. Ahmad, M. A. Alshara, dan Y. Javed, "iKern: Advanced Intrusion Detection and Prevention at the Kernel Level Using eBPF," *Technologies*, vol. 12, 2024.

[6] M. Athallah, "A Reproducibility Study of XDP-Based High-Performance Firewall in Virtualized and Cloud Environments," Istanbul Technical University, 2026.

[7] D. Soldani, P. Nahi, H. Bour, S. Jafarizadeh, M. F. Soliman, L. Di Giovanna, F. Monaco, G. Ognibene, dan F. Risso, "eBPF: A New Approach to Cloud-Native Observability, Networking and Security for Current (5G) and Future Mobile Networks (6G and Beyond)," *IEEE Access*, 2023.

[8] S. Remya, M. J. Pillai, B. Niranjan, P. M. A. Kumar, K. M. Shaju, K. D. Raj, S. Ramasubbareddy, dan Y. Cho, "eBPF-Based Runtime Detection of Semantic DDoS Attacks in Linux Containers," *IEEE Access*, 2025.

[9] M. Mittal, K. Kumar, dan S. Behal, "Deep learning approaches for detecting DDoS attacks: a systematic review," *Soft Computing*, 2021.

[10] L. Pattnaik, S. Satpathy, B. K. Paikaray, dan P. K. Swain, "DDoS analysis using machine learning: survey, issues, and future directions," *International Journal of Business Continuity and Risk Management*, vol. 14, no. 1, hlm. 57, 2024.

[11] N. Anand, M. A. Saifulla, dan P. K. Aakula, "High-performance Intrusion Detection System using eBPF with Machine Learning algorithms," *Research Square*, 2023.

[12] J. Gallego-Madrid, I. Bru-Santa, A. Ruiz-Rodenas, R. Sanchez-Iborra, dan A. Skarmeta, "Machine learning-powered traffic processing in commodity hardware with eBPF," *Computer Networks*, vol. 243, art. no. 110295, 2024.

[13] J. Zhang, P. Chen, Z. He, H. Chen, dan X. Li, "Real-Time Intrusion Detection and Prevention with Neural Network in Kernel using eBPF," dalam *54th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN)*, 2024.

[14] S. K. Erskine, "Real-Time Large-Scale Intrusion Detection and Prevention System (IDPS) CICIoT Dataset Traffic Assessment Based on Deep Learning," *Applied System Innovation*, vol. 8, 2025.

[15] A. P. L. Gaol, A. Tedyyana, dan N. Hidayasari, "Penerapan Sistem Keamanan Jaringan menggunakan Intrusion Prevention System dengan Machine Learning," *Sistemasi: Jurnal Sistem Informasi*, vol. 14, no. 6, hlm. 2615-2629, 2025.

[16] R. K. Machnicki, J. R. Andreotti, U. Penteado, J. P. Correia, V. Fulber-Garcia, dan A. Grégio, "Sapo-boi: Bypassing Linux Kernel Network Stack in the Implementation of an XDP-based NIDS," *Journal of the Brazilian Computer Society*, vol. 32, no. 1, 2026.

[17] O. Toyin, M. O. Adeola, A. Oguntimilehin, O. B. Abiola, O. M. Aweh, dan S. E. Obamiyi, "Intelligent Network Intrusion Detection and Prevention System (NIDPS): A Machine Learning and Network Security," dalam *2024 IEEE 5th International Conference on Electro-Computing Technologies for Humanity (NIGERCON)*, Ado Ekiti, 2024.

[18] R. F. Aji, H. Kurniawan, dan N. P. Utami, "A Lightweight Rule-Based Detection Approach for ARP Flooding Malware in Office Networks," *International Journal of Advanced Computer Science and Applications (IJACSA)*, vol. 16, no. 12, 2025.

[19] S. A. AL-Shami dan M. F. Abdullah, "Deep Learning for DDoS Detection: A Systematic Review of Explainability and Adversarial Robustness," *Gongcheng Kexue Xuebao*, vol. 11, no. 1, 2026.

[20] H. Li, Y. Zhao, W. Yao, K. Xu, dan Q. Li, "Towards real-time ML-based DDoS detection via cost-efficient window-based feature extraction," *Science China Information Sciences*, vol. 66, no. 5, hlm. 152105, 2023.

[21] J. Halladay, D. Cullen, N. Briner, J. Warren, K. Fye, R. Basnet, J. Bergen, dan T. Doleck, "Detection and Characterization of DDoS Attacks Using Time-Based Features," *IEEE Access*, vol. 10, hlm. 49794-49807, 2022.

[22] S. Gai, *Building a Future-Proof Cloud Infrastructure: A Unified Architecture for Network, Security, and Storage Services*. Boston, MA, USA: Addison-Wesley Professional, 2020.

[23] L. Rice, *What Is eBPF?: An Introduction to a New Generation of Networking, Security, and Observability Tools*. Sebastopol, CA, USA: O'Reilly Media, Inc., 2022.

[24] "What is eBPF?," eBPF.io. [Online]. Available: https://ebpf.io/what-is-ebpf/. [Diakses pada Jun. 19, 2026].

[25] "eBPF Documentation," eBPF Foundation. [Online]. Available: https://docs.ebpf.io/linux/concepts/verifier/. [Diakses pada Jun. 19, 2026].

[26] "BPF and XDP Reference Guide - Program Types," Cilium Documentation. [Online]. Available: https://docs.cilium.io/en/stable/reference-guides/bpf/progtypes/#xdp. [Diakses pada Jun. 19, 2026].

[27] R. H. Ali dan Z. S. Karam, "Enhancing Performance of Intrusion Prevention Systems through Machine Learning: A Comparative Study," *Baghdad Science Journal*, vol. 23, no. 2, 2026.

[28] "BPF Design Q&A," The Linux Kernel Documentation. [Online]. Available: https://docs.kernel.org/bpf/bpf_design_QA.html. [Diakses pada Jul. 6, 2026].

[29] Z. Liu, H. Namkung, G. Nikolaidis, J. Lee, C. Kim, X. Jin, V. Braverman, M. Yu, dan V. Sekar, "Jaqen: A High-Performance Switch-Native Approach for Detecting and Mitigating Volumetric DDoS Attacks with Programmable Switches," dalam *30th USENIX Security Symposium (USENIX Security 21)*, 2021, hlm. 3829-3846.

[30] C.-L. Chen dan W.-J. Lee, "Constructing an Ensemble Stacking Model for Detecting DDoS Attacks," *Telecom*, vol. 7, no. 3, hlm. 51, 2026. [Online]. Available: https://doi.org/10.3390/telecom7030051.

[31] T. Farasat, J. Kim, dan J. Posegga, "SmartX Intelligent Sec: A Security Framework Based on Machine Learning and eBPF/XDP," University of Passau dan GIST, 2024.

[32] B. Ali, "On the fog's frontline: a federated machine learning approach for industrial network threat detection and intrusion prevention," *Journal of Cybersecurity*, 2025.

[33] H. Taguchi, T. Hara, dan S. Kasahara, "Unsupervised Real-Time In-Kernel Intrusion Detection System Using Autoencoders and eBPF," *IEICE Transactions on Communications*, vol. E109-B, no. 2, 2026.

[34] G. H. E. Einsfeldt dan A. E. Schaeffer-Filho, "XFAST: Efficient Feature Selection for High-Performance Network Traffic Analysis using eBPF/XDP and Genetic Algorithms," dalam *21st International Conference on Network and Service Management (CNSM)*, 2025.

[35] T. Hara dan M. Sasabe, "On practicality of kernel packet processing empowered by lightweight neural network and decision tree," dalam *2023 14th International Conference on Network of the Future (NoF)*, 2023, hlm. 89-97.

[36] J. F. Kurose dan K. W. Ross, *Computer Networking: A Top-Down Approach*, 8th ed. Boston, MA, USA: Pearson, 2022.

[37] Y. Al-Dunainawi, B. R. Al-Kaseem, dan H. S. Al-Raweshidy, "Optimized Artificial Intelligence Model for DDoS Detection in SDN Environment," *IEEE Access*, vol. 11, hlm. 106733–106748, 2023.

[38] M. M. N. Hider, F. Rahma, dkk., "An Encoder-Only Transformer With Features-as-Tokens for Robust Network Intrusion Detection," *IEEE Access*, vol. 11, hlm. 132291–132304, 2023.
