# 🛰️ ORBIT

**Go ile yazılmış hafif DNS ve ağ istihbarat aracı.**

[English documentation](README_EN.md)

ORBIT, bir alan adı için odaklı ve pasif dostu DNS keşfi yapar; IPv4/IPv6 çözümlemesi, posta sunucuları, ad sunucuları, TXT kayıtları, CNAME takma adları, CAA politikaları, ters DNS, sorgu süresi, DNS güvenlik duruşu ve çözümleyici uyarılarını içeren kompakt bir terminal raporu üretir.

Proje bilinçli olarak küçük tutulmuştur ve yalnızca Go standart kütüphanesini kullanır. İsteğe bağlı DNSSEC doğrulama ve CAA sorguları Cloudflare'in DNS-over-HTTPS uç noktası üzerinden yapılır; üçüncü taraf Go bağımlılığı gerekmez.

<p>
  <img alt="Go 1.23+" src="https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white" />
  <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-14B8A6.svg" />
  <img alt="No runtime dependencies" src="https://img.shields.io/badge/Runtime%20dependencies-None-64748B.svg" />
  <a href="https://github.com/raxwqx/ORBIT/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/raxwqx/ORBIT/actions/workflows/tests.yml/badge.svg?branch=main" /></a>
</p>

## Özellikler

- A / AAAA kayıtları
- MX kayıtları
- NS kayıtları
- TXT kayıtları
- CNAME kayıtları
- **CAA (Certificate Authority Authorization) kayıtları** — yeni
- Çözümlenen IP'ler için ters DNS (PTR)
- DNS sorgu süresi
- SPF algılama ve kayıt çıkarma
- DMARC algılama ve kayıt çıkarma
- DNSSEC imzalı / imzasız / doğrulanmış durumu
- Alt alan adlarında da doğru DNSSEC bölge tespiti
- İnsan tarafından okunabilir terminal çıktısı
- JSON çıktısı
- Yapılandırılabilir DNS ve HTTP zaman aşımı
- Yalnızca standart kütüphane
- Eşzamanlı ve sınırlı DNS sorguları
- Terminal kontrol karakterlerine karşı çıktı temizliği

## Gereksinimler

- Go 1.23 veya üzeri
- DNSSEC ve CAA kontrolleri için `cloudflare-dns.com` adresine HTTPS erişimi
- Diğer kayıtlar için sistem çözümleyicisine erişim (genellikle yerel ağ)

## Kurulum

Kaynak koddan derleyin:

```bash
git clone https://github.com/raxwqx/ORBIT.git
cd ORBIT
go build -o orbit ./cmd/orbit
```

Doğrudan Go ile çalıştırın:

```bash
go run ./cmd/orbit example.com
```

## Kullanım

```bash
./orbit example.com
```

JSON çıktısı:

```bash
./orbit example.com --json
```

Özel zaman aşımı (saniye):

```bash
./orbit example.com --timeout 10
```

Hedefi bayrakla belirtme:

```bash
./orbit --target example.com --json
```

Yardım ve sürüm:

```bash
./orbit --help
./orbit --version
```

Bayraklar hedefin önünde veya arkasında kullanılabilir. `--target` ile konumsal hedef birlikte verilirse araç hata verir.

### Zaman aşımı

`--timeout` varsayılan olarak `5` saniyedir. `1` ile `300` arasında bir tam sayı kabul edilir. Değer hem sistem çözümleyici sorgularına hem de Cloudflare DoH isteklerine uygulanır.

### Hedef doğrulama

ORBIT, sorgulamadan önce hedefi doğrular:

- Alan adı en fazla 253 karakter, her etiket en fazla 63 karakter olabilir.
- Boş etiketler, baştaki/sondaki tireler ve boşluk veya kontrol karakterleri reddedilir.
- Yalnızca ASCII harfler, rakamlar, tire ve alt çizgi kabul edilir. Uluslararası alan adları için punycode (`xn--...`) kullanın.
- Tek bir sondaki nokta kabul edilip kaldırılır; tekrarlanan sondaki noktalar reddedilir.
- Girdi küçük harfe dönüştürülür; DNS adları büyük/küçük harfe duyarlı değildir.

## Örnek çıktı

```text
🛰️ ORBIT
Target: example.com
Elapsed: 412 ms

IPv4 (A)
  • 192.0.2.10
  • 192.0.2.11

IPv6 (AAAA)
  • 2001:db8::10

Mail (MX)
  • mail.example.com (priority 10)
  • mail2.example.com (priority 20)

Nameservers (NS)
  • ns1.example.com
  • ns2.example.com

Aliases (CNAME)
  -

TXT
  • v=spf1 include:_spf.example.net ~all

Certificate Authorities (CAA)
  • 0 iodef "mailto:security@example.com"
  • 0 issue "letsencrypt.org"
  • 0 issuewild "letsencrypt.org"

Reverse DNS (PTR)
  192.0.2.10 ->
    • host.example.com

Security
  • SPF:   present
  • DMARC: present
  • DNSSEC: validated (Cloudflare DoH validated)

SPF Records
  • v=spf1 include:_spf.example.net ~all

DMARC Records
  • v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com
```

## Güvenlik kontrolleri

ORBIT, SPF ve DMARC kayıtlarını DNS TXT sorgularıyla bulur.

DNSSEC durumu Cloudflare DNS-over-HTTPS üzerinden kontrol edilir. DNSKEY kayıtları bölge tepesinde (zone apex) bulunduğu için ORBIT yalnızca hedef adı değil, yetkili SOA kaydının gösterdiği bölgeyi ve üst etiketleri de sorgular. Bu sayede `www.example.com` gibi alt alan adları, imzalı `example.com` bölgesi için yanlışlıkla "imzasız" gösterilmez. Bölge `signed` olarak raporlanır; Cloudflare doğrulanmış DNS verisi döndürdüğünde `validated` olur.

CAA kayıtları, sertifika otoritesi politikasını göstermek için aynı DoH çözümleyicisi üzerinden okunur. CAA kaydı bulunmaması bir uyarı üretmez; çünkü CAA isteğe bağlı bir politikadır.

DNS yanıtları güvenilmeyen girdi olarak kabul edilir. Terminal çıktısındaki tüm alan adları, TXT/CAA kayıtları, PTR adları ve çözümleyici hata mesajları kontrol karakterlerinden arındırılır ve uzun değerler sınırlandırılır. Böylece kötü niyetli bir DNS yanıtı ANSI kaçış dizisi veya sahte rapor satırı enjekte edemez.

## Sınırlar

- Ters DNS sorguları en fazla 64 adres için yapılır; daha fazla adres varsa yalnızca ilk 64'ü işlenir ve bir uyarı gösterilir.
- PTR sorguları en fazla 8 eşzamanlı çalışanla yürütülür; böylece çok sayıda A/AAAA kaydı olan alan adları sınırsız goroutine oluşturmaz.
- Her aşama `--timeout` değeriyle sınırlıdır. Çok yavaş bir çözümleyicide toplam süre aşamaların toplamı kadar olabilir.
- DNSSEC doğrulaması Cloudflare'in gördüğü doğrulama durumunu yansıtır; yerel bir doğrulayıcı değildir.
- CAA ve DNSSEC kontrolleri için internet erişimi gerekir. Erişim yoksa bu bölümler uyarıyla birlikte eksik/`unknown` döner.

## JSON yapısı

JSON çıktısı terminal raporundaki bilgileri ve makine tarafından okunabilir güvenlik sonuçlarını içerir:

```json
{
  "target": "example.com",
  "elapsed_ms": 412,
  "A": ["192.0.2.1"],
  "AAAA": ["2001:db8::1"],
  "MX": ["mail.example.com (priority 10)"],
  "NS": ["ns1.example.com", "ns2.example.com"],
  "TXT": ["v=spf1 -all"],
  "CAA": ["0 issue \"letsencrypt.org\""],
  "CNAME": [],
  "PTR": {
    "192.0.2.1": ["host.example.com"]
  },
  "security": {
    "spf": {
      "present": true,
      "records": ["v=spf1 -all"]
    },
    "dmarc": {
      "present": false
    },
    "dnssec": {
      "status": "signed",
      "validated": true,
      "checked_via": "Cloudflare DoH"
    },
    "summary": {
      "spf": "present",
      "dmarc": "missing",
      "dnssec": "validated"
    }
  },
  "warnings": []
}
```

Notlar:

- `CAA` üst düzey bir dizi alanıdır; CAA kaydı yoksa boş dizi olur.
- `PTR` yalnızca en az bir ters DNS adı bulunduğunda görünür.
- `warnings` boşsa alan tamamen atlanır.
- `MX` ve `NS` değerleri okunabilirlik için biçimlendirilmiş metin dizileridir.

## Testler

```bash
go test ./...
go vet ./...
```

CI, Linux, macOS ve Windows üzerinde Go 1.23–1.25 sürümleriyle testleri, `go vet` ve derlemeyi çalıştırır.

## Kapsam

ORBIT; yetkili güvenlik araştırması, varlık envanteri, sorun giderme ve DNS odaklı keşif için tasarlanmıştır. Bağlantı noktası taraması, sömürü, kimlik bilgisi saldırıları veya müdahaleci servis sorgulaması yapmaz.

Yalnızca sorgulama yetkiniz olan alan adlarını kullanın.

## Değişiklikler

Sürüm notları için [CHANGELOG.md](CHANGELOG.md) dosyasına bakın.

## Lisans

MIT
