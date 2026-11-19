# Ders Çalışma özel backend

Node.js + Express tabanlıdır. Kullanıcı kayıtları `data/store.json` içinde tutulur; bu hafif kurulum içindir. Üretimde bu depoyu PostgreSQL gibi yönetilen bir veritabanına taşıman önerilir.

## Kurulum

1. Node.js 20 veya üstünü kur.
2. Bu klasörde `npm install` çalıştır.
3. `.env.example` dosyasını `.env` olarak kopyala ve güçlü bir `SESSION_SECRET` yaz.
4. E-posta için SMTP, SMS için Twilio bilgilerini `.env` içine ekle.
5. `npm start` çalıştır ve `http://localhost:8787` adresini aç.

İlk yönetici hesabı `ADMIN_EMAIL`, `ADMIN_PHONE` ve `ADMIN_PASSWORD` değerleriyle ilk başlatmada oluşturulur. `ADMIN_PASSWORD` aynı güçlü parola politikasına uymalıdır. Bu bilgiler istemciye gömülmez.
