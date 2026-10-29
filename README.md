# MediAssist
```
npm install
cp .env.example .env   # éditez JWT_SECRET et SMTP (sinon le code s'affiche dans la console)
node --env-file=.env server.js
```
Ouvrir http://localhost:3000 (Node 20+). En production : HTTPS obligatoire (micro, GPS, Bluetooth) + COOKIE_SECURE=1.
Montre : doit exposer le service BLE Nordic UART (Bangle.js, PineTime, ESP32, app Wear OS maison).
