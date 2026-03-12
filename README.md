# LaporBang API

REST API backend untuk aplikasi **LaporBang** — platform pelaporan lubang jalan (pothole reporting). Dibangun dengan Node.js, Express, MongoDB Atlas, dan Cloudinary untuk penyimpanan gambar.

## 🚀 Tech Stack

- **Runtime**: Node.js 18.x
- **Framework**: Express 5
- **Database**: MongoDB Atlas (Mongoose)
- **Authentication**: JWT (jsonwebtoken) + bcryptjs
- **Upload Gambar**: Multer + Cloudinary
- **Deployment**: Vercel

## 📁 Struktur Folder

```
laporbang-api/
├── config/
│   ├── database.js          # Koneksi MongoDB Atlas
│   └── cloudinary.js        # Konfigurasi Cloudinary & Multer upload
├── middlewares/
│   ├── authenticateToken.js # Middleware verifikasi JWT
│   └── authorizeAdmin.js    # Middleware otorisasi admin
├── models/
│   ├── User.js              # Schema pengguna
│   └── Report.js            # Schema laporan
├── routes/
│   ├── authRoutes.js        # Endpoint autentikasi
│   ├── userRoutes.js        # Endpoint manajemen pengguna
│   └── reportRoutes.js      # Endpoint laporan
├── utils/
│   └── classifySeverity.js  # Klasifikasi tingkat keparahan lubang
├── server.js                # Entry point aplikasi
├── vercel.json              # Konfigurasi deployment Vercel
└── package.json
```

## ⚙️ Environment Variables

Buat file `.env` di root project:

```env
JWT_SECRET=your_jwt_secret
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/laporbang
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

## 🛠️ Instalasi & Menjalankan

```bash
# Install dependencies
npm install

# Jalankan development server
npm run dev

# Jalankan production
npm start
```

Server berjalan di `http://localhost:3000`

## 📋 API Endpoints

### 🔐 Authentication

| Method | Endpoint          | Deskripsi                    | Auth |
|--------|-------------------|------------------------------|------|
| POST   | `/register`       | Registrasi pengguna baru     | ❌   |
| POST   | `/login`          | Login pengguna               | ❌   |
| GET    | `/validate-token` | Validasi token JWT           | ✅   |

### 👤 Users

| Method | Endpoint          | Deskripsi                        | Auth |
|--------|-------------------|----------------------------------|------|
| GET    | `/users`          | Ambil semua pengguna             | ❌   |
| GET    | `/users/me`       | Ambil data pengguna yang login   | ✅   |
| PUT    | `/users/update`   | Update profil pengguna           | ✅   |
| PUT    | `/users/:id/role` | Update role pengguna             | ✅   |
| DELETE | `/users/:id`      | Hapus pengguna                   | ❌   |

### 📝 Reports

| Method | Endpoint        | Deskripsi                  | Auth |
|--------|-----------------|----------------------------|------|
| POST   | `/reports`      | Buat laporan baru          | ✅   |
| GET    | `/reports`      | Ambil semua laporan        | ✅   |
| GET    | `/reports/:id`  | Ambil detail laporan       | ✅   |
| PUT    | `/reports/:id`  | Update laporan             | ✅   |
| DELETE | `/reports/:id`  | Hapus laporan              | ✅   |

---

### Detail Endpoint

#### POST `/register`

Registrasi pengguna baru dengan upload foto profil (opsional).

**Body** (`multipart/form-data`):
```json
{
  "username": "string",
  "email": "string",
  "password": "string",
  "confirmPassword": "string",
  "profileImage": "file (opsional)"
}
```

#### POST `/login`

Login dan mendapatkan JWT token (berlaku 7 hari).

**Body** (`application/json`):
```json
{
  "email": "string",
  "password": "string"
}
```

**Response**:
```json
{
  "token": "jwt_token",
  "user": {
    "id": "string",
    "username": "string",
    "email": "string",
    "profileImage": "string | null",
    "createdAt": "date",
    "role": "user | admin"
  }
}
```

#### PUT `/users/update`

Update profil pengguna (username, password, atau foto profil).

**Header**: `Authorization: Bearer <token>`

**Body** (`multipart/form-data`):
```json
{
  "username": "string (opsional)",
  "password": "string (opsional)",
  "currentPassword": "string (wajib jika ganti password)",
  "profileImage": "file (opsional)"
}
```

#### POST `/reports`

Buat laporan lubang jalan baru.

**Header**: `Authorization: Bearer <token>`

**Body** (`multipart/form-data`):
```json
{
  "titles": "string",
  "imageUrl": "file (wajib)",
  "lat": "number",
  "lng": "number",
  "holesCount": "number",
  "diameter": "number (cm)",
  "depth": "number (cm)",
  "segmentationPercentage": "number (0-100, opsional)"
}
```

## 🔢 Klasifikasi Keparahan (Severity)

Tingkat keparahan lubang dihitung otomatis berdasarkan **diameter** dan **persentase segmentasi**:

| Segmentasi \ Diameter | < 20 cm   | 20–45 cm  | ≥ 45 cm   |
|-----------------------|-----------|-----------|-----------|
| **< 10%**             | Rendah    | Rendah    | Sedang    |
| **10–25%**            | Rendah    | Sedang    | Tinggi    |
| **≥ 25%**             | Sedang    | Tinggi    | Tinggi    |

## 🔑 Autentikasi

API menggunakan **Bearer Token** (JWT). Sertakan token di header:

```
Authorization: Bearer <your_token>
```

Token didapat dari endpoint `/login` dan berlaku selama **7 hari**.

## 📄 License

ISC
