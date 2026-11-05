# ตั้งค่าโปรไฟล์ EcoLoop ด้วย Firebase Firestore

## สิ่งที่ระบบทำ
- ระบบเข้าสู่ระบบเดิมยังตรวจสอบรหัสบัญชี/รหัสผ่านด้วยฐานข้อมูล SQLite
- ชื่อบัญชีและชื่อร้านค้าถูกอ่าน/เขียนจาก Firestore จริง ผ่าน Firebase Admin SDK
- เอกสารโปรไฟล์ใช้ collection `users` และ document ID รูปแบบ `student_<รหัส>` หรือ `merchant_<รหัส>`
- นักศึกษาใช้ field `fullName`; ร้านค้าใช้ field `shopName`; ทั้งสองเอกสารมี `publicId` และ `role`

ตัวอย่างเอกสาร `users/student_123456`:
```json
{ "publicId": "123456", "role": "student", "fullName": "ชื่อ นามสกุล" }
```

ตัวอย่างเอกสาร `users/merchant_123456`:
```json
{ "publicId": "123456", "role": "merchant", "shopName": "ชื่อร้านค้า" }
```

## ติดตั้งและเชื่อมต่อ
1. รัน `npm install` เพื่อติดตั้ง `firebase-admin`
2. ดาวน์โหลด Service Account key จาก Firebase Console > Project settings > Service accounts และเก็บไว้นอกโฟลเดอร์ที่เผยแพร่/อัปโหลดขึ้น Git
3. ตั้ง environment variable `FIREBASE_SERVICE_ACCOUNT_PATH` ให้ชี้ไปยังไฟล์ JSON ของ service account
4. เริ่มระบบด้วย `npm start`

ห้ามเผยแพร่ Service Account key หรือ commit เข้า Git หากไฟล์ key เคยถูกเผยแพร่แล้ว ให้เพิกถอน/สร้าง key ใหม่ใน Firebase Console

## หมายเหตุสำหรับบัญชีเดิม
บัญชีเดิมที่ยังไม่มีเอกสารโปรไฟล์ใน Firestore จะไม่ถูกเติมชื่อสมมติ ระบบจะแจ้งว่าไม่พบชื่อบัญชีจนกว่าจะเพิ่มเอกสารตามโครงสร้างข้างต้น
